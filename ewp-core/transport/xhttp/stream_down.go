package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"
	"ewp-core/transport"
)

type StreamDownConn struct {
	httpClient        *http.Client
	host              string
	port              string
	path              string
	uuid              [16]byte
	uuidStr           string
	password          string
	sessionID         string
	enableFlow        bool
	useTrojan         bool
	transport         *Transport  // 引用 Transport 以获取新功能
	uploadSeq         uint64
	respBody          io.ReadCloser
	uploadMu          sync.Mutex
	connected         bool
	mu                sync.Mutex
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte
	udpGlobalID       [8]byte

	// P1-UDP-OPT: 可重用缓冲区用于 WriteUDP（零分配热路径）
	udpWriteBuf []byte
	udpWriteMu  sync.Mutex
}

func NewStreamDownConn(httpClient *http.Client, host, port, path string, uuid [16]byte, uuidStr, password string, enableFlow, useTrojan bool, transport *Transport) *StreamDownConn {
	sessionID := generateSessionID()
	return &StreamDownConn{
		httpClient: httpClient,
		host:       host,
		port:       port,
		path:       path,
		uuid:       uuid,
		uuidStr:    uuidStr,
		password:   password,
		sessionID:  sessionID,
		enableFlow: enableFlow,
		useTrojan:  useTrojan,
		transport:  transport,
	}
}

func (c *StreamDownConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	ewpReq := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)
	handshakeData, err := ewpReq.Encode()
	if err != nil {
		return fmt.Errorf("encode EWP handshake: %w", err)
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	// 使用 Transport 的随机化配置 - ECH 环境下不在路径中添加 padding
	var padding string
	if c.transport.enablePadding && !c.transport.paddingInReferer {
		paddingLen := c.transport.paddingBytes.Rand()
		if paddingLen > 0 {
			padding = strings.Repeat("X", int(paddingLen))
		}
	}

	handshakeURL := fmt.Sprintf("https://%s:%s%s/%s/0", c.host, c.port, c.path, c.sessionID)
	if padding != "" {
		handshakeURL += "?x_padding=" + padding
	}
	// 使用新的请求创建方法
	ctx := context.Background()
	handshakeReq, err := c.transport.createRequestWithContext(ctx, "POST", handshakeURL, bytes.NewReader(handshakeData))
	if err != nil {
		return fmt.Errorf("create handshake request: %w", err)
	}

	// 使用统一的头部管理
	headers := c.transport.GetRequestHeader(handshakeURL)
	for k, v := range headers {
		handshakeReq.Header[k] = v
	}
	handshakeReq.Header.Set("X-Auth-Token", c.uuidStr)
	handshakeReq.ContentLength = int64(len(handshakeData))

	handshakeResp, err := c.httpClient.Do(handshakeReq)
	if err != nil {
		return fmt.Errorf("handshake request failed: %w", err)
	}
	defer handshakeResp.Body.Close()

	if handshakeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(handshakeResp.Body)
		return fmt.Errorf("handshake http error: %d %s, body: %s", handshakeResp.StatusCode, handshakeResp.Status, body)
	}

	handshakeRespData, err := io.ReadAll(handshakeResp.Body)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(handshakeRespData, ewpReq.Version, ewpReq.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode EWP handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("EWP handshake failed with status: %d", resp.Status)
	}

	c.uploadSeq = 1

	// 构造下载 URL - ECH 环境下不在路径中添加 padding
	getURL := fmt.Sprintf("https://%s:%s%s/%s", c.host, c.port, c.path, c.sessionID)
	if padding != "" {
		getURL += "?x_padding=" + padding
	}

	getReq, err := c.transport.createRequestWithContext(ctx, "GET", getURL, nil)
	if err != nil {
		return fmt.Errorf("create GET request: %w", err)
	}

	// 使用统一的头部管理
	headers = c.transport.GetRequestHeader(getURL)
	for k, v := range headers {
		getReq.Header[k] = v
	}
	getReq.Header.Set("X-Auth-Token", c.uuidStr)

	getResp, err := c.httpClient.Do(getReq)
	if err != nil {
		return fmt.Errorf("GET request failed: %w", err)
	}

	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		getResp.Body.Close()
		return fmt.Errorf("GET http error: %d %s, body: %s", getResp.StatusCode, getResp.Status, body)
	}

	c.respBody = getResp.Body

	if len(initialData) > 0 {
		if err := c.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	c.connected = true
	log.V("[XHTTP] stream-down EWP handshake success, target: %s, SessionID: %s", target, c.sessionID)
	return nil
}

// ConnectUDP sends UDP connection request
// Bug-E: Explicitly branch between EWP and Trojan UDP protocols
func (c *StreamDownConn) ConnectUDP(target transport.Endpoint, initialData []byte) error {
	// Bug-E: Explicit protocol branching for clarity
	if c.useTrojan {
		return c.connectTrojanUDP(target, initialData)
	}
	return c.connectEWPUDP(target, initialData)
}

// connectEWPUDP handles EWP native UDP protocol
func (c *StreamDownConn) connectEWPUDP(target transport.Endpoint, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var addr ewp.Address
	if target.Domain != "" {
		addr = ewp.Address{Type: ewp.AddressTypeDomain, Host: target.Domain, Port: target.Port}
	} else {
		addr = ewp.AddressFromAddrPort(target.Addr)
	}

	// Use CommandUDP for UDP connections
	ewpReq := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)
	handshakeData, err := ewpReq.Encode()
	if err != nil {
		return fmt.Errorf("encode EWP handshake: %w", err)
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	// 使用 Transport 的随机化配置
	var padding string
	if c.transport.enablePadding && !c.transport.paddingInReferer {
		paddingLen := c.transport.paddingBytes.Rand()
		if paddingLen > 0 {
			padding = strings.Repeat("X", int(paddingLen))
		}
	}

	handshakeURL := fmt.Sprintf("https://%s:%s%s/%s/0", c.host, c.port, c.path, c.sessionID)
	if padding != "" {
		handshakeURL += "?x_padding=" + padding
	}

	ctx := context.Background()
	handshakeReq, err := c.transport.createRequestWithContext(ctx, "POST", handshakeURL, bytes.NewReader(handshakeData))
	if err != nil {
		return fmt.Errorf("create handshake request: %w", err)
	}

	headers := c.transport.GetRequestHeader(handshakeURL)
	for k, v := range headers {
		handshakeReq.Header[k] = v
	}
	handshakeReq.Header.Set("X-Auth-Token", c.uuidStr)
	handshakeReq.ContentLength = int64(len(handshakeData))

	handshakeResp, err := c.httpClient.Do(handshakeReq)
	if err != nil {
		return fmt.Errorf("handshake request failed: %w", err)
	}
	defer handshakeResp.Body.Close()

	if handshakeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(handshakeResp.Body)
		return fmt.Errorf("handshake http error: %d %s, body: %s", handshakeResp.StatusCode, handshakeResp.Status, body)
	}

	handshakeRespData, err := io.ReadAll(handshakeResp.Body)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(handshakeRespData, ewpReq.Version, ewpReq.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode EWP handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("EWP handshake failed with status: %d", resp.Status)
	}

	c.uploadSeq = 1

	// 构造下载 URL
	getURL := fmt.Sprintf("https://%s:%s%s/%s", c.host, c.port, c.path, c.sessionID)
	if padding != "" {
		getURL += "?x_padding=" + padding
	}

	getReq, err := c.transport.createRequestWithContext(ctx, "GET", getURL, nil)
	if err != nil {
		return fmt.Errorf("create GET request: %w", err)
	}

	headers = c.transport.GetRequestHeader(getURL)
	for k, v := range headers {
		getReq.Header[k] = v
	}
	getReq.Header.Set("X-Auth-Token", c.uuidStr)

	getResp, err := c.httpClient.Do(getReq)
	if err != nil {
		return fmt.Errorf("GET request failed: %w", err)
	}

	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		getResp.Body.Close()
		return fmt.Errorf("GET http error: %d %s, body: %s", getResp.StatusCode, getResp.Status, body)
	}

	c.respBody = getResp.Body
	c.connected = true
	log.V("[XHTTP] stream-down EWP UDP connected, target: %v, SessionID: %s", target, c.sessionID)
	return nil
}

// connectTrojanUDP handles Trojan UDP protocol over XHTTP stream-down
// Bug-E: Explicit implementation of Trojan UDP path
func (c *StreamDownConn) connectTrojanUDP(target transport.Endpoint, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Trojan UDP uses simple handshake - just establish the HTTP stream
	// The actual UDP target is sent with each packet
	
	var padding string
	if c.transport.enablePadding && !c.transport.paddingInReferer {
		paddingLen := c.transport.paddingBytes.Rand()
		if paddingLen > 0 {
			padding = strings.Repeat("X", int(paddingLen))
		}
	}

	// For Trojan, handshake is simpler - just password verification
	handshakeURL := fmt.Sprintf("https://%s:%s%s/%s/0", c.host, c.port, c.path, c.sessionID)
	if padding != "" {
		handshakeURL += "?x_padding=" + padding
	}

	ctx := context.Background()
	
	// Trojan handshake: password + CRLF + CMD (0x03 for UDP) + target + CRLF
	var handshakeBuf bytes.Buffer
	handshakeBuf.WriteString(c.password)
	handshakeBuf.Write(trojan.CRLF)
	handshakeBuf.WriteByte(trojan.CommandUDP)
	
	// Encode target address
	if target.Domain != "" {
		handshakeBuf.WriteByte(trojan.AddressTypeDomain)
		handshakeBuf.WriteByte(byte(len(target.Domain)))
		handshakeBuf.WriteString(target.Domain)
	} else if target.Addr.Addr().Is4() {
		handshakeBuf.WriteByte(trojan.AddressTypeIPv4)
		ipv4 := target.Addr.Addr().As4()
		handshakeBuf.Write(ipv4[:])
	} else {
		handshakeBuf.WriteByte(trojan.AddressTypeIPv6)
		ipv6 := target.Addr.Addr().As16()
		handshakeBuf.Write(ipv6[:])
	}
	binary.Write(&handshakeBuf, binary.BigEndian, target.Port)
	handshakeBuf.Write(trojan.CRLF)
	
	// Add initial data if present
	if len(initialData) > 0 {
		length := uint16(len(initialData))
		binary.Write(&handshakeBuf, binary.BigEndian, length)
		handshakeBuf.Write(trojan.CRLF)
		handshakeBuf.Write(initialData)
	}

	handshakeReq, err := c.transport.createRequestWithContext(ctx, "POST", handshakeURL, &handshakeBuf)
	if err != nil {
		return fmt.Errorf("create handshake request: %w", err)
	}

	headers := c.transport.GetRequestHeader(handshakeURL)
	for k, v := range headers {
		handshakeReq.Header[k] = v
	}
	handshakeReq.ContentLength = int64(handshakeBuf.Len())

	handshakeResp, err := c.httpClient.Do(handshakeReq)
	if err != nil {
		return fmt.Errorf("handshake request failed: %w", err)
	}
	defer handshakeResp.Body.Close()

	if handshakeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(handshakeResp.Body)
		return fmt.Errorf("handshake http error: %d %s, body: %s", handshakeResp.StatusCode, handshakeResp.Status, body)
	}

	c.uploadSeq = 1

	// 构造下载 URL
	getURL := fmt.Sprintf("https://%s:%s%s/%s", c.host, c.port, c.path, c.sessionID)
	if padding != "" {
		getURL += "?x_padding=" + padding
	}

	getReq, err := c.transport.createRequestWithContext(ctx, "GET", getURL, nil)
	if err != nil {
		return fmt.Errorf("create GET request: %w", err)
	}

	headers = c.transport.GetRequestHeader(getURL)
	for k, v := range headers {
		getReq.Header[k] = v
	}

	getResp, err := c.httpClient.Do(getReq)
	if err != nil {
		return fmt.Errorf("GET request failed: %w", err)
	}

	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		getResp.Body.Close()
		return fmt.Errorf("GET http error: %d %s, body: %s", getResp.StatusCode, getResp.Status, body)
	}

	c.respBody = getResp.Body
	c.connected = true
	log.V("[XHTTP] stream-down Trojan UDP connected, target: %v, SessionID: %s", target, c.sessionID)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel
func (c *StreamDownConn) WriteUDP(target transport.Endpoint, data []byte) error {
	c.udpWriteMu.Lock()
	defer c.udpWriteMu.Unlock()

	if c.useTrojan {
		return c.writeTrojanUDPPooled(target, data)
	}

	// P1-UDP-OPT: EWP 路径使用可重用缓冲区
	requiredCap := 2 + 8 + 1 + 1 + 19 + 2 + len(data) // 最大尺寸（IPv6）
	if target.Domain != "" {
		requiredCap = 2 + 8 + 1 + 1 + (1 + 1 + len(target.Domain) + 2) + 2 + len(data)
	}

	if cap(c.udpWriteBuf) < requiredCap {
		c.udpWriteBuf = make([]byte, 0, requiredCap)
	}

	c.udpWriteBuf = c.udpWriteBuf[:0]

	if target.Domain != "" {
		c.udpWriteBuf = ewp.AppendUDPDomainFrame(
			c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep,
			target.Domain, target.Port, data,
		)
	} else {
		c.udpWriteBuf = ewp.AppendUDPAddrFrame(
			c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep,
			target.Addr, data,
		)
	}

	return c.Write(c.udpWriteBuf)
}

func (c *StreamDownConn) writeTrojanUDPPooled(target transport.Endpoint, data []byte) error {
	// P1-UDP-OPT: Trojan 路径使用可重用缓冲区
	length := uint16(len(data))
	addrLen := 7
	if target.Domain != "" {
		addrLen = 1 + 1 + len(target.Domain) + 2
	} else if target.Addr.Addr().Is6() {
		addrLen = 19
	}

	requiredCap := addrLen + 4 + len(data)
	if cap(c.udpWriteBuf) < requiredCap {
		c.udpWriteBuf = make([]byte, 0, requiredCap)
	}

	c.udpWriteBuf = c.udpWriteBuf[:0]

	if target.Domain != "" {
		c.udpWriteBuf = append(c.udpWriteBuf, trojan.AddressTypeDomain, byte(len(target.Domain)))
		c.udpWriteBuf = append(c.udpWriteBuf, []byte(target.Domain)...)
		c.udpWriteBuf = append(c.udpWriteBuf, byte(target.Port>>8), byte(target.Port))
	} else {
		c.udpWriteBuf = trojan.AppendAddrPort(c.udpWriteBuf, target.Addr)
	}
	c.udpWriteBuf = append(c.udpWriteBuf, byte(length>>8), byte(length))
	c.udpWriteBuf = append(c.udpWriteBuf, trojan.CRLF...)
	c.udpWriteBuf = append(c.udpWriteBuf, data...)

	return c.Write(c.udpWriteBuf)
}

// ReadUDP reads and decodes a UDP response packet
func (c *StreamDownConn) ReadUDP() ([]byte, error) {
	if c.respBody == nil {
		return nil, errors.New("not connected")
	}
	
	if c.useTrojan {
		
	}

	pkt, err := ewp.DecodeUDPPacket(c.respBody)
	if err != nil {
		return nil, err
	}
	return pkt.Payload, nil
}

// ReadUDPTo reads and decodes a UDP response packet directly into the provided buffer
func (c *StreamDownConn) ReadUDPTo(buf []byte) (int, error) {
	if c.respBody == nil {
		return 0, errors.New("not connected")
	}
	
	if c.useTrojan {
		payload, err := c.readTrojanUDP()
		if err != nil {
			return 0, err
		}
		n := copy(buf, payload)
		return n, nil
	}

	pkt, err := ewp.DecodeUDPPacket(c.respBody)
	if err != nil {
		return 0, err
	}
	n := copy(buf, pkt.Payload)
	return n, nil
}

func (c *StreamDownConn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	if c.respBody == nil {
		return 0, netip.AddrPort{}, errors.New("not connected")
	}
	
	if c.useTrojan {
		return readTrojanUDPWithAddrFromReader(c.respBody, buf)
	}

	return ewp.DecodeUDPAddrPacketTo(c.respBody, buf)
}

func readTrojanUDPWithAddrFromReader(r io.Reader, out []byte) (int, netip.AddrPort, error) {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("read trojan type: %w", err)
	}

	var remoteAddr netip.AddrPort
	switch typeBuf[0] {
	case trojan.AddressTypeIPv4:
		var buf [6]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("read ipv4 target: %w", err)
		}
		ip := netip.AddrFrom4(*(*[4]byte)(buf[0:4]))
		port := binary.BigEndian.Uint16(buf[4:6])
		remoteAddr = netip.AddrPortFrom(ip, port)
	case trojan.AddressTypeIPv6:
		var buf [18]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("read ipv6 target: %w", err)
		}
		ip := netip.AddrFrom16(*(*[16]byte)(buf[0:16]))
		port := binary.BigEndian.Uint16(buf[16:18])
		remoteAddr = netip.AddrPortFrom(ip, port)
	case trojan.AddressTypeDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(lenBuf[0])
		if domainLen > 0 {
			io.CopyN(io.Discard, r, int64(domainLen))
		}
		var portBuf [2]byte
		if _, err := io.ReadFull(r, portBuf[:]); err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("read domain port: %w", err)
		}
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unknown trojan address type: %d", typeBuf[0])
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("read trojan length: %w", err)
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))

	var crlf [2]byte
	if _, err := io.ReadFull(r, crlf[:]); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("read trojan crlf: %w", err)
	}

	if length > 0 {
		var n int
		if length <= len(out) {
			if _, err := io.ReadFull(r, out[:length]); err != nil {
				return 0, netip.AddrPort{}, fmt.Errorf("read trojan payload: %w", err)
			}
			n = length
		} else {
			if _, err := io.ReadFull(r, out); err != nil {
				return 0, netip.AddrPort{}, err
			}
			n = len(out)
			io.CopyN(io.Discard, r, int64(length-len(out)))
		}
		return n, remoteAddr, nil
	}
	return 0, remoteAddr, nil
}

func (c *StreamDownConn) readTrojanUDP() ([]byte, error) {
	addr, err := trojan.DecodeAddress(c.respBody)
	if err != nil {
		return nil, fmt.Errorf("read trojan address: %w", err)
	}
	_ = addr // not returned
	
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.respBody, lengthBuf); err != nil {
		return nil, fmt.Errorf("read trojan length: %w", err)
	}
	length := int(lengthBuf[0])<<8 | int(lengthBuf[1])
	
	crlf := make([]byte, 2)
	if _, err := io.ReadFull(c.respBody, crlf); err != nil {
		return nil, fmt.Errorf("read trojan crlf: %w", err)
	}
	
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.respBody, payload); err != nil {
		return nil, fmt.Errorf("read trojan payload: %w", err)
	}
	return payload, nil
}

func (c *StreamDownConn) Read(buf []byte) (int, error) {
	if c.respBody == nil {
		return 0, errors.New("not connected")
	}

	n, err := c.respBody.Read(buf)
	if err != nil {
		return 0, err
	}

	if c.flowState != nil && c.enableFlow {
		data := c.flowState.ProcessDownlink(buf[:n])
		n = copy(buf, data)
	}

	return n, nil
}

func (c *StreamDownConn) Write(data []byte) error {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()

	var writeData []byte
	if c.flowState != nil && c.enableFlow {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}

	// 使用 Transport 的随机化配置
	var newPadding string
	if c.transport.enablePadding && !c.transport.paddingInReferer {
		paddingLen := c.transport.paddingBytes.Rand()
		if paddingLen > 0 {
			newPadding = strings.Repeat("X", int(paddingLen))
		}
	}

	seq := c.uploadSeq
	c.uploadSeq++

	reqURL := fmt.Sprintf("https://%s:%s%s/%s/%d", c.host, c.port, c.path, c.sessionID, seq)
	if newPadding != "" {
		reqURL += "?x_padding=" + newPadding
	}

	req, err := c.transport.createRequestWithContext(context.Background(), "POST", reqURL, bytes.NewReader(writeData))
	if err != nil {
		return err
	}

	// 使用统一的头部管理
	headers := c.transport.GetRequestHeader(reqURL)
	for k, v := range headers {
		req.Header[k] = v
	}
	req.Header.Set("X-Auth-Token", c.uuidStr)
	req.ContentLength = int64(len(writeData))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed: %s", resp.Status)
	}

	return nil
}

func (c *StreamDownConn) Close() error {
	if c.respBody != nil {
		return c.respBody.Close()
	}
	return nil
}

// generateSessionID 生成会话 ID
// P2-21: Use crypto/rand for unpredictable session IDs
func generateSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to timestamp if randomness fails (should never happen)
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b[:])
}

func (c *StreamDownConn) StartPing(interval time.Duration) chan struct{} {
	return make(chan struct{})
}
