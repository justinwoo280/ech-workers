package xhttp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"
	"ewp-core/transport"
)

type StreamOneConn struct {
	httpClient *http.Client
	host       string
	port       string
	path       string
	uuid       [16]byte
	uuidStr    string
	password   string
	enableFlow bool
	useTrojan  bool
	transport  *Transport // 引用 Transport 以获取新功能

	// 连接管理
	pipeReader        *io.PipeReader
	pipeWriter        *io.PipeWriter
	respBody          io.ReadCloser
	connected         bool
	mu                sync.Mutex
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte

	// Xray-core 风格的异步处理
	waitReader      *WaitReadCloser
	lastRequestTime time.Time
	requestCount    int64
	udpGlobalID     [8]byte
}

func NewStreamOneConn(httpClient *http.Client, host, port, path string, uuid [16]byte, uuidStr, password string, enableFlow, useTrojan bool, transport *Transport) *StreamOneConn {
	return &StreamOneConn{
		httpClient: httpClient,
		host:       host,
		port:       port,
		path:       path,
		uuid:       uuid,
		uuidStr:    uuidStr,
		password:   password,
		enableFlow: enableFlow,
		useTrojan:  useTrojan,
		transport:  transport,
		waitReader: NewWaitReadCloser(),
	}
}

func (c *StreamOneConn) Connect(target string, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojan(target, initialData)
	}
	return c.connectEWP(target, initialData)
}

func (c *StreamOneConn) connectTrojan(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pipeReader, c.pipeWriter = io.Pipe()

	// 使用 Transport 的随机化配置
	requestInterval := c.transport.requestInterval.RandDuration()
	if requestInterval > 0 && !c.lastRequestTime.IsZero() {
		elapsed := time.Since(c.lastRequestTime)
		if elapsed < requestInterval {
			time.Sleep(requestInterval - elapsed)
		}
	}

	// 构造 URL - ECH 环境下不在路径中添加 padding
	reqURL := fmt.Sprintf("https://%s:%s%s", c.host, c.port, c.path)

	// 使用新的请求创建方法（带 httptrace 和 WithoutCancel）
	ctx := context.Background()
	req, err := c.transport.createRequestWithContext(ctx, "POST", reqURL, c.pipeReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// 使用统一的头部管理
	headers := c.transport.GetRequestHeader(reqURL)
	for k, v := range headers {
		req.Header[k] = v
	}
	req.Header.Set("X-Auth-Token", c.uuidStr)
	req.Header.Set("Content-Type", "application/octet-stream")

	// Build Trojan handshake
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	key := trojan.GenerateKey(c.password)
	var handshakeData []byte
	handshakeData = append(handshakeData, key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandTCP)

	addrBytes, err := addr.Encode()
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	handshakeData = append(handshakeData, addrBytes...)
	handshakeData = append(handshakeData, trojan.CRLF...)

	if len(initialData) > 0 {
		handshakeData = append(handshakeData, initialData...)
	}

	// 使用 WaitReadCloser 进行异步响应处理
	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)

	// 异步发送请求
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("request panic: %v", r)
			}
		}()

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.waitReader.Fail(err)
			errChan <- err
			return
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			c.waitReader.Fail(fmt.Errorf("http error: %d %s, body: %s", resp.StatusCode, resp.Status, body))
			errChan <- fmt.Errorf("http error: %d", resp.StatusCode)
			return
		}

		// 设置响应体到 WaitReadCloser
		c.waitReader.SetReadCloser(resp.Body)
		respChan <- resp
	}()

	// 发送握手数据
	if _, err := c.pipeWriter.Write(handshakeData); err != nil {
		return fmt.Errorf("send Trojan handshake: %w", err)
	}

	// 更新请求统计
	c.lastRequestTime = time.Now()
	c.requestCount++

	// 等待响应
	select {
	case <-respChan:
		c.respBody = c.waitReader
		c.connected = true
		log.V("[XHTTP] Trojan connected, target: %s", target)
		return nil
	case err := <-errChan:
		return fmt.Errorf("request failed: %w", err)
	case <-time.After(c.transport.connectionTimeout.RandDuration()):
		return fmt.Errorf("connection timeout")
	}
}

func (c *StreamOneConn) connectEWP(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pipeReader, c.pipeWriter = io.Pipe()

	// 使用 Transport 的随机化配置
	requestInterval := c.transport.requestInterval.RandDuration()
	if requestInterval > 0 && !c.lastRequestTime.IsZero() {
		elapsed := time.Since(c.lastRequestTime)
		if elapsed < requestInterval {
			time.Sleep(requestInterval - elapsed)
		}
	}

	// 构造 URL - ECH 环境下不在路径中添加 padding
	reqURL := fmt.Sprintf("https://%s:%s%s", c.host, c.port, c.path)

	// 使用新的请求创建方法
	ctx := context.Background()
	req, err := c.transport.createRequestWithContext(ctx, "POST", reqURL, c.pipeReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// 使用统一的头部管理
	headers := c.transport.GetRequestHeader(reqURL)
	for k, v := range headers {
		req.Header[k] = v
	}
	req.Header.Set("X-Auth-Token", c.uuidStr)
	req.Header.Set("Content-Type", "application/octet-stream")

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

	if len(initialData) > 0 {
		handshakeData = append(handshakeData, initialData...)
	}

	// 使用 WaitReadCloser 进行异步响应处理
	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)

	// 异步发送请求
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("request panic: %v", r)
			}
		}()

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.waitReader.Fail(err)
			errChan <- err
			return
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			c.waitReader.Fail(fmt.Errorf("http error: %d %s, body: %s", resp.StatusCode, resp.Status, body))
			errChan <- fmt.Errorf("http error: %d", resp.StatusCode)
			return
		}

		// 设置响应体到 WaitReadCloser
		c.waitReader.SetReadCloser(resp.Body)
		respChan <- resp
	}()

	// 发送握手数据
	if _, err := c.pipeWriter.Write(handshakeData); err != nil {
		return fmt.Errorf("send EWP handshake: %w", err)
	}

	// 更新请求统计
	c.lastRequestTime = time.Now()
	c.requestCount++

	// 等待响应
	select {
	case <-respChan:
		// Bug-F: wrap in bufio.Reader so bytes read beyond the 26-byte handshake
		// response are buffered and available to subsequent Read() calls, preventing
		// silent data loss when the server sends handshake+data in a single TCP segment.
		br := bufio.NewReaderSize(c.waitReader, 65536)
		c.respBody = struct {
			io.Reader
			io.Closer
		}{br, c.waitReader}
		c.connected = true
		log.V("[XHTTP] EWP connected, target: %s", target)
	case err := <-errChan:
		return fmt.Errorf("request failed: %w", err)
	case <-time.After(c.transport.connectionTimeout.RandDuration()):
		return fmt.Errorf("connection timeout")
	}

	// ewp.HandshakeResponse.Encode() always produces exactly 26 bytes.
	// Using io.ReadFull guarantees we consume only those 26 bytes; any
	// application data that arrived in the same read is retained in the
	// bufio.Reader above and returned by the next Read() call.
	const ewpHandshakeRespSize = 26
	handshakeResp := make([]byte, ewpHandshakeRespSize)
	if _, err := io.ReadFull(c.respBody, handshakeResp); err != nil {
		return fmt.Errorf("read EWP handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(handshakeResp, ewpReq.Version, ewpReq.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode EWP handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("EWP handshake failed with status: %d", resp.Status)
	}

	c.connected = true
	log.V("[XHTTP] stream-one EWP handshake success, target: %s", target)
	return nil
}

func (c *StreamOneConn) ConnectUDP(target transport.Endpoint, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojanUDP(target, initialData)
	}
	return c.connectEWPUDP(target, initialData)
}

func (c *StreamOneConn) connectEWPUDP(target transport.Endpoint, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pipeReader, c.pipeWriter = io.Pipe()

	requestInterval := c.transport.requestInterval.RandDuration()
	if requestInterval > 0 && !c.lastRequestTime.IsZero() {
		elapsed := time.Since(c.lastRequestTime)
		if elapsed < requestInterval {
			time.Sleep(requestInterval - elapsed)
		}
	}

	reqURL := fmt.Sprintf("https://%s:%s%s", c.host, c.port, c.path)

	ctx := context.Background()
	req, err := c.transport.createRequestWithContext(ctx, "POST", reqURL, c.pipeReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	headers := c.transport.GetRequestHeader(reqURL)
	for k, v := range headers {
		req.Header[k] = v
	}
	req.Header.Set("X-Auth-Token", c.uuidStr)
	req.Header.Set("Content-Type", "application/octet-stream")

	var addr ewp.Address
	if target.Domain != "" {
		addr = ewp.Address{Type: ewp.AddressTypeDomain, Host: target.Domain, Port: target.Port}
	} else {
		addr = ewp.AddressFromAddrPort(target.Addr)
	}

	ewpReq := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)
	handshakeData, err := ewpReq.Encode()
	if err != nil {
		return fmt.Errorf("encode EWP UDP handshake: %w", err)
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("request panic: %v", r)
			}
		}()

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.waitReader.Fail(err)
			errChan <- err
			return
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			c.waitReader.Fail(fmt.Errorf("http error: %d %s, body: %s", resp.StatusCode, resp.Status, body))
			errChan <- fmt.Errorf("http error: %d", resp.StatusCode)
			return
		}

		c.waitReader.SetReadCloser(resp.Body)
		respChan <- resp
	}()

	if _, err := c.pipeWriter.Write(handshakeData); err != nil {
		return fmt.Errorf("send EWP UDP handshake: %w", err)
	}

	c.lastRequestTime = time.Now()
	c.requestCount++

	select {
	case <-respChan:
		c.respBody = c.waitReader
	case err := <-errChan:
		return fmt.Errorf("request failed: %w", err)
	case <-time.After(c.transport.connectionTimeout.RandDuration()):
		return fmt.Errorf("connection timeout")
	}

	handshakeResp := make([]byte, 64)
	n, err := c.respBody.Read(handshakeResp)
	if err != nil {
		return fmt.Errorf("read EWP UDP handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(handshakeResp[:n], ewpReq.Version, ewpReq.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode EWP UDP handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("EWP UDP handshake failed with status: %d", resp.Status)
	}

	c.udpGlobalID = ewp.NewGlobalID()

	var encoded []byte
	if target.Domain != "" {
		// Send domain directly to server; local DNS resolution would return a FakeIP in TUN mode.
		pkt := &ewp.UDPPacketDomain{
			GlobalID: c.udpGlobalID,
			Status:   ewp.UDPStatusNew,
			Domain:   target.Domain,
			Port:     target.Port,
			Payload:  initialData,
		}
		var encErr error
		encoded, encErr = ewp.EncodeUDPDomainPacket(pkt)
		if encErr != nil {
			return fmt.Errorf("encode UDP domain new packet: %w", encErr)
		}
	} else {
		pkt := &ewp.UDPPacketAddr{
			GlobalID: c.udpGlobalID,
			Status:   ewp.UDPStatusNew,
			Target:   target.Addr,
			Payload:  initialData,
		}
		var encErr error
		encoded, encErr = ewp.EncodeUDPAddrPacket(pkt)
		if encErr != nil {
			return fmt.Errorf("encode UDP new packet: %w", encErr)
		}
	}

	if _, err := c.pipeWriter.Write(encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
	}

	c.connected = true
	log.V("[XHTTP] stream-one EWP UDP handshake success, target: %v", target)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel
func (c *StreamOneConn) WriteUDP(target transport.Endpoint, data []byte) error {
	if c.useTrojan {
		length := uint16(len(data))
		addrLen := 7
		if target.Domain != "" {
			addrLen = 1 + 1 + len(target.Domain) + 2
		} else if target.Addr.Addr().Is6() {
			addrLen = 19
		}
		buf := make([]byte, 0, addrLen+4+len(data))
		if target.Domain != "" {
			buf = append(buf, trojan.AddressTypeDomain, byte(len(target.Domain)))
			buf = append(buf, []byte(target.Domain)...)
			buf = append(buf, byte(target.Port>>8), byte(target.Port))
		} else {
			buf = trojan.AppendAddrPort(buf, target.Addr)
		}
		buf = append(buf, byte(length>>8), byte(length))
		buf = append(buf, trojan.CRLF...)
		buf = append(buf, data...)

		_, err := c.pipeWriter.Write(buf)
		return err
	}

	if target.Domain != "" {
		buf := make([]byte, 0, 2+8+1+1+(1+1+len(target.Domain)+2)+2+len(data))
		buf = ewp.AppendUDPDomainFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, target.Domain, target.Port, data)
		return c.Write(buf)
	}

	addrLen := 7
	if target.Addr.IsValid() && target.Addr.Addr().Is6() {
		addrLen = 19
	}
	buf := make([]byte, 0, 2+8+1+1+addrLen+2+len(data))
	buf = ewp.AppendUDPAddrFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, target.Addr, data)
	return c.Write(buf)
}

// ReadUDP reads and decodes a UDP response packet from a streaming response
func (c *StreamOneConn) ReadUDP() ([]byte, error) {
	if c.respBody == nil {
		return nil, errors.New("not connected")
	}

	if c.useTrojan {
		return c.readTrojanUDP()
	}

	pkt, err := ewp.DecodeUDPPacket(c.respBody)
	if err != nil {
		return nil, err
	}
	return pkt.Payload, nil
}

// ReadUDPTo reads and decodes a UDP response packet directly into the provided buffer
func (c *StreamOneConn) ReadUDPTo(buf []byte) (int, error) {
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

func (c *StreamOneConn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	if c.respBody == nil {
		return 0, netip.AddrPort{}, errors.New("not connected")
	}

	if c.useTrojan {
		return readTrojanUDPWithAddrFromReader(c.respBody, buf)
	}

	return ewp.DecodeUDPAddrPacketTo(c.respBody, buf)
}

func (c *StreamOneConn) readTrojanUDP() ([]byte, error) {
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

func (c *StreamOneConn) connectTrojanUDP(target transport.Endpoint, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pipeReader, c.pipeWriter = io.Pipe()

	// 使用 Transport 的随机化配置
	requestInterval := c.transport.requestInterval.RandDuration()
	if requestInterval > 0 && !c.lastRequestTime.IsZero() {
		elapsed := time.Since(c.lastRequestTime)
		if elapsed < requestInterval {
			time.Sleep(requestInterval - elapsed)
		}
	}

	// 构造 URL - ECH 环境下不在路径中添加 padding
	reqURL := fmt.Sprintf("https://%s:%s%s", c.host, c.port, c.path)

	// 使用新的请求创建方法（带 httptrace 和 WithoutCancel）
	ctx := context.Background()
	req, err := c.transport.createRequestWithContext(ctx, "POST", reqURL, c.pipeReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// 使用统一的头部管理
	headers := c.transport.GetRequestHeader(reqURL)
	for k, v := range headers {
		req.Header[k] = v
	}
	req.Header.Set("X-Auth-Token", c.uuidStr)
	req.Header.Set("Content-Type", "application/octet-stream")

	// Build Trojan UDP handshake
	key := trojan.GenerateKey(c.password)
	var handshakeData []byte
	handshakeData = append(handshakeData, key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandUDP) // ← UDP command

	if target.Domain != "" {
		handshakeData = append(handshakeData, trojan.AddressTypeDomain, byte(len(target.Domain)))
		handshakeData = append(handshakeData, []byte(target.Domain)...)
		handshakeData = append(handshakeData, byte(target.Port>>8), byte(target.Port))
	} else {
		handshakeData = trojan.AppendAddrPort(handshakeData, target.Addr)
	}
	handshakeData = append(handshakeData, trojan.CRLF...)

	// 使用 WaitReadCloser 进行异步响应处理
	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)

	// 异步发送请求
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("request panic: %v", r)
			}
		}()

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.waitReader.Fail(err)
			errChan <- err
			return
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			c.waitReader.Fail(fmt.Errorf("http error: %d %s, body: %s", resp.StatusCode, resp.Status, body))
			errChan <- fmt.Errorf("http error: %d", resp.StatusCode)
			return
		}

		// 设置响应体到 WaitReadCloser
		c.waitReader.SetReadCloser(resp.Body)
		respChan <- resp
	}()

	// 发送握手数据
	if _, err := c.pipeWriter.Write(handshakeData); err != nil {
		return fmt.Errorf("send Trojan UDP handshake: %w", err)
	}

	// 更新请求统计
	c.lastRequestTime = time.Now()
	c.requestCount++

	// 等待响应
	select {
	case <-respChan:
		c.respBody = c.waitReader
	case err := <-errChan:
		return fmt.Errorf("request failed: %w", err)
	case <-time.After(c.transport.connectionTimeout.RandDuration()):
		return fmt.Errorf("connection timeout")
	}

	// For Trojan UDP, no additional EWP UDPStatusNew packet is needed.
	// The UDP handshake and target are already included in initial write.

	c.connected = true
	log.V("[XHTTP] Trojan UDP connected, target: %v", target)
	return nil
}

func (c *StreamOneConn) Read(buf []byte) (int, error) {
	if c.respBody == nil {
		return 0, errors.New("not connected")
	}

	n, err := c.respBody.Read(buf)
	if err != nil {
		return 0, err
	}

	// Only apply flow processing for EWP mode
	if !c.useTrojan && c.flowState != nil && c.enableFlow {
		data := c.flowState.ProcessDownlink(buf[:n])
		n = copy(buf, data)
	}

	return n, nil
}

func (c *StreamOneConn) Write(data []byte) error {
	if c.pipeWriter == nil {
		return errors.New("not connected")
	}

	var writeData []byte
	// Only apply flow processing for EWP mode
	if !c.useTrojan && c.flowState != nil && c.enableFlow {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}

	_, err := c.pipeWriter.Write(writeData)
	return err
}

func (c *StreamOneConn) Close() error {
	var err error
	if c.pipeWriter != nil {
		err = c.pipeWriter.Close()
	}
	if c.respBody != nil {
		err2 := c.respBody.Close()
		if err == nil {
			err = err2
		}
	}
	return err
}

func (c *StreamOneConn) StartPing(interval time.Duration) chan struct{} {
	return make(chan struct{})
}
