package xhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
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
func generateSessionID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func (c *StreamDownConn) StartPing(interval time.Duration) chan struct{} {
	return make(chan struct{})
}
