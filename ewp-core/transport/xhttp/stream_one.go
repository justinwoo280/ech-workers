package xhttp

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"
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
	paddingMin int
	paddingMax int

	pipeReader        *io.PipeReader
	pipeWriter        *io.PipeWriter
	respBody          io.ReadCloser
	connected         bool
	mu                sync.Mutex
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte
}

func NewStreamOneConn(httpClient *http.Client, host, port, path string, uuid [16]byte, uuidStr, password string, enableFlow, useTrojan bool, paddingMin, paddingMax int) *StreamOneConn {
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
		paddingMin: paddingMin,
		paddingMax: paddingMax,
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

	paddingLen := c.paddingMin
	if c.paddingMax > c.paddingMin {
		paddingLen += int(time.Now().UnixNano() % int64(c.paddingMax-c.paddingMin))
	}
	padding := generatePadding(paddingLen)

	reqURL := fmt.Sprintf("https://%s:%s%s?x_padding=%s", c.host, c.port, c.path, padding)

	req, err := http.NewRequest("POST", reqURL, c.pipeReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
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

	connEstablished := make(chan struct{})
	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)

	go func() {
		resp, err := c.httpClient.Do(req)
		close(connEstablished)
		if err != nil {
			errChan <- err
			return
		}
		respChan <- resp
	}()

	if _, err := c.pipeWriter.Write(handshakeData); err != nil {
		return fmt.Errorf("send Trojan handshake: %w", err)
	}

	<-connEstablished

	select {
	case resp := <-respChan:
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("http error: %d %s, body: %s", resp.StatusCode, resp.Status, body)
		}
		c.respBody = resp.Body
	case err := <-errChan:
		return fmt.Errorf("http request failed: %w", err)
	case <-time.After(5 * time.Second):
		return errors.New("connect timeout")
	}

	c.connected = true
	log.V("[XHTTP] stream-one Trojan handshake success, target: %s", target)
	return nil
}

func (c *StreamOneConn) connectEWP(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pipeReader, c.pipeWriter = io.Pipe()

	paddingLen := c.paddingMin
	if c.paddingMax > c.paddingMin {
		paddingLen += int(time.Now().UnixNano() % int64(c.paddingMax-c.paddingMin))
	}
	padding := generatePadding(paddingLen)

	reqURL := fmt.Sprintf("https://%s:%s%s?x_padding=%s", c.host, c.port, c.path, padding)

	req, err := http.NewRequest("POST", reqURL, c.pipeReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
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

	connEstablished := make(chan struct{})
	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)

	go func() {
		resp, err := c.httpClient.Do(req)
		close(connEstablished)
		if err != nil {
			errChan <- err
			return
		}
		respChan <- resp
	}()

	if _, err := c.pipeWriter.Write(handshakeData); err != nil {
		return fmt.Errorf("send EWP handshake: %w", err)
	}

	<-connEstablished

	select {
	case resp := <-respChan:
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("http error: %d %s, body: %s", resp.StatusCode, resp.Status, body)
		}
		c.respBody = resp.Body
	case err := <-errChan:
		return fmt.Errorf("http request failed: %w", err)
	case <-time.After(5 * time.Second):
		return errors.New("connect timeout")
	}

	handshakeResp := make([]byte, 64)
	n, err := c.respBody.Read(handshakeResp)
	if err != nil {
		return fmt.Errorf("read EWP handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(handshakeResp[:n], ewpReq.Version, ewpReq.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode EWP handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("EWP handshake failed with status: %d", resp.Status)
	}

	if len(initialData) > 0 {
		if err := c.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	c.connected = true
	log.V("[XHTTP] stream-one EWP handshake success, target: %s", target)
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
