package xhttp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	paddingMin        int
	paddingMax        int
	uploadSeq         uint64
	respBody          io.ReadCloser
	uploadMu          sync.Mutex
	connected         bool
	mu                sync.Mutex
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte
}

func NewStreamDownConn(httpClient *http.Client, host, port, path string, uuid [16]byte, uuidStr, password string, enableFlow, useTrojan bool, paddingMin, paddingMax int) *StreamDownConn {
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	sessionID := fmt.Sprintf("%x%x", uuid[:4], randomBytes)

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
		paddingMin: paddingMin,
		paddingMax: paddingMax,
		uploadSeq:  0,
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

	paddingLen := c.paddingMin
	if c.paddingMax > c.paddingMin {
		paddingLen += int(time.Now().UnixNano() % int64(c.paddingMax-c.paddingMin))
	}
	padding := generatePadding(paddingLen)

	handshakeURL := fmt.Sprintf("https://%s:%s%s/%s/0?x_padding=%s", c.host, c.port, c.path, c.sessionID, padding)
	handshakeReq, err := http.NewRequest("POST", handshakeURL, bytes.NewReader(handshakeData))
	if err != nil {
		return fmt.Errorf("create handshake request: %w", err)
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

	padding = generatePadding(paddingLen)
	getURL := fmt.Sprintf("https://%s:%s%s/%s?x_padding=%s", c.host, c.port, c.path, c.sessionID, padding)
	getReq, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return fmt.Errorf("create GET request: %w", err)
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

	paddingLen := c.paddingMin
	if c.paddingMax > c.paddingMin {
		paddingLen += int(time.Now().UnixNano() % int64(c.paddingMax-c.paddingMin))
	}
	padding := generatePadding(paddingLen)

	seq := c.uploadSeq
	c.uploadSeq++

	reqURL := fmt.Sprintf("https://%s:%s%s/%s/%d?x_padding=%s", c.host, c.port, c.path, c.sessionID, seq, padding)
	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(writeData))
	if err != nil {
		return err
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

func (c *StreamDownConn) StartPing(interval time.Duration) chan struct{} {
	return make(chan struct{})
}
