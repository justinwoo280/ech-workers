package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	pb "ech-client/proto"
	"ech-client/ewp"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// ======================== Buffer Pool (性能优化) ========================

var (
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 512)
		},
	}
	
	largeBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
)

const (
	TransportWebSocket = "ws"
	TransportGRPC      = "grpc"
	TransportXHTTP     = "xhttp"
)

// ======================== 地址解析 ========================

// ParsedAddress 解析后的服务器地址
type ParsedAddress struct {
	Scheme   string // ws, wss, grpc, grpcs, http, https
	Host     string
	Port     string
	Path     string // 对于 WebSocket/XHTTP 是路径，对于 gRPC 是服务名
	UseTLS   bool
	RawAddr  string // 原始地址
}

// parseServerAddr 解析服务器地址（参考 Xray 格式）
// 支持格式:
//   - wss://example.com:443/ws-path
//   - grpcs://example.com:443/ServiceName
//   - https://example.com:443/xhttp
//   - example.com:443/path (默认 wss)
func parseServerAddr(addr string) (host, port, path string, err error) {
	parsed, err := parseAddress(addr)
	if err != nil {
		return "", "", "", err
	}
	return parsed.Host, parsed.Port, parsed.Path, nil
}

func parseAddress(addr string) (*ParsedAddress, error) {
	parsed := &ParsedAddress{
		RawAddr: addr,
		Path:    "/",
	}
	
	// 去除协议前缀
	addr = strings.TrimSpace(addr)
	scheme := ""
	
	if strings.Contains(addr, "://") {
		parts := strings.SplitN(addr, "://", 2)
		scheme = strings.ToLower(parts[0])
		addr = parts[1]
	}
	
	// 提取路径
	slashIdx := strings.Index(addr, "/")
	if slashIdx != -1 {
		parsed.Path = addr[slashIdx:]
		addr = addr[:slashIdx]
	}
	
	// 解析 host:port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// 没有端口，尝试添加默认端口
		host = addr
		switch scheme {
		case "ws", "http":
			port = "80"
		case "wss", "https", "grpc", "grpcs":
			port = "443"
		default:
			port = "443" // 默认 HTTPS 端口
		}
	}
	
	parsed.Host = host
	parsed.Port = port
	
	// 确定协议和TLS
	switch scheme {
	case "ws":
		parsed.Scheme = "ws"
		parsed.UseTLS = false
	case "wss":
		parsed.Scheme = "wss"
		parsed.UseTLS = true
	case "grpc":
		parsed.Scheme = "grpc"
		parsed.UseTLS = false
	case "grpcs":
		parsed.Scheme = "grpcs"
		parsed.UseTLS = true
	case "http":
		parsed.Scheme = "http"
		parsed.UseTLS = false
	case "https":
		parsed.Scheme = "https"
		parsed.UseTLS = true
	default:
		// 默认 wss
		parsed.Scheme = "wss"
		parsed.UseTLS = true
	}
	
	return parsed, nil
}

// ======================== UUID 处理 ========================

func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")
	
	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d", len(s))
	}
	
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return uuid, fmt.Errorf("invalid UUID hex: %w", err)
	}
	
	copy(uuid[:], decoded)
	return uuid, nil
}

// ======================== Transport 接口定义 ========================

// TunnelConn 表示一个隧道连接（抽象接口）
type TunnelConn interface {
	// Connect 发送连接请求并等待响应
	Connect(target string, initialData []byte) error
	// Read 从隧道读取数据到提供的buffer（零拷贝优化）
	Read(buf []byte) (int, error)
	// Write 向隧道写入数据
	Write(data []byte) error
	// Close 关闭连接
	Close() error
	// StartPing 启动心跳（返回停止通道）
	StartPing(interval time.Duration) chan struct{}
}

// Transport 传输层接口
type Transport interface {
	// Dial 建立新连接
	Dial() (TunnelConn, error)
	// Name 返回传输层名称
	Name() string
}

// ======================== WebSocket Transport ========================

type WebSocketTransport struct {
	serverAddr      string
	serverIP        string
	token           string
	uuid            [16]byte
	useTLS          bool
	useECH          bool
	enableFlow      bool
	path            string
	host            string
	headers         map[string]string
	earlyDataLength int
	heartbeatPeriod time.Duration
	wsConn          *websocket.Conn
}

func NewWebSocketTransport(serverAddr, serverIP, token string, useECH, enableFlow bool, path string) *WebSocketTransport {
	uuid, err := parseUUID(token)
	if err != nil {
		log.Printf("[警告] 无法解析 UUID，将使用 token 原值: %v", err)
	}

	if path == "" {
		path = "/"
	}

	t := &WebSocketTransport{
		serverAddr:      serverAddr,
		serverIP:        serverIP,
		token:           token,
		uuid:            uuid,
		useTLS:          true,
		useECH:          useECH,
		enableFlow:      enableFlow,
		path:            path,
		headers:         make(map[string]string),
		earlyDataLength: 0,
		heartbeatPeriod: 0,
	}

	return t
}

func (t *WebSocketTransport) SetHost(host string) *WebSocketTransport {
	t.host = host
	return t
}

func (t *WebSocketTransport) SetHeaders(headers map[string]string) *WebSocketTransport {
	t.headers = headers
	return t
}

func (t *WebSocketTransport) SetEarlyData(length int) *WebSocketTransport {
	t.earlyDataLength = length
	return t
}

func (t *WebSocketTransport) SetHeartbeat(period time.Duration) *WebSocketTransport {
	t.heartbeatPeriod = period
	return t
}

func (t *WebSocketTransport) Name() string {
	var name string
	if t.enableFlow {
		name = "WebSocket+Vision"
	} else {
		name = "WebSocket"
	}
	if t.useECH {
		name += "+ECH"
	} else {
		name += "+TLS"
	}
	return name
}

func (t *WebSocketTransport) Dial() (TunnelConn, error) {
	// EWP Flow 模式：使用 Vision 风格流控协议
	if t.enableFlow {
		return t.dialFlow()
	}

	// 简单协议模式
	return t.dialSimple()
}

func (t *WebSocketTransport) Close() error {
	if t.wsConn != nil {
		t.wsConn.Close()
		t.wsConn = nil
	}

	return nil
}

// dialFlow EWP Flow 协议（Vision 风格流控，替代 Yamux）
func (t *WebSocketTransport) dialFlow() (TunnelConn, error) {
	host, port, _, err := parseServerAddr(t.serverAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, t.path)

	var tlsCfg *tls.Config

	if t.useECH {
		echBytes, echErr := getECHList()
		if echErr != nil {
			return nil, echErr
		}
		tlsCfg, err = buildTLSConfigWithECH(host, echBytes)
		if err != nil {
			return nil, err
		}
	} else {
		tlsCfg = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS13,
		}
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 10 * time.Second,
	}

	if t.serverIP != "" {
		dialer.NetDial = func(network, address string) (net.Conn, error) {
			_, p, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return net.DialTimeout(network, net.JoinHostPort(t.serverIP, p), 10*time.Second)
		}
	}

	headers := http.Header{}
	if t.host != "" {
		headers.Set("Host", t.host)
	}
	for k, v := range t.headers {
		headers.Set(k, v)
	}

	wsConn, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		return nil, err
	}

	t.wsConn = wsConn

	logV("[Flow] 新建 EWP Flow 连接")
	return &FlowWSConn{
		conn:            wsConn,
		uuid:            t.uuid,
		streamID:        1,
		heartbeatPeriod: t.heartbeatPeriod,
		earlyDataLength: t.earlyDataLength,
	}, nil
}

// dialSimple 简单 WebSocket 协议（兼容 Cloudflare Workers）
func (t *WebSocketTransport) dialSimple() (TunnelConn, error) {
	host, port, _, err := parseServerAddr(t.serverAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, t.path)

	var tlsCfg *tls.Config

	if t.useECH {
		echBytes, echErr := getECHList()
		if echErr != nil {
			return nil, echErr
		}
		tlsCfg, err = buildTLSConfigWithECH(host, echBytes)
		if err != nil {
			return nil, err
		}
	} else {
		tlsCfg = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS13,
		}
	}

	dialer := websocket.Dialer{
		TLSClientConfig: tlsCfg,
		Subprotocols: func() []string {
			if t.token == "" {
				return nil
			}
			return []string{t.token}
		}(),
		HandshakeTimeout: 10 * time.Second,
	}

	if t.serverIP != "" {
		dialer.NetDial = func(network, address string) (net.Conn, error) {
			_, p, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return net.DialTimeout(network, net.JoinHostPort(t.serverIP, p), 10*time.Second)
		}
	}

	headers := http.Header{}
	if t.host != "" {
		headers.Set("Host", t.host)
	}
	for k, v := range t.headers {
		headers.Set(k, v)
	}

	wsConn, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		return nil, err
	}

	logV("[WebSocket] 新建简单协议连接")
	return &SimpleWSConn{
		conn:            wsConn,
		uuid:            t.uuid,
		heartbeatPeriod: t.heartbeatPeriod,
		earlyDataLength: t.earlyDataLength,
	}, nil
}

type SimpleWSConn struct {
	conn            *websocket.Conn
	uuid            [16]byte
	connected       bool
	mu              sync.Mutex
	version         byte
	nonce           [12]byte
	heartbeatPeriod time.Duration
	earlyDataLength int
	earlyDataSent   bool
}

func (c *SimpleWSConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)
	c.version = req.Version
	c.nonce = req.Nonce

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	if c.earlyDataLength > 0 && len(initialData) > 0 && len(initialData) <= c.earlyDataLength && !c.earlyDataSent {
		combinedData := append(handshakeData, initialData...)
		if err := c.conn.WriteMessage(websocket.BinaryMessage, combinedData); err != nil {
			return fmt.Errorf("send handshake with early data: %w", err)
		}
		c.earlyDataSent = true
	} else {
		if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
			return fmt.Errorf("send handshake: %w", err)
		}
	}

	_, respData, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respData, c.version, c.nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	if len(initialData) > 0 && !c.earlyDataSent {
		if err := c.conn.WriteMessage(websocket.BinaryMessage, initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	c.connected = true
	logV("[EWP] 握手成功，目标: %s", target)
	return nil
}

func (c *SimpleWSConn) Read(buf []byte) (int, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	// 检查是否是控制消息
	if len(msg) > 0 {
		str := string(msg)
		if str == "CLOSE" {
			return 0, io.EOF
		}
		if strings.HasPrefix(str, "ERROR:") {
			return 0, errors.New(str)
		}
	}

	n := copy(buf, msg)
	return n, nil
}

func (c *SimpleWSConn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (c *SimpleWSConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// 发送 CLOSE 消息
	_ = c.conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
	return c.conn.Close()
}

func (c *SimpleWSConn) StartPing(interval time.Duration) chan struct{} {
	if c.heartbeatPeriod > 0 {
		interval = c.heartbeatPeriod
	}
	if interval == 0 {
		return make(chan struct{})
	}
	
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				err := c.conn.WriteMessage(websocket.PingMessage, nil)
				c.mu.Unlock()
				if err != nil {
					return
				}
			case <-stop:
				return
			}
		}
	}()
	return stop
}

type FlowWSConn struct {
	conn              *websocket.Conn
	uuid              [16]byte
	streamID          uint16
	connected         bool
	mu                sync.Mutex
	version           byte
	nonce             [12]byte
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte
	heartbeatPeriod   time.Duration
	earlyDataLength   int
	earlyDataSent     bool
}

func (c *FlowWSConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)
	c.version = req.Version
	c.nonce = req.Nonce

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	_, respData, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respData, c.version, c.nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	// 初始化 Flow State
	c.flowState = ewp.NewFlowState(c.uuid[:])
	c.writeOnceUserUUID = make([]byte, 16)
	copy(c.writeOnceUserUUID, c.uuid[:])

	if len(initialData) > 0 && !c.earlyDataSent {
		if err := c.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	c.connected = true
	logV("[Flow] 握手成功，目标: %s, StreamID: %d", target, c.streamID)
	return nil
}

func (c *FlowWSConn) Read(buf []byte) (int, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	// 检查是否是控制消息
	if len(msg) > 0 {
		str := string(msg)
		if str == "CLOSE" {
			return 0, io.EOF
		}
		if strings.HasPrefix(str, "ERROR:") {
			return 0, errors.New(str)
		}
	}

	// 处理 Flow 协议解包（移除填充）
	if c.flowState != nil {
		msg = c.flowState.ProcessDownlink(msg)
	}

	n := copy(buf, msg)
	return n, nil
}

func (c *FlowWSConn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 应用 Flow 协议填充
	var writeData []byte
	if c.flowState != nil {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}

	return c.conn.WriteMessage(websocket.BinaryMessage, writeData)
}

func (c *FlowWSConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
	return c.conn.Close()
}

func (c *FlowWSConn) StartPing(interval time.Duration) chan struct{} {
	if c.heartbeatPeriod > 0 {
		interval = c.heartbeatPeriod
	}
	if interval == 0 {
		return make(chan struct{})
	}
	
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				err := c.conn.WriteMessage(websocket.PingMessage, nil)
				c.mu.Unlock()
				if err != nil {
					return
				}
			case <-stop:
				return
			}
		}
	}()
	return stop
}

// ======================== gRPC Transport ========================

type GRPCTransport struct {
	serverAddr         string
	serverIP           string
	uuidStr            string
	uuid               [16]byte
	useTLS             bool
	useECH             bool
	enableFlow         bool
	serviceName        string
	authority          string
	idleTimeout        time.Duration
	healthCheckTimeout time.Duration
	permitWithoutStream bool
	initialWindowSize  int32
	userAgent          string
}

func NewGRPCTransport(serverAddr, serverIP, uuidStr string, useTLS, useECH, enableFlow bool, serviceName string) *GRPCTransport {
	uuid, err := parseUUID(uuidStr)
	if err != nil {
		log.Printf("[警告] 无法解析 UUID: %v", err)
	}

	if serviceName == "" {
		serviceName = "/ProxyService"
	}

	return &GRPCTransport{
		serverAddr:          serverAddr,
		serverIP:            serverIP,
		uuidStr:             uuidStr,
		uuid:                uuid,
		useTLS:              useTLS,
		useECH:              useECH,
		enableFlow:          enableFlow,
		serviceName:         serviceName,
		authority:           "",
		idleTimeout:         0,
		healthCheckTimeout:  0,
		permitWithoutStream: false,
		initialWindowSize:   0,
		userAgent:           "",
	}
}

func (t *GRPCTransport) SetAuthority(authority string) *GRPCTransport {
	t.authority = authority
	return t
}

func (t *GRPCTransport) SetKeepalive(idleTimeout, healthCheckTimeout time.Duration, permitWithoutStream bool) *GRPCTransport {
	t.idleTimeout = idleTimeout
	t.healthCheckTimeout = healthCheckTimeout
	t.permitWithoutStream = permitWithoutStream
	return t
}

func (t *GRPCTransport) SetInitialWindowSize(size int32) *GRPCTransport {
	t.initialWindowSize = size
	return t
}

func (t *GRPCTransport) SetUserAgent(userAgent string) *GRPCTransport {
	t.userAgent = userAgent
	return t
}

func (t *GRPCTransport) Name() string {
	var name string
	if t.enableFlow {
		name = "gRPC+Flow"
	} else {
		name = "gRPC"
	}
	if t.useECH {
		name += "+ECH"
	} else if t.useTLS {
		name += "+TLS"
	}
	return name
}

func (t *GRPCTransport) Dial() (TunnelConn, error) {
	host, port, _, err := parseServerAddr(t.serverAddr)
	if err != nil {
		return nil, err
	}

	// 确定连接地址
	addr := net.JoinHostPort(host, port)
	if t.serverIP != "" {
		addr = net.JoinHostPort(t.serverIP, port)
	}

	var opts []grpc.DialOption

	if t.useTLS || t.useECH {
		var tlsCfg *tls.Config

		if t.useECH {
			echBytes, echErr := getECHList()
			if echErr != nil {
				return nil, fmt.Errorf("获取 ECH 配置失败: %w", echErr)
			}
			tlsCfg, err = buildTLSConfigWithECH(host, echBytes)
			if err != nil {
				return nil, fmt.Errorf("构建 ECH TLS 配置失败: %w", err)
			}
			log.Printf("[gRPC] 使用 ECH + TLS 1.3 连接")
		} else {
			tlsCfg = &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS13,
			}
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if t.authority != "" {
		opts = append(opts, grpc.WithAuthority(t.authority))
	}

	if t.idleTimeout > 0 || t.healthCheckTimeout > 0 || t.permitWithoutStream {
		opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                t.idleTimeout,
			Timeout:             t.healthCheckTimeout,
			PermitWithoutStream: t.permitWithoutStream,
		}))
	}

	if t.initialWindowSize > 0 {
		opts = append(opts, grpc.WithInitialWindowSize(t.initialWindowSize))
	}

	if t.userAgent != "" {
		opts = append(opts, grpc.WithUserAgent(t.userAgent))
	}

	// 连接超时
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("gRPC dial failed: %w", err)
	}

	client := pb.NewProxyServiceClient(conn)

	stream, err := client.Tunnel(context.Background())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("gRPC stream failed: %w", err)
	}

	return &GRPCConn{
		conn:       conn,
		stream:     stream,
		uuid:       t.uuid,
		enableFlow: t.enableFlow,
	}, nil
}

// GRPCConn gRPC 连接实现
type GRPCConn struct {
	conn              *grpc.ClientConn
	stream            pb.ProxyService_TunnelClient
	uuid              [16]byte
	mu                sync.Mutex
	enableFlow        bool
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte
}

func (c *GRPCConn) Connect(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	c.mu.Lock()
	err = c.stream.Send(&pb.SocketData{Content: handshakeData})
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	respMsg, err := c.stream.Recv()
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respMsg.Content, req.Version, req.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	// 初始化 Flow State（如果启用）
	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	if len(initialData) > 0 {
		if err := c.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	logV("[EWP] gRPC 握手成功，目标: %s", target)
	return nil
}

func (c *GRPCConn) Read(buf []byte) (int, error) {
	resp, err := c.stream.Recv()
	if err != nil {
		return 0, err
	}

	data := resp.Content

	// 处理 Flow 协议（如果启用）
	if c.enableFlow && c.flowState != nil {
		data = c.flowState.ProcessDownlink(data)
	}

	n := copy(buf, data)
	return n, nil
}

func (c *GRPCConn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 应用 Flow 协议（如果启用）
	var writeData []byte
	if c.enableFlow && c.flowState != nil {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}

	return c.stream.Send(&pb.SocketData{Content: writeData})
}

func (c *GRPCConn) Close() error {
	if c.stream != nil {
		c.stream.CloseSend()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *GRPCConn) StartPing(interval time.Duration) chan struct{} {
	// gRPC 有内置的 keepalive，这里返回空的 stop channel
	stopChan := make(chan struct{})
	// gRPC 不需要应用层心跳
	return stopChan
}

// ======================== XHTTP Transport ========================

type XHTTPTransport struct {
	serverAddr string
	serverIP   string
	token      string
	uuid       [16]byte
	uuidStr    string
	useECH     bool
	enableFlow bool
	path       string
	paddingMin int
	paddingMax int
	mode       string
}

func NewXHTTPTransport(serverAddr, serverIP, token string, useECH, enableFlow bool, path string) *XHTTPTransport {
	uuid, err := parseUUID(token)
	if err != nil {
		log.Printf("[警告] 无法解析 UUID: %v", err)
	}

	if path == "" {
		path = "/xhttp"
	}

	return &XHTTPTransport{
		serverAddr: serverAddr,
		serverIP:   serverIP,
		token:      token,
		uuid:       uuid,
		uuidStr:    token,
		useECH:     useECH,
		enableFlow: enableFlow,
		path:       path,
		paddingMin: 100,
		paddingMax: 1000,
		mode:       "stream-one",
	}
}

func (t *XHTTPTransport) SetMode(mode string) *XHTTPTransport {
	t.mode = mode
	return t
}

func (t *XHTTPTransport) SetPaddingRange(min, max int) *XHTTPTransport {
	t.paddingMin = min
	t.paddingMax = max
	return t
}

func (t *XHTTPTransport) Name() string {
	name := "XHTTP"
	if t.enableFlow {
		name += "+Vision"
	}
	if t.useECH {
		name += "+ECH"
	}
	return name
}

func (t *XHTTPTransport) Dial() (TunnelConn, error) {
	if t.mode == "stream-down" {
		return t.dialStreamDown()
	}
	return t.dialStreamOne()
}

func (t *XHTTPTransport) dialStreamOne() (TunnelConn, error) {
	host, port, _, err := parseServerAddr(t.serverAddr)
	if err != nil {
		return nil, err
	}

	var tlsCfg *tls.Config
	if t.useECH {
		echBytes, echErr := getECHList()
		if echErr != nil {
			return nil, echErr
		}
		tlsCfg, err = buildTLSConfigWithECH(host, echBytes)
		if err != nil {
			return nil, err
		}
		// 强制使用 HTTP/2
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	} else {
		tlsCfg = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		}
	}

	var rawConn net.Conn
	target := net.JoinHostPort(host, port)
	if t.serverIP != "" {
		target = net.JoinHostPort(t.serverIP, port)
	}

	rawConn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	// 检查协商的协议
	negotiatedProto := tlsConn.ConnectionState().NegotiatedProtocol
	logV("[XHTTP] TLS连接建立，协议: %s", negotiatedProto)

	return &XHTTPStreamOneConn{
		conn:       tlsConn,
		host:       host,
		path:       t.path,
		uuid:       t.uuid,
		uuidStr:    t.uuidStr,
		enableFlow: t.enableFlow,
		paddingMin: t.paddingMin,
		paddingMax: t.paddingMax,
	}, nil
}

func (t *XHTTPTransport) Close() error {
	return nil
}

// XHTTPStreamOneConn XHTTP stream-one模式连接（最简单的双向流）
type XHTTPStreamOneConn struct {
	conn       net.Conn
	host       string
	path       string
	uuid       [16]byte
	uuidStr    string
	enableFlow bool
	paddingMin int
	paddingMax int
	reader     *bufio.Reader
	writer     *bufio.Writer
	connected  bool
	mu         sync.Mutex
	flowState  *ewp.FlowState
	writeOnceUserUUID []byte
}

func (c *XHTTPStreamOneConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 生成随机padding
	paddingLen := c.paddingMin
	if c.paddingMax > c.paddingMin {
		paddingLen += int(time.Now().UnixNano() % int64(c.paddingMax-c.paddingMin))
	}
	padding := generatePadding(paddingLen)

	// 构造HTTP POST请求（stream-one模式）
	reqBuilder := &strings.Builder{}
	reqBuilder.WriteString(fmt.Sprintf("POST %s?x_padding=%s HTTP/1.1\r\n", c.path, padding))
	reqBuilder.WriteString(fmt.Sprintf("Host: %s\r\n", c.host))
	reqBuilder.WriteString(fmt.Sprintf("X-Auth-Token: %s\r\n", c.uuidStr))
	reqBuilder.WriteString("Content-Type: application/octet-stream\r\n")
	reqBuilder.WriteString("Transfer-Encoding: chunked\r\n")
	reqBuilder.WriteString("Cache-Control: no-cache\r\n")
	reqBuilder.WriteString("\r\n")

	// 发送HTTP头
	if _, err := c.conn.Write([]byte(reqBuilder.String())); err != nil {
		return fmt.Errorf("send http headers: %w", err)
	}

	// 构造连接数据: "CONNECT:host:port\n" + initialData
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}
	
	connectMsg := fmt.Sprintf("CONNECT:%s\n", addr.String())
	var connectData []byte
	if len(initialData) > 0 {
		connectData = append([]byte(connectMsg), initialData...)
	} else {
		connectData = []byte(connectMsg)
	}

	// 发送第一个chunk（CONNECT消息）
	chunkHeader := fmt.Sprintf("%x\r\n", len(connectData))
	if _, err := c.conn.Write([]byte(chunkHeader)); err != nil {
		return fmt.Errorf("send chunk header: %w", err)
	}
	if _, err := c.conn.Write(connectData); err != nil {
		return fmt.Errorf("send connect data: %w", err)
	}
	if _, err := c.conn.Write([]byte("\r\n")); err != nil {
		return fmt.Errorf("send chunk trailer: %w", err)
	}

	// 初始化reader和writer
	c.reader = bufio.NewReader(c.conn)
	c.writer = bufio.NewWriter(c.conn)

	// 读取HTTP响应
	resp, err := http.ReadResponse(c.reader, nil)
	if err != nil {
		return fmt.Errorf("read http response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Errorf("http error: %d %s, body: %s", resp.StatusCode, resp.Status, body)
	}

	// 初始化 Flow State
	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	c.connected = true
	logV("[XHTTP] stream-one 连接成功，目标: %s", target)
	return nil
}

func (c *XHTTPStreamOneConn) Read(buf []byte) (int, error) {
	if c.reader == nil {
		c.reader = bufio.NewReader(c.conn)
	}

	n, err := c.reader.Read(buf)
	if err != nil {
		return 0, err
	}

	// 处理 Flow 协议解包
	if c.flowState != nil && c.enableFlow {
		data := c.flowState.ProcessDownlink(buf[:n])
		n = copy(buf, data)
	}

	return n, nil
}

func (c *XHTTPStreamOneConn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 应用 Flow 协议填充
	var writeData []byte
	if c.flowState != nil && c.enableFlow {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}

	// 写入chunked格式
	chunkHeader := fmt.Sprintf("%x\r\n", len(writeData))
	if _, err := c.conn.Write([]byte(chunkHeader)); err != nil {
		return err
	}
	if _, err := c.conn.Write(writeData); err != nil {
		return err
	}
	if _, err := c.conn.Write([]byte("\r\n")); err != nil {
		return err
	}

	return nil
}

func (c *XHTTPStreamOneConn) Close() error {
	// 发送结束chunk
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.Write([]byte("0\r\n\r\n"))
	return c.conn.Close()
}

func (c *XHTTPStreamOneConn) StartPing(interval time.Duration) chan struct{} {
	// HTTP/2 有内置的keepalive
	return make(chan struct{})
}

func generatePadding(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[int(time.Now().UnixNano()+int64(i))%len(chars)]
	}
	return string(result)
}

func (t *XHTTPTransport) dialStreamDown() (TunnelConn, error) {
	host, port, _, err := parseServerAddr(t.serverAddr)
	if err != nil {
		return nil, err
	}

	var tlsCfg *tls.Config
	if t.useECH {
		echBytes, echErr := getECHList()
		if echErr != nil {
			return nil, echErr
		}
		tlsCfg, err = buildTLSConfigWithECH(host, echBytes)
		if err != nil {
			return nil, err
		}
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	} else {
		tlsCfg = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		}
	}

	sessionID := fmt.Sprintf("%x", t.uuid[:8])

	return &XHTTPStreamDownConn{
		host:       host,
		port:       port,
		serverIP:   t.serverIP,
		path:       t.path,
		uuid:       t.uuid,
		uuidStr:    t.uuidStr,
		sessionID:  sessionID,
		tlsCfg:     tlsCfg,
		enableFlow: t.enableFlow,
		paddingMin: t.paddingMin,
		paddingMax: t.paddingMax,
		uploadSeq:  0,
	}, nil
}

type XHTTPStreamDownConn struct {
	host            string
	port            string
	serverIP        string
	path            string
	uuid            [16]byte
	uuidStr         string
	sessionID       string
	tlsCfg          *tls.Config
	enableFlow      bool
	paddingMin      int
	paddingMax      int
	uploadSeq       uint64
	downloadConn    net.Conn
	downloadReader  *bufio.Reader
	uploadMu        sync.Mutex
	connected       bool
	mu              sync.Mutex
	flowState       *ewp.FlowState
	writeOnceUserUUID []byte
}

func (c *XHTTPStreamDownConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	targetAddr := net.JoinHostPort(c.host, c.port)
	if c.serverIP != "" {
		targetAddr = net.JoinHostPort(c.serverIP, c.port)
	}

	rawConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return err
	}

	tlsConn := tls.Client(rawConn, c.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return err
	}

	c.downloadConn = tlsConn

	paddingLen := c.paddingMin
	if c.paddingMax > c.paddingMin {
		paddingLen += int(time.Now().UnixNano() % int64(c.paddingMax-c.paddingMin))
	}
	padding := generatePadding(paddingLen)

	reqURL := fmt.Sprintf("https://%s%s/%s?x_padding=%s", c.host, c.path, c.sessionID, padding)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		tlsConn.Close()
		return err
	}

	req.Host = c.host
	req.Header.Set("X-Auth-Token", c.uuidStr)
	req.Header.Set("X-Target", addr.String())

	if err := req.Write(tlsConn); err != nil {
		tlsConn.Close()
		return err
	}

	c.downloadReader = bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(c.downloadReader, req)
	if err != nil {
		tlsConn.Close()
		return err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		tlsConn.Close()
		return fmt.Errorf("http error: %d %s, body: %s", resp.StatusCode, resp.Status, body)
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	if len(initialData) > 0 {
		if err := c.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	c.connected = true
	logV("[XHTTP] stream-down 连接成功，目标: %s, SessionID: %s", target, c.sessionID)
	return nil
}

func (c *XHTTPStreamDownConn) Read(buf []byte) (int, error) {
	if c.downloadReader == nil {
		return 0, errors.New("not connected")
	}

	n, err := c.downloadReader.Read(buf)
	if err != nil {
		return 0, err
	}

	if c.flowState != nil && c.enableFlow {
		data := c.flowState.ProcessDownlink(buf[:n])
		n = copy(buf, data)
	}

	return n, nil
}

func (c *XHTTPStreamDownConn) Write(data []byte) error {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()

	var writeData []byte
	if c.flowState != nil && c.enableFlow {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}

	targetAddr := net.JoinHostPort(c.host, c.port)
	if c.serverIP != "" {
		targetAddr = net.JoinHostPort(c.serverIP, c.port)
	}

	rawConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return err
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, c.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	paddingLen := c.paddingMin
	if c.paddingMax > c.paddingMin {
		paddingLen += int(time.Now().UnixNano() % int64(c.paddingMax-c.paddingMin))
	}
	padding := generatePadding(paddingLen)

	seq := c.uploadSeq
	c.uploadSeq++

	reqURL := fmt.Sprintf("https://%s%s/%s/%d?x_padding=%s", c.host, c.path, c.sessionID, seq, padding)
	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(writeData))
	if err != nil {
		return err
	}

	req.Host = c.host
	req.Header.Set("X-Auth-Token", c.uuidStr)
	req.ContentLength = int64(len(writeData))

	if err := req.Write(tlsConn); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed: %s", resp.Status)
	}

	return nil
}

func (c *XHTTPStreamDownConn) Close() error {
	if c.downloadConn != nil {
		return c.downloadConn.Close()
	}
	return nil
}

func (c *XHTTPStreamDownConn) StartPing(interval time.Duration) chan struct{} {
	return make(chan struct{})
}

// ======================== Transport 工厂函数 ========================

var (
	currentTransport Transport
	transportMode    string
)

// InitTransport 初始化传输层（支持自动协议检测）
func InitTransport(mode, serverAddr, serverIP, token string, useECH, enableFlow bool) {
	// 解析地址以获取协议信息
	parsed, err := parseAddress(serverAddr)
	if err != nil {
		log.Printf("[警告] 地址解析失败: %v，使用默认模式", err)
		parsed = &ParsedAddress{
			Scheme: "wss",
			UseTLS: true,
		}
	}
	
	// 自动检测协议（如果mode为空或为"ws"）
	if mode == "" || mode == TransportWebSocket {
		// 根据协议前缀自动选择
		switch parsed.Scheme {
		case "grpc", "grpcs":
			mode = TransportGRPC
		case "http", "https":
			mode = TransportXHTTP
		default:
			mode = TransportWebSocket
		}
	}
	
	transportMode = mode

	switch mode {
	case TransportGRPC:
		currentTransport = NewGRPCTransport(serverAddr, serverIP, token, parsed.UseTLS, useECH, enableFlow, parsed.Path)
		log.Printf("[传输层] gRPC: %s:%s%s (TLS: %v, ECH: %v, Flow: %v)", 
			parsed.Host, parsed.Port, parsed.Path, parsed.UseTLS, useECH, enableFlow)

	case TransportXHTTP:
		currentTransport = NewXHTTPTransport(serverAddr, serverIP, token, useECH, enableFlow, parsed.Path)
		log.Printf("[传输层] XHTTP: %s:%s%s (ECH: %v, Vision: %v)", 
			parsed.Host, parsed.Port, parsed.Path, useECH, enableFlow)

	default:
		currentTransport = NewWebSocketTransport(serverAddr, serverIP, token, useECH, enableFlow, parsed.Path)
		log.Printf("[传输层] WebSocket: %s:%s%s (TLS: %v, ECH: %v, Vision: %v)", 
			parsed.Host, parsed.Port, parsed.Path, parsed.UseTLS, useECH, enableFlow)
	}
}

// GetTransport 获取当前传输层
func GetTransport() Transport {
	return currentTransport
}

// DialTunnel 建立隧道连接（使用当前传输层）
func DialTunnel() (TunnelConn, error) {
	if currentTransport == nil {
		return nil, errors.New("transport not initialized")
	}
	return currentTransport.Dial()
}
