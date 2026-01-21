package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	pb "ech-client/proto"
	"ech-client/ewp"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// ======================== Buffer Pool (性能优化) ========================

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
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
	// Read 从隧道读取数据
	Read() ([]byte, error)
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
	serverAddr string
	serverIP   string
	token      string
	uuid       [16]byte
	useTLS     bool
	useECH     bool
	useYamux   bool
	// Yamux session 管理
	sessionMu  sync.Mutex
	session    *yamux.Session
	wsConn     *websocket.Conn
	stopShrink chan struct{}
}

func NewWebSocketTransport(serverAddr, serverIP, token string, useECH, useYamux bool) *WebSocketTransport {
	uuid, err := parseUUID(token)
	if err != nil {
		log.Printf("[警告] 无法解析 UUID，将使用 token 原值: %v", err)
	}

	t := &WebSocketTransport{
		serverAddr: serverAddr,
		serverIP:   serverIP,
		token:      token,
		uuid:       uuid,
		useTLS:     true,
		useECH:     useECH,
		useYamux:   useYamux,
		stopShrink: make(chan struct{}),
	}

	if useYamux {
		t.startShrinkWorker()
	}

	return t
}

func (t *WebSocketTransport) Name() string {
	var name string
	if t.useYamux {
		name = "WebSocket+Yamux"
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
	// 简单协议模式：每次都新建 WebSocket 连接
	if !t.useYamux {
		return t.dialSimple()
	}

	// Yamux 模式：复用 session
	t.sessionMu.Lock()
	defer t.sessionMu.Unlock()

	// 如果已有有效 session，直接打开新 stream
	if t.session != nil && !t.session.IsClosed() {
		stream, err := t.session.Open()
		if err == nil {
			return &YamuxStreamConn{stream: stream, uuid: t.uuid}, nil
		}
		// session 失效（可能底层 WebSocket 已断开），关闭并重建
		log.Printf("[Yamux] session.Open 失败，重建连接: %v", err)
		t.session.Close()
		if t.wsConn != nil {
			t.wsConn.Close()
		}
		t.session = nil
		t.wsConn = nil
	}

	// 建立新的 WebSocket 连接
	host, port, path, err := parseServerAddr(t.serverAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

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

	wsConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return nil, err
	}

	// 创建 WebSocket 到 net.Conn 的适配器
	wsNetConn := &wsConnAdapter{conn: wsConn}

	// 创建 Yamux client session（性能优化配置）
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.MaxStreamWindowSize = 4 * 1024 * 1024
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 5 * time.Second

	session, err := yamux.Client(wsNetConn, cfg)
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("yamux session error: %w", err)
	}

	t.session = session
	t.wsConn = wsConn

	// 打开第一个 stream
	stream, err := session.Open()
	if err != nil {
		session.Close()
		wsConn.Close()
		t.session = nil
		t.wsConn = nil
		return nil, fmt.Errorf("yamux stream error: %w", err)
	}

	logV("[Yamux] 新建 session 并打开 stream")
	return &YamuxStreamConn{stream: stream, uuid: t.uuid}, nil
}

func (t *WebSocketTransport) startShrinkWorker() {
	// Note: yamux.Stream.Shrink() 存在，但 Session 无公开 API 获取所有流
	// 暂不实现定期回收，由 GC 自动处理
}

func (t *WebSocketTransport) Close() error {
	close(t.stopShrink)

	t.sessionMu.Lock()
	defer t.sessionMu.Unlock()

	if t.session != nil {
		t.session.Close()
		t.session = nil
	}

	if t.wsConn != nil {
		t.wsConn.Close()
		t.wsConn = nil
	}

	return nil
}

// dialSimple 简单 WebSocket 协议（兼容 Cloudflare Workers）
func (t *WebSocketTransport) dialSimple() (TunnelConn, error) {
	host, port, path, err := parseServerAddr(t.serverAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

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

	wsConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return nil, err
	}

	logV("[WebSocket] 新建简单协议连接")
	return &SimpleWSConn{conn: wsConn, uuid: t.uuid}, nil
}

// SimpleWSConn 简单 WebSocket 连接实现（使用 EWP 协议）
type SimpleWSConn struct {
	conn      *websocket.Conn
	uuid      [16]byte
	connected bool
	mu        sync.Mutex
	version   byte
	nonce     [12]byte
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

	if len(initialData) > 0 {
		if err := c.conn.WriteMessage(websocket.BinaryMessage, initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	c.connected = true
	logV("[EWP] 握手成功，目标: %s", target)
	return nil
}

func (c *SimpleWSConn) Read() ([]byte, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	// 检查是否是控制消息
	if len(msg) > 0 {
		str := string(msg)
		if str == "CLOSE" {
			return nil, io.EOF
		}
		if strings.HasPrefix(str, "ERROR:") {
			return nil, errors.New(str)
		}
	}

	return msg, nil
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

// wsConnAdapter 将 WebSocket 连接适配为 net.Conn 接口（供 Yamux 使用）
type wsConnAdapter struct {
	conn   *websocket.Conn
	reader io.Reader
	mu     sync.Mutex
}

func (c *wsConnAdapter) Read(p []byte) (int, error) {
	for {
		if c.reader == nil {
			_, r, err := c.conn.NextReader()
			if err != nil {
				return 0, err
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			continue
		}
		return n, err
	}
}

func (c *wsConnAdapter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConnAdapter) Close() error {
	return c.conn.Close()
}

func (c *wsConnAdapter) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wsConnAdapter) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *wsConnAdapter) SetDeadline(t time.Time) error {
	return nil
}

func (c *wsConnAdapter) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *wsConnAdapter) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// YamuxStreamConn Yamux stream 连接实现
type YamuxStreamConn struct {
	stream net.Conn
	uuid   [16]byte
}

func (c *YamuxStreamConn) Connect(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	if _, err := c.stream.Write(handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	respData, err := ewp.ReadHandshake(c.stream)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respData, req.Version, req.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	if len(initialData) > 0 {
		if _, err := c.stream.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	logV("[EWP] Yamux 握手成功，目标: %s", target)
	return nil
}

func (c *YamuxStreamConn) Read() ([]byte, error) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	n, err := c.stream.Read(buf)
	if err != nil {
		return nil, err
	}

	data := make([]byte, n)
	copy(data, buf[:n])
	return data, nil
}

func (c *YamuxStreamConn) Write(data []byte) error {
	_, err := c.stream.Write(data)
	return err
}

func (c *YamuxStreamConn) Close() error {
	return c.stream.Close()
}

func (c *YamuxStreamConn) StartPing(interval time.Duration) chan struct{} {
	// Yamux 有内置的 keepalive，不需要应用层心跳
	return make(chan struct{})
}

// ======================== gRPC Transport ========================

type GRPCTransport struct {
	serverAddr string
	serverIP   string
	uuidStr    string
	uuid       [16]byte
	useTLS     bool
	useECH     bool
}

func NewGRPCTransport(serverAddr, serverIP, uuidStr string, useTLS, useECH bool) *GRPCTransport {
	uuid, err := parseUUID(uuidStr)
	if err != nil {
		log.Printf("[警告] 无法解析 UUID: %v", err)
	}

	return &GRPCTransport{
		serverAddr: serverAddr,
		serverIP:   serverIP,
		uuidStr:    uuidStr,
		uuid:       uuid,
		useTLS:     useTLS,
		useECH:     useECH,
	}
}

func (t *GRPCTransport) Name() string {
	if t.useECH {
		return "gRPC+ECH"
	}
	if t.useTLS {
		return "gRPC+TLS"
	}
	return "gRPC"
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
			// 使用 ECH + TLS 1.3
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
			// 普通 TLS
			tlsCfg = &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS13,
			}
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
		conn:   conn,
		stream: stream,
		uuid:   t.uuid,
	}, nil
}

// GRPCConn gRPC 连接实现
type GRPCConn struct {
	conn   *grpc.ClientConn
	stream pb.ProxyService_TunnelClient
	uuid   [16]byte
	mu     sync.Mutex
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

	if len(initialData) > 0 {
		c.mu.Lock()
		err = c.stream.Send(&pb.SocketData{Content: initialData})
		c.mu.Unlock()
		if err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	logV("[EWP] gRPC 握手成功，目标: %s", target)
	return nil
}

func (c *GRPCConn) Read() ([]byte, error) {
	resp, err := c.stream.Recv()
	if err != nil {
		return nil, err
	}
	return resp.Content, nil
}

func (c *GRPCConn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stream.Send(&pb.SocketData{Content: data})
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

// ======================== Transport 工厂函数 ========================

// 传输模式常量
const (
	TransportWebSocket = "ws"
	TransportGRPC      = "grpc"
)

var (
	currentTransport Transport
	transportMode    string
)

// InitTransport 初始化传输层
func InitTransport(mode, serverAddr, serverIP, token string, useECH, useYamux bool) {
	transportMode = mode

	switch mode {
	case TransportGRPC:
		// gRPC 模式：token 作为 UUID，支持 ECH
		useTLS := !strings.HasPrefix(serverAddr, "grpc://")
		addr := strings.TrimPrefix(strings.TrimPrefix(serverAddr, "grpcs://"), "grpc://")
		currentTransport = NewGRPCTransport(addr, serverIP, token, useTLS, useECH)
		log.Printf("[传输层] 使用 gRPC 模式: %s (ECH: %v)", addr, useECH)

	default:
		// 默认 WebSocket 模式
		currentTransport = NewWebSocketTransport(serverAddr, serverIP, token, useECH, useYamux)
		log.Printf("[传输层] 使用 WebSocket 模式: %s (ECH: %v, Yamux: %v)", serverAddr, useECH, useYamux)
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
