package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	pb "ech-client/proto"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// ======================== Buffer Pool (性能优化) ========================

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
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
	t := &WebSocketTransport{
		serverAddr: serverAddr,
		serverIP:   serverIP,
		token:      token,
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
			return &YamuxStreamConn{stream: stream}, nil
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
	return &YamuxStreamConn{stream: stream}, nil
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
	return &SimpleWSConn{conn: wsConn}, nil
}

// SimpleWSConn 简单 WebSocket 连接实现（兼容 Cloudflare Workers 协议）
type SimpleWSConn struct {
	conn      *websocket.Conn
	connected bool
	mu        sync.Mutex
}

func (c *SimpleWSConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 发送 CONNECT 消息：CONNECT:host:port|initialData
	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, string(initialData))
	if err := c.conn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil {
		return err
	}

	// 等待 CONNECTED 响应
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return err
	}

	response := string(msg)
	if strings.HasPrefix(response, "ERROR:") {
		return errors.New(response)
	}
	if response != "CONNECTED" {
		return fmt.Errorf("unexpected response: %s", response)
	}

	c.connected = true
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
}

func (c *YamuxStreamConn) Connect(target string, initialData []byte) error {
	// Yamux 协议：发送 "host:port\n" + 可选的初始数据
	connectMsg := target + "\n"
	if _, err := c.stream.Write([]byte(connectMsg)); err != nil {
		return err
	}
	// 如果有初始数据，一并发送
	if len(initialData) > 0 {
		if _, err := c.stream.Write(initialData); err != nil {
			return err
		}
	}
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
	uuid       string
	useTLS     bool
	useECH     bool
}

func NewGRPCTransport(serverAddr, serverIP, uuid string, useTLS, useECH bool) *GRPCTransport {
	return &GRPCTransport{
		serverAddr: serverAddr,
		serverIP:   serverIP,
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

	// 创建带 metadata 的 context（用于鉴权）
	md := metadata.New(map[string]string{"uuid": t.uuid})
	streamCtx := metadata.NewOutgoingContext(context.Background(), md)

	stream, err := client.Tunnel(streamCtx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("gRPC stream failed: %w", err)
	}

	return &GRPCConn{
		conn:   conn,
		stream: stream,
	}, nil
}

// GRPCConn gRPC 连接实现
type GRPCConn struct {
	conn   *grpc.ClientConn
	stream pb.ProxyService_TunnelClient
	mu     sync.Mutex
}

func (c *GRPCConn) Connect(target string, initialData []byte) error {
	// 构建 CONNECT 消息（与 WebSocket 协议兼容）
	connectMsg := fmt.Sprintf("CONNECT:%s|", target)
	data := append([]byte(connectMsg), initialData...)

	c.mu.Lock()
	err := c.stream.Send(&pb.SocketData{Content: data})
	c.mu.Unlock()
	if err != nil {
		return err
	}

	// 等待响应
	resp, err := c.stream.Recv()
	if err != nil {
		return err
	}

	response := string(resp.Content)
	if strings.HasPrefix(response, "ERROR:") {
		return errors.New(response)
	}
	if response != "CONNECTED" {
		return fmt.Errorf("unexpected response: %s", response)
	}

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
