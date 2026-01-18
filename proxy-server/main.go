package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "proxy-server/proto"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	uuid     = getEnv("UUID", "d342d11e-d424-4583-b36e-524ab1f0afa4")
	port     = getEnv("PORT", "8080")
	grpcMode = false
	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
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

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Nginx disguise page
const nginxHTML = `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>`

func main() {
	// 解析命令行参数
	flag.BoolVar(&grpcMode, "grpc", false, "启用 gRPC 模式（默认 WebSocket 模式）")
	flag.StringVar(&port, "port", port, "监听端口")
	flag.Parse()

	// 也支持环境变量 MODE=grpc
	if os.Getenv("MODE") == "grpc" {
		grpcMode = true
	}

	log.Printf("🔑 UUID: %s", uuid)

	if grpcMode {
		// gRPC 模式
		log.Printf("🚀 gRPC server listening on :%s", port)
		startGRPCServer()
	} else {
		// WebSocket 模式（默认）
		mux := http.NewServeMux()
		mux.HandleFunc("/health", healthHandler)
		mux.HandleFunc("/healthz", healthHandler)
		mux.HandleFunc("/", handler)

		server := &http.Server{
			Addr:    ":" + port,
			Handler: mux,
		}

		log.Printf("🚀 WebSocket server listening on :%s", port)
		log.Fatal(server.ListenAndServe())
	}
}

// ======================== gRPC 服务 ========================

type proxyServer struct {
	pb.UnimplementedProxyServiceServer
}

func (s *proxyServer) Tunnel(stream pb.ProxyService_TunnelServer) error {
	// 从 metadata 获取 UUID 进行鉴权
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		log.Printf("❌ gRPC: 无法获取 metadata")
		return status.Error(codes.InvalidArgument, "missing metadata")
	}

	uuids := md.Get("uuid")
	if len(uuids) == 0 || uuids[0] != uuid {
		log.Printf("❌ gRPC: UUID 验证失败")
		return status.Error(codes.Unauthenticated, "invalid UUID")
	}

	log.Println("✅ gRPC client connected")

	// 读取第一个消息获取目标地址
	firstMsg, err := stream.Recv()
	if err != nil {
		log.Printf("❌ gRPC: 读取首包失败: %v", err)
		return err
	}

	data := firstMsg.GetContent()
	target, extraData := parseGRPCConnect(data)
	if target == "" {
		log.Printf("❌ gRPC: 无效的目标地址")
		stream.Send(&pb.SocketData{Content: []byte("ERROR:invalid target")})
		return nil
	}

	log.Printf("🔗 gRPC connecting to %s", target)

	// 连接目标
	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ gRPC dial error: %v", err)
		stream.Send(&pb.SocketData{Content: []byte("ERROR:" + err.Error())})
		return nil
	}
	defer remote.Close()

	log.Printf("✅ gRPC connected to %s", target)

	// 发送连接成功响应
	if err := stream.Send(&pb.SocketData{Content: []byte("CONNECTED")}); err != nil {
		return err
	}

	// 发送额外数据
	if len(extraData) > 0 {
		remote.Write(extraData)
	}

	// 双向转发
	done := make(chan struct{}, 2)

	// gRPC -> remote
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			if _, err := remote.Write(msg.GetContent()); err != nil {
				return
			}
		}
	}()

	// remote -> gRPC
	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			if err := stream.Send(&pb.SocketData{Content: buf[:n:n]}); err != nil {
				return
			}
		}
	}()

	<-done
	return nil
}

func parseGRPCConnect(data []byte) (target string, extraData []byte) {
	// 格式: "CONNECT:host:port|extra_data"
	str := string(data)
	if !strings.HasPrefix(str, "CONNECT:") {
		return "", nil
	}

	str = strings.TrimPrefix(str, "CONNECT:")
	idx := strings.Index(str, "|")
	if idx < 0 {
		return str, nil
	}

	target = str[:idx]
	extraData = data[len("CONNECT:")+idx+1:]
	return target, extraData
}

func startGRPCServer() {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("❌ gRPC listen failed: %v", err)
	}

	kasp := keepalive.ServerParameters{
		Time:    60 * time.Second,
		Timeout: 10 * time.Second,
	}
	kaep := keepalive.EnforcementPolicy{
		MinTime:             10 * time.Second,
		PermitWithoutStream: true,
	}

	s := grpc.NewServer(
		grpc.KeepaliveParams(kasp),
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.MaxConcurrentStreams(100),
		grpc.InitialWindowSize(1<<20),
		grpc.InitialConnWindowSize(1<<20),
		grpc.WriteBufferSize(32*1024),
		grpc.ReadBufferSize(32*1024),
	)
	pb.RegisterProxyServiceServer(s, &proxyServer{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("🛑 Gracefully stopping gRPC server...")
		s.GracefulStop()
	}()

	if err := s.Serve(lis); err != nil {
		log.Fatalf("❌ gRPC serve failed: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("📥 Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Check auth via header or path
	proto := r.Header.Get("Sec-WebSocket-Protocol")
	authorized := proto == uuid || strings.Contains(r.URL.Path, uuid)

	if !authorized || !websocket.IsWebSocketUpgrade(r) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(nginxHTML))
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, http.Header{"Sec-WebSocket-Protocol": {proto}})
	if err != nil {
		log.Printf("❌ Upgrade error: %v", err)
		return
	}
	defer conn.Close()

	log.Println("✅ Client connected")
	handleWebSocket(conn)
}

// WebSocket adapter for yamux
type wsConn struct {
	*websocket.Conn
	reader io.Reader
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if c.reader == nil {
			_, r, err := c.NextReader()
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

func (c *wsConn) Write(p []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

// handleWebSocket 自动检测客户端协议：Yamux 或简单文本协议
func handleWebSocket(conn *websocket.Conn) {
	// 读取第一帧数据来判断协议类型
	_, firstMsg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("❌ Read first message error: %v", err)
		return
	}

	// Yamux 协议的 magic number: 0x00 0x00 (version + type)
	// 简单协议以 "CONNECT:" 开头
	if len(firstMsg) >= 2 && firstMsg[0] == 0x00 {
		// Yamux 协议
		log.Println("🔄 Detected Yamux protocol")
		handleYamuxWithFirstFrame(conn, firstMsg)
	} else if strings.HasPrefix(string(firstMsg), "CONNECT:") {
		// 简单文本协议
		log.Println("🔄 Detected simple protocol")
		handleSimpleProtocol(conn, firstMsg)
	} else {
		log.Printf("❌ Unknown protocol, first bytes: %v", firstMsg[:min(len(firstMsg), 16)])
		return
	}
}

// handleSimpleProtocol 处理简单文本协议（兼容 Cloudflare Workers）
func handleSimpleProtocol(conn *websocket.Conn, firstMsg []byte) {
	// 解析 CONNECT:host:port|data
	msg := string(firstMsg)
	if !strings.HasPrefix(msg, "CONNECT:") {
		conn.WriteMessage(websocket.TextMessage, []byte("ERROR:invalid message"))
		return
	}

	msg = strings.TrimPrefix(msg, "CONNECT:")
	idx := strings.Index(msg, "|")
	var target string
	var extraData []byte
	if idx >= 0 {
		target = msg[:idx]
		extraData = []byte(msg[idx+1:])
	} else {
		target = msg
	}

	log.Printf("🔗 Simple: connecting to %s", target)

	// 连接目标
	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ Dial error: %v", err)
		conn.WriteMessage(websocket.TextMessage, []byte("ERROR:"+err.Error()))
		return
	}
	defer remote.Close()

	// 发送连接成功响应
	if err := conn.WriteMessage(websocket.TextMessage, []byte("CONNECTED")); err != nil {
		return
	}

	log.Printf("✅ Simple: connected to %s", target)

	// 发送额外数据
	if len(extraData) > 0 {
		remote.Write(extraData)
	}

	// 双向转发
	done := make(chan struct{}, 2)

	// WebSocket -> remote
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			// 检查控制消息
			if str := string(msg); str == "CLOSE" {
				return
			}
			if _, err := remote.Write(msg); err != nil {
				return
			}
		}
	}()

	// remote -> WebSocket
	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				return
			}
		}
	}()

	<-done
	// 发送关闭消息
	conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
}

// handleYamuxWithFirstFrame 处理 Yamux 协议（带已读取的第一帧）
func handleYamuxWithFirstFrame(conn *websocket.Conn, firstFrame []byte) {
	ws := &wsConnWithBuffer{
		Conn:        conn,
		firstFrame:  firstFrame,
		firstFrameRead: false,
	}

	// Create yamux server session（性能优化配置）
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.MaxStreamWindowSize = 4 * 1024 * 1024
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 5 * time.Second

	session, err := yamux.Server(ws, cfg)
	if err != nil {
		log.Printf("❌ Yamux session error: %v", err)
		return
	}
	defer session.Close()

	// Accept streams
	for {
		stream, err := session.Accept()
		if err != nil {
			if err != io.EOF {
				log.Printf("📴 Session closed: %v", err)
			}
			return
		}
		go handleStream(stream)
	}
}

// wsConnWithBuffer 带缓冲的 WebSocket 适配器（用于回放第一帧）
type wsConnWithBuffer struct {
	*websocket.Conn
	firstFrame     []byte
	firstFrameRead bool
	reader         io.Reader
}

func (c *wsConnWithBuffer) Read(p []byte) (int, error) {
	// 先返回已读取的第一帧
	if !c.firstFrameRead && len(c.firstFrame) > 0 {
		c.firstFrameRead = true
		c.reader = bytes.NewReader(c.firstFrame)
	}

	for {
		if c.reader == nil {
			_, r, err := c.NextReader()
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

func (c *wsConnWithBuffer) Write(p []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

func handleYamux(conn *websocket.Conn) {
	ws := &wsConn{Conn: conn}

	// Create yamux server session（性能优化配置）
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.MaxStreamWindowSize = 4 * 1024 * 1024
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 5 * time.Second

	session, err := yamux.Server(ws, cfg)
	if err != nil {
		log.Printf("❌ Yamux session error: %v", err)
		return
	}
	defer session.Close()

	// Accept streams
	for {
		stream, err := session.Accept()
		if err != nil {
			if err != io.EOF {
				log.Printf("📴 Session closed: %v", err)
			}
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream net.Conn) {
	defer stream.Close()

	// First read: target address "host:port\n" (newline delimited)
	buf := smallBufferPool.Get().([]byte)
	n, err := stream.Read(buf)
	if err != nil {
		smallBufferPool.Put(buf)
		return
	}

	data := buf[:n]
	
	// Find newline delimiter
	newlineIdx := -1
	for i, b := range data {
		if b == '\n' {
			newlineIdx = i
			break
		}
	}

	var target string
	var extraData []byte
	
	if newlineIdx >= 0 {
		target = string(data[:newlineIdx])
		if newlineIdx+1 < len(data) {
			extraData = make([]byte, len(data[newlineIdx+1:]))
			copy(extraData, data[newlineIdx+1:])
		}
	} else {
		// Fallback: no newline, treat entire data as target
		target = strings.TrimSpace(string(data))
	}

	smallBufferPool.Put(buf)

	parts := strings.SplitN(target, ":", 2)
	if len(parts) != 2 {
		log.Printf("❌ Invalid target: %s", target)
		return
	}

	host, port := parts[0], parts[1]
	log.Printf("🔗 Connecting to %s:%s", host, port)

	// Connect to target
	remote, err := net.Dial("tcp", host+":"+port)
	if err != nil {
		log.Printf("❌ Dial error: %v", err)
		return
	}
	defer remote.Close()

	log.Printf("✅ Connected to %s:%s", host, port)

	// Send extra data that came with target address (e.g., HTTP request)
	if len(extraData) > 0 {
		remote.Write(extraData)
	}

	// Bidirectional copy
	done := make(chan struct{})
	go func() {
		io.Copy(remote, stream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(stream, remote)
		done <- struct{}{}
	}()
	<-done
}
