package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"ewp-core/internal/server"
	pb "ewp-core/proto"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
)

var (
	uuid          = getEnv("UUID", "d342d11e-d424-4583-b36e-524ab1f0afa4")
	password      = getEnv("PASSWORD", "")  // Trojan 密码，多个用逗号分隔
	port          = getEnv("PORT", "8080")
	wsPath        = getEnv("WS_PATH", "/")
	xhttpPath     = getEnv("XHTTP_PATH", "/xhttp")
	grpcService   = getEnv("GRPC_SERVICE", "ProxyService")  // gRPC 服务名（可自定义，客户端需配置相同名称）
	paddingMin    = getEnvInt("PADDING_MIN", 100)
	paddingMax    = getEnvInt("PADDING_MAX", 1000)
	fallbackAddr  = getEnv("FALLBACK", "")  // Trojan 回退地址，如 127.0.0.1:80 或 https://example.com
	grpcMode      = false
	xhttpMode     = false
	enableFlow    = false
	trojanMode    = false  // Trojan 协议模式
	upgrader      = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
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

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

// Nginx disguise page
const nginxHTML = `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>`

func maskPassword(p string) string {
	if len(p) <= 4 {
		return "****"
	}
	return p[:2] + "****" + p[len(p)-2:]
}


func main() {
	// 解析命令行参数
	flag.BoolVar(&grpcMode, "grpc", false, "启用 gRPC 模式")
	flag.BoolVar(&xhttpMode, "xhttp", false, "启用 XHTTP 模式")
	flag.BoolVar(&enableFlow, "flow", false, "启用 EWP Flow 流控协议（Vision 风格）")
	flag.BoolVar(&trojanMode, "trojan", false, "启用 Trojan 协议模式")
	flag.StringVar(&port, "port", port, "监听端口")
	flag.StringVar(&password, "password", password, "Trojan 密码")
	flag.StringVar(&fallbackAddr, "fallback", fallbackAddr, "Trojan 回退地址（如 127.0.0.1:80）")
	flag.Parse()

	// 也支持环境变量 MODE=grpc/xhttp, ENABLE_FLOW=true/false, PROTOCOL=trojan
	mode := os.Getenv("MODE")
	if mode == "grpc" {
		grpcMode = true
	} else if mode == "xhttp" {
		xhttpMode = true
	}
	if os.Getenv("ENABLE_FLOW") == "true" {
		enableFlow = true
	}
	if os.Getenv("PROTOCOL") == "trojan" {
		trojanMode = true
	}
	if envPwd := os.Getenv("PASSWORD"); envPwd != "" {
		password = envPwd
	}

	// 初始化协议处理器
	if trojanMode {
		if password == "" {
			password = uuid  // 如果没有设置密码，使用 UUID 作为密码
		}
		log.Printf("🔐 Protocol: Trojan")
		log.Printf("🔑 Password: %s", maskPassword(password))
		if err := server.InitTrojanHandler(password); err != nil {
			log.Fatalf("❌ Failed to initialize Trojan handler: %v", err)
		}
		// 设置 Fallback 处理器
		if fallbackAddr != "" {
			log.Printf("🔄 Fallback: %s", fallbackAddr)
			server.SetTrojanFallback(&TrojanFallbackHandler{addr: fallbackAddr})
		}
	} else {
		log.Printf("🔐 Protocol: EWP")
		log.Printf("🔑 UUID: %s", uuid)
		if enableFlow {
			log.Printf("🌊 EWP Flow 协议已启用（Vision 风格流控）")
		}
		if err := server.InitEWPHandler(uuid); err != nil {
			log.Fatalf("❌ Failed to initialize EWP handler: %v", err)
		}
	}

	if grpcMode {
		// gRPC 模式
		log.Printf("🚀 gRPC server listening on :%s", port)
		startGRPCServer()
	} else if xhttpMode {
		// XHTTP 模式
		log.Printf("🚀 XHTTP server listening on :%s", port)
		startXHTTPServer()
	} else {
		// WebSocket 模式（默认）
		mux := http.NewServeMux()
		mux.HandleFunc("/health", healthHandler)
		mux.HandleFunc("/healthz", healthHandler)
		mux.HandleFunc(wsPath, wsHandler)
		mux.HandleFunc("/", disguiseHandler)

		server := &http.Server{
			Addr:    ":" + port,
			Handler: mux,
		}

		log.Printf("🚀 WebSocket server listening on :%s (ws_path=%s)", port, wsPath)
		log.Fatal(server.ListenAndServe())
	}
}

// ======================== gRPC 服务 ========================

type proxyServer struct {
	pb.UnimplementedProxyServiceServer
}

// tunnelHandler 是自定义服务名注册时使用的处理函数
func tunnelHandler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(*proxyServer).Tunnel(&grpcServerStream{stream})
}

// grpcServerStream 包装 grpc.ServerStream 以实现 pb.ProxyService_TunnelServer 接口
type grpcServerStream struct {
	grpc.ServerStream
}

func (s *grpcServerStream) Send(m *pb.SocketData) error {
	return s.ServerStream.SendMsg(m)
}

func (s *grpcServerStream) Recv() (*pb.SocketData, error) {
	m := new(pb.SocketData)
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *proxyServer) Tunnel(stream pb.ProxyService_TunnelServer) error {
	// 提取客户端 IP
	clientIP := "unknown"
	if p, ok := peer.FromContext(stream.Context()); ok {
		clientIP = p.Addr.String()
	}
	
	log.Printf("🔗 gRPC client connected from %s", clientIP)

	firstMsg, err := stream.Recv()
	if err != nil {
		log.Printf("❌ gRPC: 读取握手失败: %v", err)
		return err
	}

	content := firstMsg.GetContent()

	var target string
	var initialData []byte
	var flowState *ewp.FlowState
	var writeOnceUserUUID []byte

	if trojanMode {
		// Trojan 协议处理
		validKeys := server.GetTrojanValidKeys()
		if validKeys == nil {
			log.Printf("❌ gRPC Trojan: No valid keys configured")
			return nil
		}

		reader := &byteReader{data: content, pos: 0}
		pwd, command, addr, err := trojan.ReadHandshake(reader, validKeys)
		if err != nil {
			log.Printf("❌ gRPC Trojan handshake failed: %v", err)
			return nil
		}

		target = addr.String()
		log.Printf("✅ gRPC Trojan handshake (user: %s), target: %s", maskPassword(pwd), target)

		if command == trojan.CommandUDP {
			log.Printf("⚠️ gRPC Trojan UDP not supported")
			return nil
		}

		// 保存握手后的剩余数据
		if reader.pos < len(reader.data) {
			initialData = reader.data[reader.pos:]
		}
	} else {
		// EWP 协议处理
		req, respData, err := server.HandleEWPHandshakeBinary(content, clientIP)
		if err != nil {
			stream.Send(&pb.SocketData{Content: respData})
			return nil
		}

		if err := stream.Send(&pb.SocketData{Content: respData}); err != nil {
			log.Printf("❌ gRPC: 发送握手响应失败: %v", err)
			return err
		}

		target = req.TargetAddr.String()

		// 初始化 Flow State（如果启用）
		if enableFlow {
			flowState = ewp.NewFlowState(req.UUID[:])
			writeOnceUserUUID = make([]byte, 16)
			copy(writeOnceUserUUID, req.UUID[:])
			log.Printf("🌊 gRPC Flow 协议已启用")
		}
	}

	log.Printf("🔗 gRPC connecting to %s", target)

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ gRPC dial error: %v", err)
		return nil
	}
	defer remote.Close()

	log.Printf("✅ gRPC connected to %s", target)

	// 发送初始数据（Trojan 模式）
	if len(initialData) > 0 {
		if _, err := remote.Write(initialData); err != nil {
			log.Printf("❌ gRPC write initial data error: %v", err)
			return nil
		}
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

			data := msg.GetContent()

			// 处理 Flow 协议（移除填充）
			if enableFlow && flowState != nil {
				data = flowState.ProcessUplink(data)
			}

			if _, err := remote.Write(data); err != nil {
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

			data := buf[:n]

			// 应用 Flow 协议（添加填充）
			if enableFlow && flowState != nil {
				data = flowState.PadDownlink(data, &writeOnceUserUUID)
			}

			// 复制数据发送
			sendData := make([]byte, len(data))
			copy(sendData, data)
			if err := stream.Send(&pb.SocketData{Content: sendData}); err != nil {
				return
			}
		}
	}()

	<-done
	return nil
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

	// 无 TLS 模式（通过 Cloudflare Tunnel 提供 TLS）
	s := grpc.NewServer(
		grpc.KeepaliveParams(kasp),
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.MaxConcurrentStreams(100),
		grpc.InitialWindowSize(1<<20),
		grpc.InitialConnWindowSize(1<<20),
		grpc.WriteBufferSize(32*1024),
		grpc.ReadBufferSize(32*1024),
	)
	
	// 使用自定义服务名注册 gRPC 服务
	customServiceDesc := grpc.ServiceDesc{
		ServiceName: grpcService,
		HandlerType: (*pb.ProxyServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Tunnel",
				Handler:       tunnelHandler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "tunnel.proto",
	}
	s.RegisterService(&customServiceDesc, &proxyServer{})
	log.Printf("📡 gRPC 服务名: /%s/Tunnel", grpcService)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("🛑 Gracefully stopping gRPC server...")
		s.GracefulStop()
	}()

	log.Println("🚀 gRPC server listening (no TLS, behind Cloudflare Tunnel)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("❌ gRPC serve failed: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != wsPath {
		disguiseHandler(w, r)
		return
	}

	proto := r.Header.Get("Sec-WebSocket-Protocol")
	// Trojan 模式使用密码验证，EWP 模式使用 UUID 验证
	if trojanMode {
		if proto != password {
			disguiseHandler(w, r)
			return
		}
	} else {
		if proto != uuid {
			disguiseHandler(w, r)
			return
		}
	}

	if !websocket.IsWebSocketUpgrade(r) {
		disguiseHandler(w, r)
		return
	}

	conn, err := upgrader.Upgrade(w, r, http.Header{"Sec-WebSocket-Protocol": {proto}})
	if err != nil {
		log.Printf("❌ Upgrade error: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("✅ WebSocket connected: %s %s", r.Method, r.URL.Path)
	handleWebSocket(conn, r.RemoteAddr)
}

// handleWebSocket 处理协议（支持 EWP 和 Trojan）
func handleWebSocket(conn *websocket.Conn, clientAddr string) {
	// 读取第一帧数据
	_, firstMsg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("❌ Read first message error: %v", err)
		return
	}

	if trojanMode {
		if len(firstMsg) < trojan.KeyLength+2+1+1+2+2 {
			log.Printf("❌ Trojan message too short: %d bytes", len(firstMsg))
			return
		}
		handleTrojanProtocol(conn, firstMsg, clientAddr)
	} else {
		if len(firstMsg) < 15 {
			log.Printf("❌ EWP message too short: %d bytes", len(firstMsg))
			return
		}
		handleSimpleProtocol(conn, firstMsg, clientAddr)
	}
}

// handleSimpleProtocol 处理 EWP 协议（简单 WebSocket 模式）
func handleSimpleProtocol(conn *websocket.Conn, firstMsg []byte, clientAddr string) {
	req, respData, err := server.HandleEWPHandshakeBinary(firstMsg, clientAddr)
	if err != nil {
		conn.WriteMessage(websocket.BinaryMessage, respData)
		return
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, respData); err != nil {
		log.Printf("❌ Failed to send handshake response: %v", err)
		return
	}

	target := req.TargetAddr.String()
	log.Printf("🔗 Simple WebSocket connecting to %s", target)

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ Dial error: %v", err)
		return
	}
	defer remote.Close()

	log.Printf("✅ Simple WebSocket connected to %s", target)

	// 初始化 Flow State（如果启用）
	var flowState *ewp.FlowState
	var writeOnceUserUUID []byte
	if enableFlow {
		flowState = ewp.NewFlowState(req.UUID[:])
		writeOnceUserUUID = make([]byte, 16)
		copy(writeOnceUserUUID, req.UUID[:])
		log.Printf("🌊 Flow 协议已启用")
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

			// 处理 Flow 协议（移除填充）
			if enableFlow && flowState != nil {
				msg = flowState.ProcessUplink(msg)
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

			data := buf[:n]

			// 应用 Flow 协议（添加填充）
			if enableFlow && flowState != nil {
				data = flowState.PadDownlink(data, &writeOnceUserUUID)
			}

			// 复制数据发送
			sendData := make([]byte, len(data))
			copy(sendData, data)
			if err := conn.WriteMessage(websocket.BinaryMessage, sendData); err != nil {
				return
			}
		}
	}()

	<-done
	// 发送关闭消息
	conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
}

// handleTrojanProtocol 处理 Trojan 协议（WebSocket 模式）
func handleTrojanProtocol(conn *websocket.Conn, firstMsg []byte, clientAddr string) {
	validKeys := server.GetTrojanValidKeys()
	if validKeys == nil {
		log.Printf("❌ Trojan: No valid keys configured")
		return
	}

	// 解析 Trojan 握手
	reader := &byteReader{data: firstMsg, pos: 0}
	pwd, command, addr, err := trojan.ReadHandshake(reader, validKeys)
	if err != nil {
		log.Printf("❌ Trojan handshake failed from %s: %v", clientAddr, err)
		return
	}

	target := addr.String()
	log.Printf("✅ Trojan handshake from %s (user: %s), target: %s", clientAddr, maskPassword(pwd), target)

	// Trojan 协议不需要发送响应，直接建立连接
	if command == trojan.CommandUDP {
		log.Printf("📦 Trojan UDP mode from %s", clientAddr)
		handleTrojanUDP(conn, reader, clientAddr)
		return
	}

	// TCP 模式
	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ Trojan dial error: %v", err)
		return
	}
	defer remote.Close()

	log.Printf("🔗 Trojan connected to %s", target)

	// 如果握手数据后还有剩余数据，先发送
	if reader.pos < len(reader.data) {
		remaining := reader.data[reader.pos:]
		if _, err := remote.Write(remaining); err != nil {
			log.Printf("❌ Trojan write initial data error: %v", err)
			return
		}
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
			if string(msg) == "CLOSE" {
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
			sendData := make([]byte, n)
			copy(sendData, buf[:n])
			if err := conn.WriteMessage(websocket.BinaryMessage, sendData); err != nil {
				return
			}
		}
	}()

	<-done
	conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
}

// handleTrojanUDP 处理 Trojan UDP 连接
func handleTrojanUDP(conn *websocket.Conn, initialReader *byteReader, clientAddr string) {
	// TODO: 实现 Trojan UDP 支持
	log.Printf("⚠️ Trojan UDP not fully implemented yet")
}

// byteReader 用于从字节切片读取数据
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// ======================== XHTTP 服务 (基于 Xray-core 实现) ========================

type xhttpSession struct {
	remote           net.Conn
	uploadQueue      *server.UploadQueue
	done             chan struct{}
	isFullyConnected chan struct{}
	closeOnce        sync.Once
}

var (
	xhttpSessions      = sync.Map{}
	xhttpSessionMutex  sync.Mutex
	xhttpSessionExpiry = 30 * time.Second
)

func startXHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)
	
	mux.HandleFunc(xhttpPath+"/", xhttpHandler)
	mux.HandleFunc(xhttpPath, xhttpHandler)
	mux.HandleFunc("/", disguiseHandler)

	// 无 TLS 模式（通过 Cloudflare Tunnel 提供 TLS）
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// 注意：不设置 ReadTimeout 和 WriteTimeout，因为 stream-one 是长连接
	}

	go cleanupExpiredSessions()
	log.Println("� XHTTP server listening (no TLS, behind Cloudflare Tunnel)")
	log.Fatal(server.ListenAndServe())
}

func xhttpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth-Token") != uuid {
		disguiseHandler(w, r)
		return
	}

	paddingLen := 0
	if referrer := r.Header.Get("Referer"); referrer != "" {
		if refURL, err := url.Parse(referrer); err == nil {
			paddingLen = len(refURL.Query().Get("x_padding"))
		}
	} else {
		paddingLen = len(r.URL.Query().Get("x_padding"))
	}

	if paddingLen < paddingMin || paddingLen > paddingMax {
		log.Printf("❌ Invalid padding length: %d (expected %d-%d)", paddingLen, paddingMin, paddingMax)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	subpath := strings.TrimPrefix(r.URL.Path, xhttpPath)
	parts := strings.Split(strings.Trim(subpath, "/"), "/")
	
	sessionID := ""
	seqStr := ""
	if len(parts) > 0 && parts[0] != "" {
		sessionID = parts[0]
	}
	if len(parts) > 1 && parts[1] != "" {
		seqStr = parts[1]
	}

	log.Printf("📥 XHTTP %s %s (session=%s, seq=%s, padding=%d)", r.Method, r.URL.Path, sessionID, seqStr, paddingLen)

	if r.Method == "POST" && sessionID != "" {
		xhttpUploadHandler(w, r, sessionID, seqStr)
	} else if r.Method == "GET" && sessionID != "" {
		xhttpDownloadHandler(w, r, sessionID)
	} else if r.Method == "POST" && sessionID == "" {
		xhttpStreamOneHandler(w, r)
	} else if r.Method == "GET" && sessionID == "" {
		xhttpStreamOneHandler(w, r)
	} else {
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

func disguiseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.18.0")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(nginxHTML))
}

func upsertSession(sessionID string) *xhttpSession {
	if val, ok := xhttpSessions.Load(sessionID); ok {
		return val.(*xhttpSession)
	}

	xhttpSessionMutex.Lock()
	defer xhttpSessionMutex.Unlock()

	if val, ok := xhttpSessions.Load(sessionID); ok {
		return val.(*xhttpSession)
	}

	session := &xhttpSession{
		uploadQueue:      server.NewUploadQueue(100),
		done:             make(chan struct{}),
		isFullyConnected: make(chan struct{}),
	}
	xhttpSessions.Store(sessionID, session)

	go func() {
		timer := time.NewTimer(xhttpSessionExpiry)
		defer timer.Stop()
		select {
		case <-timer.C:
			if session.remote != nil {
				session.remote.Close()
			}
			close(session.done)
			xhttpSessions.Delete(sessionID)
			log.Printf("🧹 Session expired: %s", sessionID)
		case <-session.isFullyConnected:
		}
	}()

	return session
}

func cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		xhttpSessions.Range(func(key, value interface{}) bool {
			session := value.(*xhttpSession)
			select {
			case <-session.done:
				xhttpSessions.Delete(key)
			default:
			}
			return true
		})
	}
}

func xhttpStreamOneHandler(w http.ResponseWriter, r *http.Request) {
	// 获取客户端 IP
	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}

	var target string
	var respData []byte
	var flowState *ewp.FlowState
	var initialData []byte

	if trojanMode {
		// Trojan 协议处理
		header := make([]byte, trojan.KeyLength+2+1+1+2+2)
		if _, err := io.ReadFull(r.Body, header); err != nil {
			log.Printf("❌ XHTTP stream-one Trojan: Failed to read header: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		validKeys := server.GetTrojanValidKeys()
		if validKeys == nil {
			log.Printf("❌ XHTTP Trojan: No valid keys configured")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		reader := &byteReader{data: header, pos: 0}
		pwd, command, addr, err := trojan.ReadHandshake(reader, validKeys)
		if err != nil {
			log.Printf("❌ XHTTP Trojan handshake failed: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		target = addr.String()
		log.Printf("✅ XHTTP Trojan handshake (user: %s), target: %s", maskPassword(pwd), target)

		if command == trojan.CommandUDP {
			log.Printf("⚠️ XHTTP Trojan UDP not supported")
			http.Error(w, "UDP not supported", http.StatusBadRequest)
			return
		}

		// 保存握手后的剩余数据
		if reader.pos < len(reader.data) {
			initialData = reader.data[reader.pos:]
		}
	} else {
		// EWP 协议处理
		header := make([]byte, 15)
		if _, err := io.ReadFull(r.Body, header); err != nil {
			log.Printf("❌ XHTTP stream-one: Failed to read header: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		plaintextLen := binary.BigEndian.Uint16(header[13:15])
		totalLen := 15 + int(plaintextLen) + 16 + 16

		handshakeData := make([]byte, totalLen)
		copy(handshakeData[:15], header)
		if _, err := io.ReadFull(r.Body, handshakeData[15:]); err != nil {
			log.Printf("❌ XHTTP stream-one: Failed to read handshake: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		req, resp, err := server.HandleEWPHandshakeBinary(handshakeData, clientIP)
		if err != nil {
			log.Printf("❌ XHTTP stream-one: EWP handshake failed: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write(resp)
			return
		}

		target = req.TargetAddr.String()
		respData = resp

		if req.Command == ewp.CommandUDP {
			log.Printf("📦 stream-one UDP mode")
			w.Header().Set("X-Accel-Buffering", "no")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}
			
			if _, err := w.Write(respData); err != nil {
				log.Printf("❌ Failed to send handshake response: %v", err)
				return
			}
			flusher.Flush()
			
			server.HandleUDPConnection(r.Body, &flushWriter{w: w, f: flusher})
			return
		}

		flowState = ewp.NewFlowState(req.UUID[:])
	}

	log.Printf("🔗 stream-one: %s", target)

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ Dial failed: %v", err)
		http.Error(w, "Connection failed", http.StatusBadGateway)
		return
	}
	defer remote.Close()

	// 发送初始数据（Trojan 模式）
	if len(initialData) > 0 {
		if _, err := remote.Write(initialData); err != nil {
			log.Printf("❌ XHTTP write initial data error: %v", err)
			return
		}
	}

	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	// 发送 EWP 握手响应（仅 EWP 模式）
	if len(respData) > 0 {
		if _, err := w.Write(respData); err != nil {
			log.Printf("❌ Failed to send handshake response: %v", err)
			return
		}
		flusher.Flush()
	}

	done := make(chan struct{}, 2)

	// HTTP/2 body -> remote (uplink)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				data := buf[:n]
				// 处理 Vision 流控（仅 EWP 模式）
				if flowState != nil {
					data = flowState.ProcessUplink(data)
				}
				if len(data) > 0 {
					if _, e := remote.Write(data); e != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// remote -> HTTP/2 body (downlink)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		var writeOnceUserUUID []byte
		if flowState != nil {
			writeOnceUserUUID = make([]byte, 16)
			// flowState 存在时必定是 EWP 模式，UUID 已在 flowState 中
		}

		for {
			n, err := remote.Read(buf)
			if n > 0 {
				data := buf[:n]
				// 应用 Vision 流控填充（仅 EWP 模式）
				if flowState != nil {
					data = flowState.PadDownlink(data, &writeOnceUserUUID)
				}
				if _, e := w.Write(data); e != nil {
					return
				}
				flusher.Flush()
			}
			if err != nil {
				return
			}
		}
	}()

	// 等待任意一个方向完成
	<-done
	log.Printf("✅ stream-one closed: %s", target)
}

// xhttpHandshakeHandler 处理 stream-down 模式的 EWP 握手请求 (seq=0)
func xhttpHandshakeHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}

	// 读取 EWP 握手请求
	handshakeData, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("❌ XHTTP handshake: Failed to read body: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 处理 EWP 握手
	req, respData, err := server.HandleEWPHandshakeBinary(handshakeData, clientIP)
	if err != nil {
		log.Printf("❌ XHTTP handshake: EWP failed: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(respData)
		return
	}

	// 先创建 session（让 GET 请求可以找到它）
	session := upsertSession(sessionID)

	// 连接目标服务器（使用请求 context，支持取消）
	target := req.TargetAddr.String()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	
	var d net.Dialer
	remote, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Printf("❌ XHTTP handshake: Dial failed: %v", err)
		xhttpSessions.Delete(sessionID) // 清理失败的 session
		if ctx.Err() == context.Canceled {
			// 客户端已取消，不需要返回错误
			return
		}
		http.Error(w, "Connection failed", http.StatusBadGateway)
		return
	}

	// 设置远程连接
	session.remote = remote

	log.Printf("✅ XHTTP handshake success: sessionID=%s, target=%s", sessionID, target)

	// 返回 EWP 握手响应
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(respData)
}

func xhttpDownloadHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
	// 等待 session 创建和 remote 就绪（最多等 15 秒）
	var session *xhttpSession
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		val, ok := xhttpSessions.Load(sessionID)
		if ok {
			session = val.(*xhttpSession)
			if session.remote != nil {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}
	if session.remote == nil {
		http.Error(w, "Session not ready (target connection timeout)", http.StatusGatewayTimeout)
		return
	}

	session.closeOnce.Do(func() {
		close(session.isFullyConnected)
	})
	defer xhttpSessions.Delete(sessionID)

	// 启动上行数据处理（从 server.UploadQueue 写入 remote）
	go func() {
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		for {
			select {
			case <-session.done:
				return
			default:
				n, err := session.uploadQueue.Read(buf)
				if n > 0 {
					if _, e := session.remote.Write(buf[:n]); e != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}
	}()

	log.Printf("📥 stream-down GET: %s", sessionID)

	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	buf := largeBufferPool.Get().([]byte)
	defer largeBufferPool.Put(buf)

	for {
		select {
		case <-session.done:
			return
		default:
			n, err := session.remote.Read(buf)
			if n > 0 {
				if _, e := w.Write(buf[:n]); e != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	}
}

func xhttpUploadHandler(w http.ResponseWriter, r *http.Request, sessionID, seqStr string) {
	// 检查是否是 seq=0 的握手请求
	if seqStr == "0" {
		// seq=0 是 EWP 握手请求，需要创建 session
		xhttpHandshakeHandler(w, r, sessionID)
		return
	}

	val, ok := xhttpSessions.Load(sessionID)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	session := val.(*xhttpSession)

	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	buf := largeBufferPool.Get().([]byte)
	defer largeBufferPool.Put(buf)

	if seqStr != "" {
		seq := uint64(0)
		fmt.Sscanf(seqStr, "%d", &seq)
		
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("❌ Upload read error: %v", err)
			return
		}

		if err := session.uploadQueue.Push(server.Packet{Payload: payload, Seq: seq}); err != nil {
			log.Printf("❌ Upload queue push error: %v", err)
		}
		log.Printf("📤 Packet uploaded: seq=%d, size=%d", seq, len(payload))
	} else {
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				seq := session.uploadQueue.NextSeq()
				if e := session.uploadQueue.Push(server.Packet{Payload: data, Seq: seq}); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
}

func parseConnect(data []byte) (target string, extraData []byte) {
	str := string(data)
	if !strings.HasPrefix(str, "CONNECT:") {
		return "", nil
	}
	str = strings.TrimPrefix(str, "CONNECT:")
	idx := strings.Index(str, "\n")
	if idx < 0 {
		return strings.TrimSpace(str), nil
	}
	target = str[:idx]
	if idx+1 < len(data) {
		extraData = data[len("CONNECT:")+idx+1:]
	}
	return target, extraData
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generatePadding(minLen, maxLen int) string {
	length := minLen
	if maxLen > minLen {
		diff := maxLen - minLen
		b := make([]byte, 1)
		rand.Read(b)
		length += int(b[0]) % (diff + 1)
	}
	
	padding := make([]byte, length)
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := range padding {
		rand.Read(padding[i : i+1])
		padding[i] = chars[padding[i]%byte(len(chars))]
	}
	return string(padding)
}

// flushWriter 实现自动 flush 的 Writer
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err == nil && fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

// ======================== Trojan Fallback Handler ========================

// TrojanFallbackHandler 处理 Trojan 认证失败时的回退
type TrojanFallbackHandler struct {
	addr string
}

// HandleFallback 处理回退连接
func (h *TrojanFallbackHandler) HandleFallback(conn net.Conn, header []byte) error {
	defer conn.Close()

	// 连接到回退服务器
	fallbackConn, err := net.DialTimeout("tcp", h.addr, 10*time.Second)
	if err != nil {
		log.Printf("⚠️ Fallback dial failed: %v", err)
		// 如果回退失败，返回伪装的 nginx 页面
		h.sendNginxResponse(conn)
		return nil
	}
	defer fallbackConn.Close()

	log.Printf("🔄 Fallback connection to %s", h.addr)

	// 先发送已读取的 header 数据
	if len(header) > 0 {
		if _, err := fallbackConn.Write(header); err != nil {
			return err
		}
	}

	// 双向转发
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		io.CopyBuffer(fallbackConn, conn, buf)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		io.CopyBuffer(conn, fallbackConn, buf)
	}()

	<-done
	return nil
}

// sendNginxResponse 发送伪装的 nginx 响应
func (h *TrojanFallbackHandler) sendNginxResponse(conn net.Conn) {
	response := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: " + strconv.Itoa(len(nginxHTML)) + "\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		nginxHTML
	conn.Write([]byte(response))
}
