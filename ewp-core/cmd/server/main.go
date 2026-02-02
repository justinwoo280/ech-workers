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

	commonnet "ewp-core/common/net"
	"ewp-core/internal/server"
	pb "ewp-core/proto"
	"ewp-core/protocol/trojan"
	grpctransport "ewp-core/transport/grpc"
	wstransport "ewp-core/transport/websocket"
	xhttptransport "ewp-core/transport/xhttp"

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
	sseHeaders    = getEnv("SSE_HEADERS", "true") != "false"  // SSE 伪装头（默认启用）
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

		lis, err := commonnet.ListenTFO("tcp", ":"+port)
		if err != nil {
			log.Fatalf("❌ WebSocket listen failed: %v", err)
		}
		log.Printf("✅ WebSocket listener created with TCP Fast Open support")

		server := &http.Server{
			Handler: mux,
		}

		log.Printf("🚀 WebSocket server listening on :%s (ws_path=%s)", port, wsPath)
		log.Fatal(server.Serve(lis))
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

	protocol := newProtocolHandler()
	transport := grpctransport.NewServerAdapter(stream)

	opts := server.TunnelOptions{
		Protocol:  protocol,
		Transport: transport,
		ClientIP:  clientIP,
		Timeout:   10 * time.Second,
	}

	return server.EstablishTunnel(context.Background(), content, opts)
}

func startGRPCServer() {
	lis, err := commonnet.ListenTFO("tcp", ":"+port)
	if err != nil {
		log.Fatalf("❌ gRPC listen failed: %v", err)
	}
	log.Printf("✅ gRPC listener created with TCP Fast Open support")

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

func handleWebSocket(conn *websocket.Conn, clientAddr string) {
	_, firstMsg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("❌ WebSocket: Failed to read first message: %v", err)
		return
	}

	if trojanMode {
		if len(firstMsg) < trojan.KeyLength+2+1+1+2+2 {
			log.Printf("❌ Trojan message too short: %d bytes", len(firstMsg))
			return
		}
	} else {
		if len(firstMsg) < 15 {
			log.Printf("❌ EWP message too short: %d bytes", len(firstMsg))
			return
		}
	}
	
	protocol := newProtocolHandler()

	transport := wstransport.NewServerAdapter(conn)

	opts := server.TunnelOptions{
		Protocol:  protocol,
		Transport: transport,
		ClientIP:  clientAddr,
		Timeout:   10 * time.Second,
	}

	server.EstablishTunnel(context.Background(), firstMsg, opts)
}

// ======================== XHTTP 服务 (基于 Xray-core 实现) ========================

type xhttpSession struct {
	remote           net.Conn
	uploadQueue      *server.UploadQueue
	done             chan struct{}
	isFullyConnected chan struct{}
	closeOnce        sync.Once
	createdAt        time.Time
	clientIP         string
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

	setXHTTPResponseHeaders(w)

	paddingLen := 0
	if referrer := r.Header.Get("Referer"); referrer != "" {
		if refURL, err := url.Parse(referrer); err == nil {
			paddingLen = len(refURL.Query().Get("x_padding"))
		}
	} else {
		paddingLen = len(r.URL.Query().Get("x_padding"))
	}

	if paddingLen < paddingMin || paddingLen > paddingMax {
		httpError(w, http.StatusBadRequest, "Bad Request", "❌ Invalid padding length: %d (expected %d-%d)", paddingLen, paddingMin, paddingMax)
		return
	}

	clientIP := getClientIP(r)

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

	log.Printf("📥 XHTTP %s %s (session=%s, seq=%s, padding=%d, ip=%s)", r.Method, r.URL.Path, sessionID, seqStr, paddingLen, clientIP)

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

// setStreamResponseHeaders 统一设置流式响应头并返回 Flusher
// contentType: 内容类型，空字符串则使用 SSE 伪装
func setStreamResponseHeaders(w http.ResponseWriter, contentType string) http.Flusher {
	// 禁止 CDN/Nginx 缓存和缓冲（参考 Xray-core）
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	
	// 设置 Content-Type
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	} else if sseHeaders {
		// SSE 伪装：让中间件认为这是 Server-Sent Events 长连接
		w.Header().Set("Content-Type", "text/event-stream")
	}
	
	w.WriteHeader(http.StatusOK)
	
	// 返回 Flusher（如果支持）
	if flusher, ok := w.(http.Flusher); ok {
		return flusher
	}
	return nil
}

// setXHTTPResponseHeaders 保持向后兼容
func setXHTTPResponseHeaders(w http.ResponseWriter) {
	setStreamResponseHeaders(w, "")
}

// newProtocolHandler 统一创建协议处理器
func newProtocolHandler() server.ProtocolHandler {
	if trojanMode {
		return server.NewTrojanProtocolHandler()
	}
	return server.NewEWPProtocolHandler(enableFlow)
}

// httpError 统一记录错误日志并返回 HTTP 错误响应
func httpError(w http.ResponseWriter, statusCode int, message string, logFormat string, args ...interface{}) {
	log.Printf(logFormat, args...)
	http.Error(w, message, statusCode)
}

// maskPassword 隐藏密码的敏感部分
func maskPassword(p string) string {
	if len(p) <= 4 {
		return "****"
	}
	return p[:2] + "****" + p[len(p)-2:]
}

func getClientIP(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}

	cfConnectingIP := r.Header.Get("CF-Connecting-IP")
	if cfConnectingIP != "" {
		return cfConnectingIP
	}

	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}
	return clientIP
}

func disguiseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.18.0")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(nginxHTML))
}

func upsertSession(sessionID string, clientIP string) *xhttpSession {
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
		createdAt:        time.Now(),
		clientIP:         clientIP,
	}
	xhttpSessions.Store(sessionID, session)

	shouldReap := make(chan struct{})
	go func() {
		time.Sleep(xhttpSessionExpiry)
		close(shouldReap)
	}()

	go func() {
		select {
		case <-shouldReap:
			session.closeOnce.Do(func() {
				if session.remote != nil {
					session.remote.Close()
				}
				close(session.done)
				xhttpSessions.Delete(sessionID)
				log.Printf("🧹 Session expired after %s: %s (client: %s)", 
					time.Since(session.createdAt).Round(time.Second), sessionID, clientIP)
			})
		case <-session.isFullyConnected:
			log.Printf("✅ Session fully connected: %s (client: %s)", sessionID, clientIP)
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
	clientIP := getClientIP(r)

	var handshakeData []byte

	if trojanMode {
		header := make([]byte, trojan.KeyLength+2+1+1+2+2)
		if _, err := io.ReadFull(r.Body, header); err != nil {
			httpError(w, http.StatusBadRequest, "Bad Request", "❌ XHTTP stream-one: Failed to read Trojan header: %v", err)
			return
		}
		handshakeData = header
	} else {
		header := make([]byte, 15)
		if _, err := io.ReadFull(r.Body, header); err != nil {
			httpError(w, http.StatusBadRequest, "Bad Request", "❌ XHTTP stream-one: Failed to read EWP header: %v", err)
			return
		}

		plaintextLen := binary.BigEndian.Uint16(header[13:15])
		totalLen := 15 + int(plaintextLen) + 16 + 16
		handshakeData = make([]byte, totalLen)
		copy(handshakeData[:15], header)
		if _, err := io.ReadFull(r.Body, handshakeData[15:]); err != nil {
			httpError(w, http.StatusBadRequest, "Bad Request", "❌ XHTTP stream-one: Failed to read EWP handshake: %v", err)
			return
		}
	}

	protocol := newProtocolHandler()
	result, err := protocol.Handshake(handshakeData, clientIP)
	if err != nil {
		httpError(w, http.StatusBadRequest, "Bad Request", "❌ XHTTP stream-one: Handshake failed: %v", err)
		if len(result.Response) > 0 {
			w.Write(result.Response)
		}
		return
	}

	log.Printf("✅ [XHTTP] stream-one: %s (user: %s) -> %s", clientIP, result.UserID, result.Target)

	if result.IsUDP {
		log.Printf("📦 stream-one UDP mode")
		flusher := setStreamResponseHeaders(w, "application/octet-stream")
		if flusher == nil {
			return
		}
		
		if len(result.Response) > 0 {
			if _, err := w.Write(result.Response); err != nil {
				log.Printf("❌ Failed to send handshake response: %v", err)
				return
			}
			flusher.Flush()
		}
		
		server.HandleUDPConnection(r.Body, &flushWriter{w: w, f: flusher})
		return
	}

	remote, err := net.Dial("tcp", result.Target)
	if err != nil {
		httpError(w, http.StatusBadGateway, "Connection failed", "❌ XHTTP stream-one: Dial failed: %v", err)
		return
	}
	defer remote.Close()

	if len(result.InitialData) > 0 {
		if _, err := remote.Write(result.InitialData); err != nil {
			log.Printf("❌ XHTTP stream-one: Write initial data error: %v", err)
			return
		}
	}

	flusher := setStreamResponseHeaders(w, "application/octet-stream")
	if flusher == nil {
		return
	}

	if len(result.Response) > 0 {
		if _, err := w.Write(result.Response); err != nil {
			log.Printf("❌ XHTTP stream-one: Failed to send handshake response: %v", err)
			return
		}
		flusher.Flush()
	}

	transport := xhttptransport.NewServerAdapter(r.Body, w, flusher)
	forwarder := server.NewTunnelForwarder(transport, remote, result.FlowState)
	forwarder.Forward()

	log.Printf("✅ XHTTP stream-one closed: %s", result.Target)
}

// xhttpHandshakeHandler 处理 stream-down 模式的 EWP 握手请求 (seq=0)
func xhttpHandshakeHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
	clientIP := getClientIP(r)

	// 读取 EWP 握手请求
	handshakeData, err := io.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusBadRequest, "Bad Request", "❌ XHTTP handshake: Failed to read body: %v", err)
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

	log.Printf("✅ XHTTP handshake OK: session=%s, target=%s, client=%s", sessionID, req.TargetAddr, clientIP)

	// 先创建 session（让 GET 请求可以找到它）
	session := upsertSession(sessionID, clientIP)

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

	flusher := setStreamResponseHeaders(w, "application/octet-stream")
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
