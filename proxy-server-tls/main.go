package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
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

	pb "proxy-server/proto"
	"proxy-server/ewp"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
)

var (
	uuid          = getEnv("UUID", "d342d11e-d424-4583-b36e-524ab1f0afa4")
	port          = getEnv("PORT", "8080")
	wsPath        = getEnv("WS_PATH", "/")
	xhttpPath     = getEnv("XHTTP_PATH", "/xhttp")
	paddingMin    = getEnvInt("PADDING_MIN", 100)
	paddingMax    = getEnvInt("PADDING_MAX", 1000)
	grpcMode      = false
	xhttpMode     = false
	enableFlow    = false
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

// ======================== 自签名证书生成 ========================

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ECH Workers Proxy"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	// 解析命令行参数
	flag.BoolVar(&grpcMode, "grpc", false, "启用 gRPC 模式")
	flag.BoolVar(&xhttpMode, "xhttp", false, "启用 XHTTP 模式")
	flag.BoolVar(&enableFlow, "flow", false, "启用 EWP Flow 流控协议（Vision 风格）")
	flag.StringVar(&port, "port", port, "监听端口")
	flag.Parse()

	// 也支持环境变量 MODE=grpc/xhttp, ENABLE_FLOW=true/false
	mode := os.Getenv("MODE")
	if mode == "grpc" {
		grpcMode = true
	} else if mode == "xhttp" {
		xhttpMode = true
	}
	if os.Getenv("ENABLE_FLOW") == "true" {
		enableFlow = true
	}

	log.Printf("🔑 UUID: %s", uuid)
	if enableFlow {
		log.Printf("🌊 EWP Flow 协议已启用（Vision 风格流控）")
	}

	if err := initEWPHandler(uuid); err != nil {
		log.Fatalf("❌ Failed to initialize EWP handler: %v", err)
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
	// 调试：打印收到的原始数据摘要
	if len(content) >= 32 {
		fmt.Printf("[DEBUG] gRPC received: len=%d, first16=%x, last16=%x\n", 
			len(content), content[:16], content[len(content)-16:])
	} else {
		fmt.Printf("[DEBUG] gRPC received: len=%d, data=%x\n", len(content), content)
	}

	req, respData, err := handleEWPHandshakeBinary(content, clientIP)
	if err != nil {
		stream.Send(&pb.SocketData{Content: respData})
		return nil
	}

	if err := stream.Send(&pb.SocketData{Content: respData}); err != nil {
		log.Printf("❌ gRPC: 发送握手响应失败: %v", err)
		return err
	}

	target := req.TargetAddr.String()
	log.Printf("🔗 gRPC connecting to %s", target)

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ gRPC dial error: %v", err)
		return nil
	}
	defer remote.Close()

	log.Printf("✅ gRPC connected to %s", target)

	// 初始化 Flow State（如果启用）
	var flowState *ewp.FlowState
	var writeOnceUserUUID []byte
	if enableFlow {
		flowState = ewp.NewFlowState(req.UUID[:])
		writeOnceUserUUID = make([]byte, 16)
		copy(writeOnceUserUUID, req.UUID[:])
		log.Printf("🌊 gRPC Flow 协议已启用")
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
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("❌ Failed to generate self-signed cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	creds := credentials.NewTLS(tlsConfig)

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
		grpc.Creds(creds),
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

	log.Println("🔒 gRPC server with TLS enabled")
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
	if proto != uuid {
		disguiseHandler(w, r)
		return
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

// handleWebSocket 处理 EWP 协议（支持 Vision 流控）
func handleWebSocket(conn *websocket.Conn, clientAddr string) {
	// 读取第一帧数据
	_, firstMsg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("❌ Read first message error: %v", err)
		return
	}

	if len(firstMsg) < 15 {
		log.Printf("❌ Message too short: %d bytes", len(firstMsg))
		return
	}

	handleSimpleProtocol(conn, firstMsg, clientAddr)
}

// handleSimpleProtocol 处理 EWP 协议（简单 WebSocket 模式）
func handleSimpleProtocol(conn *websocket.Conn, firstMsg []byte, clientAddr string) {
	req, respData, err := handleEWPHandshakeBinary(firstMsg, clientAddr)
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

// ======================== XHTTP 服务 (基于 Xray-core 实现) ========================

type xhttpSession struct {
	remote           net.Conn
	uploadQueue      *uploadQueue
	done             chan struct{}
	isFullyConnected chan struct{}
}

var (
	xhttpSessions      = sync.Map{}
	xhttpSessionMutex  sync.Mutex
	xhttpSessionExpiry = 30 * time.Second
)

func startXHTTPServer() {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("❌ Failed to generate self-signed cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"}, // 显式支持 HTTP/2
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)
	
	// 包装所有请求的日志中间件
	loggedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] HTTP request received: %s %s %s from %s", r.Proto, r.Method, r.URL.Path, r.RemoteAddr)
		mux.ServeHTTP(w, r)
	})
	
	mux.HandleFunc(xhttpPath+"/", xhttpHandler)
	mux.HandleFunc(xhttpPath, xhttpHandler)
	mux.HandleFunc("/", disguiseHandler)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           loggedHandler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// 注意：不设置 ReadTimeout 和 WriteTimeout，因为 stream-one 是长连接
	}

	go cleanupExpiredSessions()
	log.Println("🔒 XHTTP server with TLS enabled")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func xhttpHandler(w http.ResponseWriter, r *http.Request) {
	// 调试：打印所有进入的请求
	log.Printf("[DEBUG] XHTTP request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	log.Printf("[DEBUG] X-Auth-Token: %s (expected: %s)", r.Header.Get("X-Auth-Token"), uuid)
	
	if r.Header.Get("X-Auth-Token") != uuid {
		log.Printf("[DEBUG] Token mismatch, returning disguise page")
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
		uploadQueue:      newUploadQueue(100),
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

	// 读取 EWP 握手请求（先读取 15 字节头部获取长度）
	header := make([]byte, 15)
	if _, err := io.ReadFull(r.Body, header); err != nil {
		log.Printf("❌ XHTTP stream-one: Failed to read header: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 解析长度字段
	plaintextLen := binary.BigEndian.Uint16(header[13:15])
	totalLen := 15 + int(plaintextLen) + 16 + 16 // header + ciphertext + poly1305tag + hmac

	// 读取完整握手数据
	handshakeData := make([]byte, totalLen)
	copy(handshakeData[:15], header)
	if _, err := io.ReadFull(r.Body, handshakeData[15:]); err != nil {
		log.Printf("❌ XHTTP stream-one: Failed to read handshake: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 处理 EWP 握手
	req, respData, err := handleEWPHandshakeBinary(handshakeData, clientIP)
	if err != nil {
		log.Printf("❌ XHTTP stream-one: EWP handshake failed: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(respData)
		return
	}

	target := req.TargetAddr.String()

	// 检查是否是 UDP 模式
	if req.Command == ewp.CommandUDP {
		log.Printf("📦 stream-one UDP mode")
		
		// 发送 EWP 握手响应
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
		
		// 处理 UDP 流
		HandleUDPConnection(r.Body, &flushWriter{w: w, f: flusher})
		return
	}

	log.Printf("🔗 stream-one: %s", target)

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("❌ Dial failed: %v", err)
		http.Error(w, "Connection failed", http.StatusBadGateway)
		return
	}
	defer remote.Close()

	// 发送 EWP 握手响应
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	// 先发送握手响应
	if _, err := w.Write(respData); err != nil {
		log.Printf("❌ Failed to send handshake response: %v", err)
		return
	}
	flusher.Flush()

	// 初始化 Vision 流控状态
	flowState := ewp.NewFlowState(req.UUID[:])

	done := make(chan struct{}, 2)

	// HTTP/2 body -> remote (uplink: 解包 Vision 填充)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				// 处理 Vision 流控（自动检测并解包）
				processedData := flowState.ProcessUplink(buf[:n])
				if len(processedData) > 0 {
					if _, e := remote.Write(processedData); e != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// remote -> HTTP/2 body (downlink: 添加 Vision 填充)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		writeOnceUserUUID := make([]byte, 16)
		copy(writeOnceUserUUID, req.UUID[:])

		for {
			n, err := remote.Read(buf)
			if n > 0 {
				// 应用 Vision 流控填充
				paddedData := flowState.PadDownlink(buf[:n], &writeOnceUserUUID)
				if _, e := w.Write(paddedData); e != nil {
					return
				}
				flusher.Flush()
			}
			if err != nil {
				return
			}
		}
	}()

	// 等待任意一个方向完成（表示连接应该关闭）
	<-done
	// 注意：不需要等待两个 done，因为一方关闭后另一方也会因为读写错误而退出
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

	log.Printf("[DEBUG] XHTTP handshake: sessionID=%s, dataLen=%d", sessionID, len(handshakeData))

	// 处理 EWP 握手
	req, respData, err := handleEWPHandshakeBinary(handshakeData, clientIP)
	if err != nil {
		log.Printf("❌ XHTTP handshake: EWP failed: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(respData)
		return
	}

	// 连接目标服务器
	target := req.TargetAddr.String()
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("❌ XHTTP handshake: Dial failed: %v", err)
		http.Error(w, "Connection failed", http.StatusBadGateway)
		return
	}

	// 创建 session 并存储远程连接
	session := upsertSession(sessionID)
	session.remote = remote

	log.Printf("✅ XHTTP handshake success: sessionID=%s, target=%s", sessionID, target)

	// 返回 EWP 握手响应
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(respData)
}

func xhttpDownloadHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
	val, ok := xhttpSessions.Load(sessionID)
	if !ok {
		// 等待 session 创建（握手可能还在处理中）
		time.Sleep(100 * time.Millisecond)
		val, ok = xhttpSessions.Load(sessionID)
		if !ok {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}
	}
	
	session := val.(*xhttpSession)
	close(session.isFullyConnected)
	defer xhttpSessions.Delete(sessionID)

	if session.remote == nil {
		http.Error(w, "Session not ready", http.StatusServiceUnavailable)
		return
	}

	// 启动上行数据处理（从 uploadQueue 写入 remote）
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

		if err := session.uploadQueue.Push(Packet{Payload: payload, Seq: seq}); err != nil {
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
				if e := session.uploadQueue.Push(Packet{Payload: data, Seq: seq}); e != nil {
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
