package main

import (
	"flag"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	commonnet "ewp-core/common/net"
	"ewp-core/internal/server"
	log "ewp-core/log"
)

var (
	uuid         = getEnv("UUID", "d342d11e-d424-4583-b36e-524ab1f0afa4")
	password     = getEnv("PASSWORD", "")
	port         = getEnv("PORT", "8080")
	wsPath       = getEnv("WS_PATH", "/")
	xhttpPath    = getEnv("XHTTP_PATH", "/xhttp")
	grpcService  = getEnv("GRPC_SERVICE", "ProxyService")
	paddingMin   = getEnvInt("PADDING_MIN", 100)
	paddingMax   = getEnvInt("PADDING_MAX", 1000)
	fallbackAddr = getEnv("FALLBACK", "")
	sseHeaders   = getEnv("SSE_HEADERS", "true") != "false"
	grpcMode     = false
	xhttpMode    = false
	enableFlow   = false
	trojanMode   = false
)

var largeBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

const nginxHTML = `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>`

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

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "", "配置文件路径 (JSON 格式)")
	flag.StringVar(&configFile, "config", "", "配置文件路径 (JSON 格式)")
	flag.BoolVar(&grpcMode, "grpc", false, "启用 gRPC 模式")
	flag.BoolVar(&xhttpMode, "xhttp", false, "启用 XHTTP 模式")
	flag.BoolVar(&enableFlow, "flow", false, "启用 EWP Flow 流控协议")
	flag.BoolVar(&trojanMode, "trojan", false, "启用 Trojan 协议模式")
	flag.StringVar(&port, "port", port, "监听端口")
	flag.StringVar(&password, "password", password, "Trojan 密码")
	flag.StringVar(&fallbackAddr, "fallback", fallbackAddr, "Trojan 回退地址（如 127.0.0.1:80）")
	flag.Parse()

	if configFile != "" {
		startFromConfig(configFile)
		return
	}

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

	if trojanMode {
		if password == "" {
			password = uuid
		}
		log.Info("Protocol: Trojan")
		log.Info("Password: %s", maskPassword(password))
		if err := server.InitTrojanHandler(password); err != nil {
			log.Fatalf("Failed to initialize Trojan handler: %v", err)
		}
		if fallbackAddr != "" {
			log.Info("Fallback: %s", fallbackAddr)
			server.SetTrojanFallback(&TrojanFallbackHandler{addr: fallbackAddr})
		}
	} else {
		log.Info("Protocol: EWP")
		log.Info("UUID: %s", uuid)
		if enableFlow {
			log.Info("EWP Flow enabled")
		}
		if err := server.InitEWPHandler(uuid); err != nil {
			log.Fatalf("Failed to initialize EWP handler: %v", err)
		}
	}

	if grpcMode {
		log.Info("gRPC server listening on :%s", port)
		startGRPCServer()
	} else if xhttpMode {
		log.Info("XHTTP server listening on :%s", port)
		startXHTTPServer()
	} else {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", healthHandler)
		mux.HandleFunc("/healthz", healthHandler)
		mux.HandleFunc(wsPath, wsHandler)
		mux.HandleFunc("/", disguiseHandler)

		lis, err := commonnet.ListenTFO("tcp", ":"+port)
		if err != nil {
			log.Fatalf("WebSocket listen failed: %v", err)
		}
		log.Info("WebSocket listener ready (TFO)")

		srv := &http.Server{Handler: mux}
		log.Info("WebSocket server listening on :%s (path=%s)", port, wsPath)
		log.Fatal(srv.Serve(lis))
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func disguiseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.18.0")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(nginxHTML))
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return cfip
	}
	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}
	return clientIP
}

func maskPassword(p string) string {
	if len(p) <= 4 {
		return "****"
	}
	return p[:2] + "****" + p[len(p)-2:]
}

func httpError(w http.ResponseWriter, statusCode int, message string, logFormat string, args ...interface{}) {
	log.Warn(logFormat, args...)
	http.Error(w, message, statusCode)
}

func newProtocolHandler() server.ProtocolHandler {
	if trojanMode {
		return server.NewTrojanProtocolHandler()
	}
	return server.NewEWPProtocolHandler(enableFlow)
}

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
