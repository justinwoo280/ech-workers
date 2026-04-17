package main

import (
	"flag"
	"io"
	"net"
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
	// uuid has no default — fail-closed if not set (P0-1)
	uuid         = os.Getenv("UUID")
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

// trustedProxyCIDRs holds parsed CIDRs whose source IPs may set XFF / CF-Connecting-IP.
// Populated once at startup by initTrustedProxies(). (P0-2)
var trustedProxyCIDRs []*net.IPNet

// defaultCloudflareRanges is the official Cloudflare edge IP list (IPv4 + IPv6).
// See https://www.cloudflare.com/ips/
var defaultCloudflareRanges = []string{
	// IPv4
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"108.162.192.0/18",
	"131.0.72.0/22",
	"141.101.64.0/18",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	// IPv6
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// initTrustedProxies parses the TRUSTED_PROXIES env var (comma-separated CIDRs).
// If unset, defaults to Cloudflare's official edge ranges.
// Set TRUSTED_PROXIES="" to disable XFF parsing entirely (direct-connect mode).
func initTrustedProxies() {
	var cidrs []string
	if env := os.Getenv("TRUSTED_PROXIES"); env != "" {
		for _, s := range strings.Split(env, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				cidrs = append(cidrs, s)
			}
		}
		log.Info("Trusted proxies: %d CIDR(s) from TRUSTED_PROXIES env", len(cidrs))
	} else {
		cidrs = defaultCloudflareRanges
		log.Info("Trusted proxies: Cloudflare default ranges (%d CIDRs)", len(cidrs))
	}

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warn("Invalid trusted proxy CIDR %q: %v", cidr, err)
			continue
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, ipNet)
	}
}

// isTrustedProxy reports whether the given host (without port) is in trustedProxyCIDRs.
func isTrustedProxy(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

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
	initTrustedProxies()
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
		// P0-1: fail-closed — refuse to start without an explicit UUID
		if uuid == "" {
			log.Fatal("UUID environment variable is required for EWP mode, refusing to start. " +
				"Set the UUID env var to a valid UUID before launching the server.")
		}
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

// getClientIP returns the real client IP. (P0-2)
// XFF / CF-Connecting-IP headers are only trusted when the direct peer
// (r.RemoteAddr) falls within a configured trusted-proxy CIDR.
// This prevents attackers from spoofing their IP to bypass rate limiting.
func getClientIP(r *http.Request) string {
	// Extract the direct peer IP (strip port).
	remoteHost := r.RemoteAddr
	if idx := strings.LastIndex(remoteHost, ":"); idx != -1 {
		remoteHost = remoteHost[:idx]
	}

	// Only honour proxy headers when the request arrives from a trusted proxy.
	if isTrustedProxy(remoteHost) {
		// CF-Connecting-IP: single real IP set by Cloudflare — most reliable.
		if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
			if ip := net.ParseIP(strings.TrimSpace(cfip)); ip != nil {
				return ip.String()
			}
		}
		// X-Forwarded-For: take the rightmost untrusted entry
		// (the last IP appended by our trusted proxy, not client-controlled).
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				candidate := strings.TrimSpace(parts[i])
				if ip := net.ParseIP(candidate); ip != nil && !isTrustedProxy(candidate) {
					return ip.String()
				}
			}
		}
		// X-Real-IP fallback
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
				return ip.String()
			}
		}
	}

	// Direct connection or untrusted peer: use the socket address.
	return remoteHost
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
