package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	commonnet "ewp-core/common/net"
	"ewp-core/internal/server"
	log "ewp-core/log"
	"ewp-core/option"
	pb "ewp-core/proto"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

func startFromConfig(configPath string) {
	cfg, err := option.LoadServerConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Info("EWP-Core Server (Config Mode)")
	log.Info("Config: %s", configPath)

	if cfg.Protocol.Type == "trojan" {
		log.Info("Protocol: Trojan")
		log.Info("Password: %s", maskPassword(cfg.Protocol.Password))
		if err := server.InitTrojanHandler(cfg.Protocol.Password); err != nil {
			log.Fatalf("Failed to initialize Trojan handler: %v", err)
		}
		if cfg.Protocol.Fallback != "" {
			log.Info("Fallback: %s", cfg.Protocol.Fallback)
			server.SetTrojanFallback(&TrojanFallbackHandler{addr: cfg.Protocol.Fallback})
		}
	} else {
		log.Info("Protocol: EWP")
		log.Info("UUID: %s", cfg.Protocol.UUID)
		if cfg.Protocol.EnableFlow {
			log.Info("EWP Flow enabled")
		}
		if err := server.InitEWPHandler(cfg.Protocol.UUID); err != nil {
			log.Fatalf("Failed to initialize EWP handler: %v", err)
		}
	}

	enableFlow = cfg.Protocol.EnableFlow
	trojanMode = cfg.Protocol.Type == "trojan"

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Info("Shutting down...")
		os.Exit(0)
	}()

	var tlsConfig *tls.Config
	if cfg.TLS != nil && cfg.TLS.Enabled {
		tlsConfig, err = loadTLSConfig(cfg.TLS)
		if err != nil {
			log.Fatalf("Failed to load TLS config: %v", err)
		}
		log.Info("TLS enabled (ALPN: %v)", cfg.TLS.ALPN)
	}

	hasH3 := false
	for _, mode := range cfg.Listener.Modes {
		if mode == "h3" {
			hasH3 = true
			break
		}
	}

	if hasH3 {
		go startH3Listener(cfg, tlsConfig)
	}

	mux := createUnifiedHandler(cfg)

	addr := fmt.Sprintf("%s:%d", cfg.Listener.Address, cfg.Listener.Port)
	lis, err := commonnet.ListenTFO("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}

	log.Info("Server listening on %s (modes: %v)", addr, cfg.Listener.Modes)

	if tlsConfig != nil {
		httpServer := &http.Server{
			Handler:   mux,
			TLSConfig: tlsConfig,
		}
		log.Fatal(httpServer.ServeTLS(lis, "", ""))
	} else {
		h2s := &http2.Server{}
		httpServer := &http.Server{
			Handler: h2c.NewHandler(mux, h2s),
		}
		log.Fatal(httpServer.Serve(lis))
	}
}

func createUnifiedHandler(cfg *option.ServerConfig) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)

	hasRootHandler := false

	for _, mode := range cfg.Listener.Modes {
		switch mode {
		case "ws":
			wsPath := cfg.Listener.WSPath
			if wsPath == "" {
				wsPath = "/"
			}
			if wsPath == "/" {
				hasRootHandler = true
			}
			mux.HandleFunc(wsPath, wsHandler)
			log.Info("WebSocket handler registered (path: %s)", wsPath)

		case "grpc":
			serviceName := cfg.Listener.GRPCService
			if serviceName == "" {
				serviceName = "ProxyService"
			}
			grpcPath := "/" + serviceName + "/"

			if cfg.Advanced.EnableGRPCWeb {
				// Use the native gRPC-Web handler that works over any HTTP version
				// (H1, H2, H3). This is required for CDN scenarios where nginx
				// proxies over HTTP/1.1, bypassing grpc.Server's ProtoMajor==2 check.
				mux.Handle(grpcPath, server.NewH3GRPCWebHandler(newProtocolHandler))
				log.Info("gRPC-Web handler registered (H1/H2/H3 compatible, service: %s)", serviceName)
			} else {
				// Standard gRPC mode: requires the client to connect over HTTP/2.
				mux.Handle(grpcPath, createGRPCServer(cfg))
				log.Info("gRPC handler registered (service: %s)", serviceName)
			}

		case "xhttp":
			xhttpPath := cfg.Listener.XHTTPPath
			if xhttpPath == "" {
				xhttpPath = "/xhttp"
			}
			mux.HandleFunc(xhttpPath, xhttpHandler)
			log.Info("XHTTP handler registered (path: %s)", xhttpPath)

		case "h3":
			continue

		default:
			log.Warn("Unknown mode: %s", mode)
		}
	}

	if !hasRootHandler {
		mux.HandleFunc("/", disguiseHandler)
	}

	return mux
}

func createGRPCServer(cfg *option.ServerConfig) *grpc.Server {
	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.MaxConcurrentStreams(1000),
	)

	serviceName := cfg.Listener.GRPCService
	if serviceName == "" {
		serviceName = "ProxyService"
	}

	serviceDesc := &grpc.ServiceDesc{
		ServiceName: serviceName,
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
	grpcServer.RegisterService(serviceDesc, &proxyServer{})

	return grpcServer
}

func loadTLSConfig(cfg *option.ServerTLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if len(cfg.ALPN) > 0 {
		tlsConfig.NextProtos = cfg.ALPN
	}

	return tlsConfig, nil
}

func startH3Listener(cfg *option.ServerConfig, tlsConfig *tls.Config) {
	if tlsConfig == nil {
		log.Fatalf("HTTP/3 requires TLS to be enabled")
	}

	hasH3 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h3" {
			hasH3 = true
			break
		}
	}
	if !hasH3 {
		log.Fatalf("HTTP/3 requires 'h3' in TLS ALPN")
	}

	serviceName := cfg.Listener.GRPCService
	if serviceName == "" {
		serviceName = "ProxyService"
	}

	mux := http.NewServeMux()
	tunnelPath := "/" + serviceName + "/Tunnel"
	mux.Handle(tunnelPath, server.NewH3GRPCWebHandler(newProtocolHandler))
	mux.HandleFunc("/", disguiseHandler)

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                20 * time.Second,
		InitialStreamReceiveWindow:     6 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 15 * 1024 * 1024,
		MaxConnectionReceiveWindow:     25 * 1024 * 1024,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Listener.Address, cfg.Listener.Port)
	h3Server := &http3.Server{
		Addr:       addr,
		Handler:    mux,
		TLSConfig:  tlsConfig,
		QUICConfig: quicConfig,
	}

	log.Info("HTTP/3 listening on %s (path: %s)", addr, tunnelPath)
	log.Info("Native gRPC-Web over HTTP/3 enabled")

	if err := h3Server.ListenAndServe(); err != nil {
		log.Fatalf("HTTP/3 server failed: %v", err)
	}
}
