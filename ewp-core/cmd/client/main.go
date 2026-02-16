package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/option"
	"ewp-core/protocol"
	"ewp-core/transport"
	"ewp-core/transport/grpc"
	"ewp-core/transport/h3grpc"
	"ewp-core/transport/websocket"
	"ewp-core/transport/xhttp"
	"ewp-core/tun"
)

func main() {
	// Load configuration (will parse flags internally)
	cfg, err := option.LoadConfigWithFallback()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		fmt.Fprintf(os.Stderr, "Usage: %s -c config.json\n", os.Args[0])
		os.Exit(1)
	}

	// Setup logging
	setupLogging(cfg)

	log.Printf("[启动] EWP-Core Client")
	log.Printf("[配置] Inbounds: %d, Outbounds: %d", len(cfg.Inbounds), len(cfg.Outbounds))

	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("[信号] Received exit signal, shutting down...")
		os.Exit(0)
	}()

	// Get the first outbound (primary proxy)
	if len(cfg.Outbounds) == 0 {
		log.Fatalf("[错误] No outbound configured")
	}

	outbound := cfg.Outbounds[0]
	log.Printf("[出站] Tag: %s, Type: %s, Server: %s:%d", 
		outbound.Tag, outbound.Type, outbound.Server, outbound.ServerPort)

	// Create transport
	trans, err := createTransport(outbound, cfg)
	if err != nil {
		log.Fatalf("[错误] Failed to create transport: %v", err)
	}

	// Determine inbound type
	if len(cfg.Inbounds) == 0 {
		log.Fatalf("[错误] No inbound configured")
	}

	inbound := cfg.Inbounds[0]
	log.Printf("[入站] Tag: %s, Type: %s", inbound.Tag, inbound.Type)

	// Start based on inbound type
	switch inbound.Type {
	case "tun":
		startTunMode(inbound, trans, cfg)
	case "mixed", "socks", "http":
		startProxyMode(inbound, trans, cfg)
	default:
		log.Fatalf("[错误] Unsupported inbound type: %s", inbound.Type)
	}
}

func createTransport(outbound option.OutboundConfig, cfg *option.RootConfig) (transport.Transport, error) {
	// Validate outbound
	if outbound.Type != "ewp" && outbound.Type != "trojan" {
		return nil, fmt.Errorf("unsupported outbound type: %s", outbound.Type)
	}

	// Determine server address
	serverAddr := net.JoinHostPort(outbound.Server, fmt.Sprint(outbound.ServerPort))
	
	// Determine authentication
	var uuid, password string
	useTrojan := outbound.Type == "trojan"
	
	if useTrojan {
		password = outbound.Password
		log.Printf("[协议] Using Trojan protocol")
	} else {
		uuid = outbound.UUID
		log.Printf("[协议] Using EWP protocol (UUID: %s)", uuid)
	}

	// Get bootstrap DNS configuration
	bootstrapDNS := ""
	if cfg.DNS != nil && cfg.DNS.Bootstrap != "" {
		bootstrapDNS = cfg.DNS.Bootstrap
		log.Printf("[DNS] Using bootstrap DNS: %s", bootstrapDNS)
	}

	// Initialize ECH manager
	var echMgr *tls.ECHManager
	useECH := outbound.TLS != nil && outbound.TLS.ECH != nil && outbound.TLS.ECH.Enabled
	
	if useECH {
		echDomain := outbound.TLS.ECH.ConfigDomain
		dohServer := outbound.TLS.ECH.DOHServer
		
		if echDomain == "" {
			echDomain = "cloudflare-ech.com"
		}
		if dohServer == "" {
			// Use IP address to avoid DNS dependency (Alibaba Cloud DNS)
			dohServer = "https://223.5.5.5/dns-query"
		}

		log.Printf("[ECH] Initializing (domain: %s, DoH: %s)", echDomain, dohServer)
		echMgr = tls.NewECHManager(echDomain, dohServer)
		
		if err := echMgr.Refresh(); err != nil {
			if outbound.TLS.ECH.FallbackOnError {
				log.Printf("[警告] ECH initialization failed, falling back to plain TLS: %v", err)
				useECH = false
				echMgr = nil
			} else {
				return nil, fmt.Errorf("ECH initialization failed: %w", err)
			}
		}
	}

	// Get transport config
	if outbound.Transport == nil {
		return nil, fmt.Errorf("transport configuration is required")
	}

	transportType := outbound.Transport.Type
	enableFlow := outbound.Flow != nil && outbound.Flow.Enabled
	enablePQC := outbound.TLS != nil && outbound.TLS.PQC

	log.Printf("[传输] Type: %s, Flow: %v, ECH: %v, PQC: %v", 
		transportType, enableFlow, useECH, enablePQC)

	// Create transport based on type
	var trans transport.Transport
	var err error

	switch transportType {
	case "ws":
		path := outbound.Transport.Path
		if path == "" {
			path = "/"
		}
		trans, err = websocket.NewWithProtocolAndBootstrap(
			serverAddr, outbound.ServerIP, uuid, password,
			useECH, enableFlow, enablePQC, useTrojan,
			path, echMgr, bootstrapDNS,
		)
		if err != nil {
			return nil, err
		}

	case "grpc":
		serviceName := outbound.Transport.ServiceName
		if serviceName == "" {
			serviceName = "ProxyService"
		}
		grpcTrans, err := grpc.NewWithProtocolAndBootstrap(
			serverAddr, outbound.ServerIP, uuid, password,
			useECH, enableFlow, enablePQC, useTrojan,
			serviceName, echMgr, bootstrapDNS,
		)
		if err != nil {
			return nil, err
		}
		
		// Apply anti-DPI settings from config
		if outbound.Transport.UserAgent != "" {
			grpcTrans.SetUserAgent(outbound.Transport.UserAgent)
		}
		if outbound.Transport.ContentType != "" {
			grpcTrans.SetContentType(outbound.Transport.ContentType)
		}
		trans = grpcTrans

	case "h3grpc":
		serviceName := outbound.Transport.ServiceName
		if serviceName == "" {
			serviceName = "ProxyService"
		}
		h3Trans, err := h3grpc.NewWithProtocolAndBootstrap(
			serverAddr, outbound.ServerIP, uuid, password,
			useECH, enableFlow, enablePQC, useTrojan,
			serviceName, echMgr, bootstrapDNS,
		)
		if err != nil {
			return nil, err
		}
		
		// Apply anti-DPI settings from config
		if outbound.Transport.UserAgent != "" {
			h3Trans.SetUserAgent(outbound.Transport.UserAgent)
		}
		if outbound.Transport.ContentType != "" {
			h3Trans.SetContentType(outbound.Transport.ContentType)
		}
		trans = h3Trans

	case "xhttp":
		path := outbound.Transport.Path
		if path == "" {
			path = "/xhttp"
		}
		trans, err = xhttp.NewWithProtocolAndBootstrap(
			serverAddr, outbound.ServerIP, uuid, password,
			useECH, enableFlow, enablePQC, useTrojan,
			path, echMgr, bootstrapDNS,
		)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported transport type: %s", transportType)
	}

	log.Printf("[传输] Created: %s", trans.Name())
	return trans, nil
}

func startTunMode(inbound option.InboundConfig, trans transport.Transport, cfg *option.RootConfig) {
	log.Printf("[启动] Starting TUN mode...")

	if !tun.IsAdmin() {
		log.Fatalf("[错误] TUN mode requires administrator privileges")
	}

	// Parse TUN address
	tunIP := inbound.Inet4Address
	if tunIP == "" {
		tunIP = "10.0.85.2/24"
	}

	mtu := inbound.MTU
	if mtu == 0 {
		mtu = 1380
	}

	// Determine DNS server for TUN mode
	// Note: TUN mode currently only supports IP addresses (not DoH/DoT/DoQ URLs)
	// The DNS traffic will be routed through the proxy tunnel automatically
	dnsServer := "8.8.8.8"  // Default to Google Public DNS
	log.Printf("[TUN] Using DNS: %s (tunneled through proxy)", dnsServer)

	tunCfg := &tun.Config{
		IP:        tunIP,
		Gateway:   "10.0.85.1",
		Mask:      "255.255.255.0",
		DNS:       dnsServer,
		MTU:       mtu,
		Transport: trans,
	}

	tunDev, err := tun.New(tunCfg)
	if err != nil {
		log.Fatalf("[错误] TUN initialization failed: %v", err)
	}
	defer tunDev.Close()

	log.Printf("[TUN] Started (IP: %s, MTU: %d)", tunIP, mtu)
	log.Fatalf("[错误] TUN mode stopped: %v", tunDev.Start())
}

func startProxyMode(inbound option.InboundConfig, trans transport.Transport, cfg *option.RootConfig) {
	listenAddr := inbound.Listen
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}

	log.Printf("[启动] Starting %s proxy on %s", inbound.Type, listenAddr)

	// Determine DNS server for protocol module
	// Use IP address to avoid DNS dependency (Alibaba Cloud DNS)
	dnsServer := "https://223.5.5.5/dns-query"
	if cfg.DNS != nil && cfg.DNS.Final != "" {
		for _, server := range cfg.DNS.Servers {
			if server.Tag == cfg.DNS.Final {
				dnsServer = server.Address
				break
			}
		}
	}

	// Create and run proxy server
	server := protocol.NewServer(listenAddr, trans, dnsServer)
	log.Fatalf("[错误] Proxy server stopped: %v", server.Run())
}

func setupLogging(cfg *option.RootConfig) {
	// Set log level
	verbose := cfg.Log.Level == "debug"
	log.SetVerbose(verbose)

	// Set log file if specified
	if cfg.Log.File != "" {
		f, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		log.SetMultiOutput(os.Stdout, f)
	}
}
