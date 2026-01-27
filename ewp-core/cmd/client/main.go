package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"ewp-core/common/tls"
	"ewp-core/constant"
	"ewp-core/log"
	"ewp-core/option"
	"ewp-core/protocol"
	"ewp-core/transport"
	"ewp-core/transport/grpc"
	"ewp-core/transport/websocket"
	"ewp-core/transport/xhttp"
	"ewp-core/tun"
)

func main() {
	// Parse configuration
	cfg, err := option.ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Setup logging
	setupLogging(cfg)

	log.Printf("[启动] ECH Workers Client")
	log.Printf("[配置] Listen: %s, Server: %s", cfg.ListenAddr, cfg.ServerAddr)
	log.Printf("[配置] Mode: %s, Protocol: %s, Flow: %v, PQC: %v", cfg.ProtoMode, cfg.AppProtocol, cfg.EnableFlow, cfg.EnablePQC)

	// Determine if using Trojan protocol
	useTrojan := cfg.AppProtocol == "trojan"
	if useTrojan {
		if cfg.Password == "" {
			cfg.Password = cfg.Token // Use token as password if not specified
		}
		log.Printf("[协议] Using Trojan protocol")
	} else {
		log.Printf("[协议] Using EWP protocol")
	}

	// Initialize ECH manager if not in fallback mode
	var echMgr *tls.ECHManager
	if !cfg.Fallback {
		log.Printf("[ECH] Initializing ECH configuration...")
		echMgr = tls.NewECHManager(cfg.ECHDomain, cfg.DNSServer)
		if err := echMgr.Refresh(); err != nil {
			log.Fatalf("[ECH] Failed to initialize: %v\nTip: Use -fallback to disable ECH", err)
		}
	} else {
		log.Printf("[启动] Fallback mode enabled (plain TLS)")
	}

	// Create transport based on protocol mode
	var trans transport.Transport
	switch cfg.ProtoMode {
	case constant.TransportWebSocket:
		parsed, err := transport.ParseAddress(cfg.ServerAddr)
		if err != nil {
			log.Fatalf("[错误] Invalid server address: %v", err)
		}
		trans = websocket.NewWithProtocol(cfg.ServerAddr, cfg.ServerIP, cfg.Token, cfg.Password, !cfg.Fallback, cfg.EnableFlow, useTrojan, parsed.Path, echMgr)
		log.Printf("[传输] Using %s", trans.Name())
	case constant.TransportGRPC:
		trans = grpc.NewWithProtocol(cfg.ServerAddr, cfg.ServerIP, cfg.Token, cfg.Password, !cfg.Fallback, cfg.EnableFlow, useTrojan, "", echMgr)
		log.Printf("[传输] Using %s", trans.Name())
	case constant.TransportXHTTP:
		parsed, err := transport.ParseAddress(cfg.ServerAddr)
		if err != nil {
			log.Fatalf("[错误] Invalid server address: %v", err)
		}
		trans = xhttp.NewWithProtocol(cfg.ServerAddr, cfg.ServerIP, cfg.Token, cfg.Password, !cfg.Fallback, cfg.EnableFlow, useTrojan, parsed.Path, echMgr)
		log.Printf("[传输] Using %s", trans.Name())
	default:
		log.Fatalf("[错误] Unknown transport mode: %s", cfg.ProtoMode)
	}

	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("[信号] Received exit signal")
		// TODO: Cleanup resources
		os.Exit(0)
	}()

	// Start proxy server or TUN mode
	if cfg.TunMode {
		log.Printf("[启动] Starting TUN mode...")
		if !tun.IsAdmin() {
			log.Fatalf("[错误] TUN mode requires administrator privileges")
		}

		tunCfg := &tun.Config{
			IP:        cfg.TunIP,
			Gateway:   cfg.TunGateway,
			Mask:      cfg.TunMask,
			DNS:       cfg.TunDNS,
			MTU:       cfg.TunMTU,
			Transport: trans,
		}

		tunDev, err := tun.New(tunCfg)
		if err != nil {
			log.Fatalf("[错误] TUN initialization failed: %v", err)
		}
		defer tunDev.Close()

		log.Fatalf("[错误] TUN mode stopped: %v", tunDev.Start())
	} else {
		// Start SOCKS5/HTTP proxy server
		server := protocol.NewServer(cfg.ListenAddr, trans, cfg.DNSServer)
		log.Fatalf("[错误] Proxy server stopped: %v", server.Run())
	}
}

func setupLogging(cfg *option.Config) {
	log.SetVerbose(cfg.Verbose)

	if cfg.LogFilePath != "" {
		f, err := os.OpenFile(cfg.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		log.SetMultiOutput(os.Stdout, f)
	}
}
