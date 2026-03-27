package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"ewp-core/internal/server"
	log "ewp-core/log"
	"ewp-core/protocol/trojan"
	wstransport "ewp-core/transport/websocket"

	"github.com/lxzan/gws"
)

func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	if !isWebSocketRequest(r) {
		disguiseHandler(w, r)
		return
	}

	proto := r.Header.Get("Sec-WebSocket-Protocol")

	upgraderOpt := &gws.ServerOption{
		ReadBufferSize: 65536,
	}
	if proto != "" {
		upgraderOpt.SubProtocols = []string{proto}
		upgraderOpt.ResponseHeader = http.Header{"Sec-WebSocket-Protocol": {proto}}
	}

	adapter := wstransport.NewServerAdapter()
	upgrader := gws.NewUpgrader(adapter, upgraderOpt)

	socket, err := upgrader.Upgrade(w, r)
	if err != nil {
		log.Warn("WebSocket upgrade error: %v", err)
		return
	}
	adapter.SetSocket(socket)
	defer adapter.Close()

	go socket.ReadLoop()

	firstMsg, err := adapter.ReadFirst()
	if err != nil {
		log.Warn("WebSocket: failed to read first message: %v", err)
		return
	}

	if trojanMode {
		if len(firstMsg) < trojan.KeyLength+2+1+1+2+2 {
			log.Warn("Trojan message too short: %d bytes", len(firstMsg))
			return
		}
	} else {
		if len(firstMsg) < 15 {
			log.Warn("EWP message too short: %d bytes", len(firstMsg))
			return
		}
	}

	log.Info("WebSocket connected: %s %s", r.Method, r.URL.Path)
	opts := server.TunnelOptions{
		Protocol:  newProtocolHandler(),
		Transport: adapter,
		ClientIP:  r.RemoteAddr,
		Timeout:   10 * time.Second,
	}
	server.EstablishTunnel(context.Background(), firstMsg, opts)
}
