package main

import (
	"context"
	"net/http"
	"time"

	log "ewp-core/log"
	"ewp-core/internal/server"
	"ewp-core/protocol/trojan"
	wstransport "ewp-core/transport/websocket"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != wsPath {
		disguiseHandler(w, r)
		return
	}

	proto := r.Header.Get("Sec-WebSocket-Protocol")
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
		log.Warn("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	log.Info("WebSocket connected: %s %s", r.Method, r.URL.Path)
	handleWebSocket(conn, r.RemoteAddr)
}

func handleWebSocket(conn *websocket.Conn, clientAddr string) {
	_, firstMsg, err := conn.ReadMessage()
	if err != nil {
		log.Warn("WebSocket: Failed to read first message: %v", err)
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

	opts := server.TunnelOptions{
		Protocol:  newProtocolHandler(),
		Transport: wstransport.NewServerAdapter(conn),
		ClientIP:  clientAddr,
		Timeout:   10 * time.Second,
	}
	server.EstablishTunnel(context.Background(), firstMsg, opts)
}
