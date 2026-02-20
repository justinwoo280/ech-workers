package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	log "ewp-core/log"
	"ewp-core/internal/server"
	"ewp-core/protocol/trojan"
	xhttptransport "ewp-core/transport/xhttp"
)

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

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go cleanupExpiredSessions()
	log.Info("XHTTP server listening on :%s (no TLS)", port)
	log.Fatal(srv.ListenAndServe())
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
		httpError(w, http.StatusBadRequest, "Bad Request", "XHTTP invalid padding: %d (want %d-%d)", paddingLen, paddingMin, paddingMax)
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

	log.Debug("XHTTP %s %s (session=%s, seq=%s, padding=%d, ip=%s)", r.Method, r.URL.Path, sessionID, seqStr, paddingLen, clientIP)

	if r.Method == "POST" && sessionID != "" {
		xhttpUploadHandler(w, r, sessionID, seqStr)
	} else if r.Method == "GET" && sessionID != "" {
		xhttpDownloadHandler(w, r, sessionID)
	} else if sessionID == "" {
		xhttpStreamOneHandler(w, r)
	} else {
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

func setStreamResponseHeaders(w http.ResponseWriter, contentType string) http.Flusher {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	} else if sseHeaders {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		return flusher
	}
	return nil
}

func setXHTTPResponseHeaders(w http.ResponseWriter) {
	setStreamResponseHeaders(w, "")
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
				log.Info("Session expired after %s: %s (client: %s)",
					time.Since(session.createdAt).Round(time.Second), sessionID, clientIP)
			})
		case <-session.isFullyConnected:
			log.Info("Session fully connected: %s (client: %s)", sessionID, clientIP)
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
			httpError(w, http.StatusBadRequest, "Bad Request", "XHTTP stream-one: Failed to read Trojan header: %v", err)
			return
		}
		handshakeData = header
	} else {
		header := make([]byte, 15)
		if _, err := io.ReadFull(r.Body, header); err != nil {
			httpError(w, http.StatusBadRequest, "Bad Request", "XHTTP stream-one: Failed to read EWP header: %v", err)
			return
		}
		plaintextLen := binary.BigEndian.Uint16(header[13:15])
		totalLen := 15 + int(plaintextLen) + 16 + 16
		handshakeData = make([]byte, totalLen)
		copy(handshakeData[:15], header)
		if _, err := io.ReadFull(r.Body, handshakeData[15:]); err != nil {
			httpError(w, http.StatusBadRequest, "Bad Request", "XHTTP stream-one: Failed to read EWP handshake: %v", err)
			return
		}
	}

	protocol := newProtocolHandler()
	result, err := protocol.Handshake(handshakeData, clientIP)
	if err != nil {
		httpError(w, http.StatusBadRequest, "Bad Request", "XHTTP stream-one: Handshake failed: %v", err)
		if len(result.Response) > 0 {
			w.Write(result.Response)
		}
		return
	}

	log.Info("[XHTTP] stream-one: %s (user: %s) -> %s", clientIP, result.UserID, result.Target)

	if result.IsUDP {
		log.Info("[XHTTP] stream-one UDP mode")
		flusher := setStreamResponseHeaders(w, "application/octet-stream")
		if flusher == nil {
			return
		}
		if len(result.Response) > 0 {
			if _, err := w.Write(result.Response); err != nil {
				log.Warn("[XHTTP] stream-one: Failed to send handshake response: %v", err)
				return
			}
			flusher.Flush()
		}
		server.HandleUDPConnection(r.Body, &flushWriter{w: w, f: flusher})
		return
	}

	remote, err := net.Dial("tcp", result.Target)
	if err != nil {
		httpError(w, http.StatusBadGateway, "Connection failed", "XHTTP stream-one: Dial failed: %v", err)
		return
	}
	defer remote.Close()

	if len(result.InitialData) > 0 {
		if _, err := remote.Write(result.InitialData); err != nil {
			log.Warn("[XHTTP] stream-one: Write initial data error: %v", err)
			return
		}
	}

	flusher := setStreamResponseHeaders(w, "application/octet-stream")
	if flusher == nil {
		return
	}
	if len(result.Response) > 0 {
		if _, err := w.Write(result.Response); err != nil {
			log.Warn("[XHTTP] stream-one: Failed to send handshake response: %v", err)
			return
		}
		flusher.Flush()
	}

	transport := xhttptransport.NewServerAdapter(r.Body, w, flusher)
	forwarder := server.NewTunnelForwarder(transport, remote, result.FlowState)
	forwarder.Forward()

	log.Info("[XHTTP] stream-one closed: %s", result.Target)
}

func xhttpHandshakeHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
	clientIP := getClientIP(r)

	handshakeData, err := io.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusBadRequest, "Bad Request", "XHTTP handshake: Failed to read body: %v", err)
		return
	}

	req, respData, err := server.HandleEWPHandshakeBinary(handshakeData, clientIP)
	if err != nil {
		log.Warn("XHTTP handshake: EWP failed: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(respData)
		return
	}

	log.Info("XHTTP handshake OK: session=%s, target=%s, client=%s", sessionID, req.TargetAddr, clientIP)

	session := upsertSession(sessionID, clientIP)
	target := req.TargetAddr.String()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var d net.Dialer
	remote, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Warn("XHTTP handshake: Dial failed: %v", err)
		xhttpSessions.Delete(sessionID)
		if ctx.Err() == context.Canceled {
			return
		}
		http.Error(w, "Connection failed", http.StatusBadGateway)
		return
	}

	session.remote = remote
	log.Info("XHTTP session connected: %s -> %s", sessionID, target)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(respData)
}

func xhttpDownloadHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
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

	log.Debug("XHTTP stream-down: %s", sessionID)

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
	if seqStr == "0" {
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
			log.Warn("XHTTP upload read error: %v", err)
			return
		}
		if err := session.uploadQueue.Push(server.Packet{Payload: payload, Seq: seq}); err != nil {
			log.Warn("XHTTP upload queue push error: %v", err)
		}
		log.Debug("XHTTP packet uploaded: seq=%d, size=%d", seq, len(payload))
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
