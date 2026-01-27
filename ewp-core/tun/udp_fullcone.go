package tun

import (
	"io"
	"net"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
	"ewp-core/transport"
)

type UDPResponseCallback func(src, dst *net.UDPAddr, payload []byte)

type UDPConnectionHandler struct {
	sync.Mutex
	conns            map[string]*UDPProxyConn
	transport        transport.Transport
	sessionManager   *ewp.UDPSessionManager
	cleanupInterval  time.Duration
	connTimeout      time.Duration
	responseCallback UDPResponseCallback
}

type UDPProxyConn struct {
	handler    *UDPConnectionHandler
	srcAddr    *net.UDPAddr
	globalID   [8]byte
	tunnel     transport.TunnelConn
	egress     chan *ewp.UDPPacket
	lastActive time.Time
	closed     bool
	mu         sync.Mutex
}

func NewUDPConnectionHandler(trans transport.Transport, callback UDPResponseCallback) *UDPConnectionHandler {
	h := &UDPConnectionHandler{
		conns:            make(map[string]*UDPProxyConn),
		transport:        trans,
		sessionManager:   ewp.NewUDPSessionManager(),
		cleanupInterval:  30 * time.Second,
		connTimeout:      2 * time.Minute,
		responseCallback: callback,
	}
	go h.cleanupLoop()
	return h
}

func (h *UDPConnectionHandler) HandlePacket(src *net.UDPAddr, dst *net.UDPAddr, data []byte) error {
	srcKey := src.String()

	h.Lock()
	conn, exists := h.conns[srcKey]
	if !exists {
		conn = &UDPProxyConn{
			handler:    h,
			srcAddr:    src,
			globalID:   ewp.GenerateGlobalID(src),
			egress:     make(chan *ewp.UDPPacket, 64),
			lastActive: time.Now(),
		}
		h.conns[srcKey] = conn
		h.Unlock()

		go conn.run()
	} else {
		h.Unlock()
	}

	conn.mu.Lock()
	conn.lastActive = time.Now()
	conn.mu.Unlock()

	pkt := &ewp.UDPPacket{
		GlobalID: conn.globalID,
		Status:   ewp.UDPStatusKeep,
		Target:   dst,
		Payload:  data,
	}

	if !exists {
		pkt.Status = ewp.UDPStatusNew
	}

	select {
	case conn.egress <- pkt:
	default:
		log.V("[UDP-FC] Queue full, dropping packet: %s -> %s", src, dst)
	}

	return nil
}

func (c *UDPProxyConn) run() {
	defer c.close()

	tunnel, err := c.handler.transport.Dial()
	if err != nil {
		log.Printf("[UDP-FC] Establish tunnel failed: %v", err)
		return
	}
	c.tunnel = tunnel

	udpTarget := "udp://0.0.0.0:0"
	if err := tunnel.Connect(udpTarget, nil); err != nil {
		log.Printf("[UDP-FC] Connection failed: %v", err)
		return
	}

	log.V("[UDP-FC] Connection established: %s (GlobalID: %x)", c.srcAddr, c.globalID[:4])

	go c.readLoop()

	c.writeLoop()
}

func (c *UDPProxyConn) writeLoop() {
	for pkt := range c.egress {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		data, err := ewp.EncodeUDPPacket(pkt)
		if err != nil {
			log.Printf("[UDP-FC] Encode failed: %v", err)
			continue
		}

		if err := c.tunnel.Write(data); err != nil {
			log.Printf("[UDP-FC] Send failed: %v", err)
			return
		}
	}
}

func (c *UDPProxyConn) readLoop() {
	buf := make([]byte, 65536)
	reader := &tunnelReader{tunnel: c.tunnel, buf: buf}

	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		pkt, err := ewp.DecodeUDPPacket(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("[UDP-FC] Decode failed: %v", err)
			}
			return
		}

		c.sendToClient(pkt)
	}
}

func (c *UDPProxyConn) sendToClient(pkt *ewp.UDPPacket) {
	if pkt.Target == nil || len(pkt.Payload) == 0 {
		return
	}

	if c.handler.responseCallback != nil {
		c.handler.responseCallback(pkt.Target, c.srcAddr, pkt.Payload)
	}

	log.V("[UDP-FC] Received response: %s -> %s (%d bytes)", pkt.Target, c.srcAddr, len(pkt.Payload))
}

func (c *UDPProxyConn) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()

	close(c.egress)
	if c.tunnel != nil {
		c.tunnel.Close()
	}

	c.handler.Lock()
	delete(c.handler.conns, c.srcAddr.String())
	c.handler.Unlock()

	log.V("[UDP-FC] Connection closed: %s", c.srcAddr)
}

func (h *UDPConnectionHandler) cleanupLoop() {
	ticker := time.NewTicker(h.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		h.Lock()
		now := time.Now()
		var toDelete []string
		for key, conn := range h.conns {
			conn.mu.Lock()
			if now.Sub(conn.lastActive) > h.connTimeout {
				toDelete = append(toDelete, key)
			}
			conn.mu.Unlock()
		}
		h.Unlock()

		for _, key := range toDelete {
			h.Lock()
			if conn, exists := h.conns[key]; exists {
				go conn.close()
			}
			h.Unlock()
		}
	}
}

func (h *UDPConnectionHandler) Close() {
	h.Lock()
	defer h.Unlock()

	for _, conn := range h.conns {
		go conn.close()
	}
	h.conns = make(map[string]*UDPProxyConn)
}

type tunnelReader struct {
	tunnel transport.TunnelConn
	buf    []byte
	data   []byte
	pos    int
}

func (r *tunnelReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		n, err := r.tunnel.Read(r.buf)
		if err != nil {
			return 0, err
		}
		r.data = r.buf[:n]
		r.pos = 0
	}

	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
