package websocket

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"
	"ewp-core/transport"

	"github.com/lxzan/gws"
)

// Conn is the unified WebSocket tunnel connection for all three protocol variants
// (EWP-Simple, EWP-Flow, Trojan). It bridges gws's event-driven OnMessage API
// to the pull-based transport.TunnelConn.Read() interface via a buffered channel.
type Conn struct {
	gws.BuiltinEventHandler

	socket    *gws.Conn
	msgCh     chan *gws.Message
	closeCh   chan struct{}
	closeOnce sync.Once
	leftover  []byte
	writeMu   sync.Mutex // P2-14: Protect concurrent writes (Write + ping goroutine)

	uuid    [16]byte
	version byte
	nonce   [12]byte

	enableFlow        bool
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte

	useTrojan bool
	key       [trojan.KeyLength]byte

	udpGlobalID     [8]byte
	heartbeatPeriod time.Duration
	earlyDataLength int
	earlyDataSent   bool

	// P1-UDP-OPT: 可重用缓冲区用于 WriteUDP（零分配热路径）
	udpWriteBuf []byte
	udpWriteMu  sync.Mutex
}

func newConn(uuid [16]byte, password string, enableFlow, useTrojan bool) *Conn {
	c := &Conn{
		msgCh:      make(chan *gws.Message, 16),
		closeCh:    make(chan struct{}),
		uuid:       uuid,
		enableFlow: enableFlow,
		useTrojan:  useTrojan,
	}
	if useTrojan {
		c.key = trojan.GenerateKey(password)
	}
	return c
}

// --- gws.Event callbacks ---

func (c *Conn) OnClose(socket *gws.Conn, err error) {
	c.closeOnce.Do(func() { close(c.closeCh) })
}

func (c *Conn) OnPing(socket *gws.Conn, payload []byte) {
	// P2-14: Protect concurrent writes
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = socket.WritePong(payload)
}

func (c *Conn) OnMessage(socket *gws.Conn, message *gws.Message) {
	select {
	case c.msgCh <- message:
	case <-c.closeCh:
		message.Close()
	}
}

// --- transport.TunnelConn ---

func (c *Conn) Read(buf []byte) (int, error) {
	if len(c.leftover) > 0 {
		n := copy(buf, c.leftover)
		c.leftover = c.leftover[n:]
		if len(c.leftover) == 0 {
			c.leftover = nil
		}
		return n, nil
	}
	select {
	case msg, ok := <-c.msgCh:
		if !ok {
			return 0, io.EOF
		}
		data := msg.Bytes()
		if c.enableFlow && c.flowState != nil {
			data = c.flowState.ProcessDownlink(data)
		}
		n := copy(buf, data)
		if n < len(data) {
			c.leftover = append(c.leftover[:0], data[n:]...)
		}
		msg.Close()
		return n, nil
	case <-c.closeCh:
		return 0, io.EOF
	}
}

func (c *Conn) Write(data []byte) error {
	// P2-14: Protect concurrent writes (Write + ping goroutine)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	
	if c.enableFlow && c.flowState != nil {
		data = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	}
	return c.socket.WriteMessage(gws.OpcodeBinary, data)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		_ = c.socket.WriteClose(1000, nil)
	})
	return nil
}

func (c *Conn) StartPing(interval time.Duration) chan struct{} {
	if c.heartbeatPeriod > 0 {
		interval = c.heartbeatPeriod
	}
	if interval == 0 {
		return make(chan struct{})
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				// P2-14: Protect concurrent writes
				c.writeMu.Lock()
				_ = c.socket.WritePing(nil)
				c.writeMu.Unlock()
			case <-stop:
				return
			case <-c.closeCh:
				return
			}
		}
	}()
	return stop
}

func (c *Conn) SetEarlyData(length int)            { c.earlyDataLength = length }
func (c *Conn) SetHeartbeat(period time.Duration)  { c.heartbeatPeriod = period }

// --- Connect (TCP) ---

func (c *Conn) Connect(target string, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojan(target, initialData)
	}
	return c.connectEWP(target, initialData)
}

func (c *Conn) connectEWP(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}
	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)
	c.version = req.Version
	c.nonce = req.Nonce

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	if c.earlyDataLength > 0 && len(initialData) > 0 && len(initialData) <= c.earlyDataLength && !c.earlyDataSent {
		if err := c.socket.Writev(gws.OpcodeBinary, handshakeData, initialData); err != nil {
			return fmt.Errorf("send handshake+early data: %w", err)
		}
		c.earlyDataSent = true
	} else {
		if err := c.socket.WriteMessage(gws.OpcodeBinary, handshakeData); err != nil {
			return fmt.Errorf("send handshake: %w", err)
		}
	}

	select {
	case msg, ok := <-c.msgCh:
		if !ok {
			return fmt.Errorf("connection closed during handshake")
		}
		resp, err := ewp.DecodeHandshakeResponse(msg.Bytes(), c.version, c.nonce, c.uuid)
		msg.Close()
		if err != nil {
			return fmt.Errorf("decode handshake response: %w", err)
		}
		if resp.Status != ewp.StatusOK {
			return fmt.Errorf("handshake failed: status=%d", resp.Status)
		}
	case <-c.closeCh:
		return fmt.Errorf("connection closed during handshake")
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}
	if len(initialData) > 0 && !c.earlyDataSent {
		if err := c.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}
	log.V("[EWP] WS TCP handshake ok: %s", target)
	return nil
}

func (c *Conn) connectTrojan(target string, initialData []byte) error {
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return err
	}
	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}
	buf := make([]byte, 0, trojan.KeyLength+2+1+len(addrBytes)+2+len(initialData))
	buf = append(buf, c.key[:]...)
	buf = append(buf, trojan.CRLF...)
	buf = append(buf, trojan.CommandTCP)
	buf = append(buf, addrBytes...)
	buf = append(buf, trojan.CRLF...)
	if len(initialData) > 0 {
		buf = append(buf, initialData...)
	}
	if err := c.socket.WriteMessage(gws.OpcodeBinary, buf); err != nil {
		return err
	}
	log.V("[Trojan] WS TCP handshake sent: %s", target)
	return nil
}

// --- ConnectUDP ---

func (c *Conn) ConnectUDP(target transport.Endpoint, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojanUDP(target, initialData)
	}
	return c.connectEWPUDP(target, initialData)
}

func (c *Conn) connectEWPUDP(target transport.Endpoint, initialData []byte) error {
	var addr ewp.Address
	if target.Domain != "" {
		addr = ewp.Address{Type: ewp.AddressTypeDomain, Host: target.Domain, Port: target.Port}
	} else {
		addr = ewp.AddressFromAddrPort(target.Addr)
	}
	
	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)
	c.version = req.Version
	c.nonce = req.Nonce

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}
	if err := c.socket.WriteMessage(gws.OpcodeBinary, handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	select {
	case msg, ok := <-c.msgCh:
		if !ok {
			return fmt.Errorf("connection closed during UDP handshake")
		}
		resp, err := ewp.DecodeHandshakeResponse(msg.Bytes(), c.version, c.nonce, c.uuid)
		msg.Close()
		if err != nil {
			return fmt.Errorf("decode UDP handshake response: %w", err)
		}
		if resp.Status != ewp.StatusOK {
			return fmt.Errorf("UDP handshake failed: status=%d", resp.Status)
		}
	case <-c.closeCh:
		return fmt.Errorf("connection closed during UDP handshake")
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	c.udpGlobalID = ewp.NewGlobalID()

	var encoded []byte
	if target.Domain != "" {
		// Domain target: send domain directly to server, avoid local DNS resolution.
		// In TUN mode, local DNS would return a FakeIP which the server cannot route.
		pkt := &ewp.UDPPacketDomain{
			GlobalID: c.udpGlobalID,
			Status:   ewp.UDPStatusNew,
			Domain:   target.Domain,
			Port:     target.Port,
			Payload:  initialData,
		}
		var encErr error
		encoded, encErr = ewp.EncodeUDPDomainPacket(pkt)
		if encErr != nil {
			return fmt.Errorf("encode UDP domain new packet: %w", encErr)
		}
	} else {
		pkt := &ewp.UDPPacketAddr{
			GlobalID: c.udpGlobalID,
			Status:   ewp.UDPStatusNew,
			Target:   target.Addr,
			Payload:  initialData,
		}
		var encErr error
		encoded, encErr = ewp.EncodeUDPAddrPacket(pkt)
		if encErr != nil {
			return fmt.Errorf("encode UDP new packet: %w", encErr)
		}
	}
	if err := c.Write(encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
	}
	log.V("[EWP] WS UDP handshake ok: %v", target)
	return nil
}

func (c *Conn) connectTrojanUDP(target transport.Endpoint, initialData []byte) error {
	addrLen := 7
	if target.Domain != "" {
		addrLen = 1 + 1 + len(target.Domain) + 2
	} else if target.Addr.Addr().Is6() {
		addrLen = 19
	}
	buf := make([]byte, 0, trojan.KeyLength+2+1+addrLen+2)
	buf = append(buf, c.key[:]...)
	buf = append(buf, trojan.CRLF...)
	buf = append(buf, trojan.CommandUDP)
	if target.Domain != "" {
		buf = append(buf, trojan.AddressTypeDomain, byte(len(target.Domain)))
		buf = append(buf, []byte(target.Domain)...)
		buf = append(buf, byte(target.Port>>8), byte(target.Port))
	} else {
		buf = trojan.AppendAddrPort(buf, target.Addr)
	}
	buf = append(buf, trojan.CRLF...)
	if err := c.socket.WriteMessage(gws.OpcodeBinary, buf); err != nil {
		return err
	}
	log.V("[Trojan] WS UDP handshake sent: %v", target)
	return nil
}

// --- WriteUDP ---

func (c *Conn) WriteUDP(target transport.Endpoint, data []byte) error {
	c.udpWriteMu.Lock()
	defer c.udpWriteMu.Unlock()

	if c.useTrojan {
		return c.writeTrojanUDPPooled(target, data)
	}

	// P1-UDP-OPT: 计算所需容量并确保缓冲区足够大
	requiredCap := 2 + 8 + 1 + 1 + 19 + 2 + len(data) // 最大尺寸（IPv6）
	if target.Domain != "" {
		requiredCap = 2 + 8 + 1 + 1 + (1 + 1 + len(target.Domain) + 2) + 2 + len(data)
	}

	// 仅在需要时增长缓冲区（首次调用或大包）
	if cap(c.udpWriteBuf) < requiredCap {
		c.udpWriteBuf = make([]byte, 0, requiredCap)
	}

	// 重置缓冲区并追加帧
	c.udpWriteBuf = c.udpWriteBuf[:0]

	if target.Domain != "" {
		// Domain target: send domain directly to server, avoid local DNS resolution.
		// In TUN mode, local DNS would return a FakeIP which the server cannot route.
		c.udpWriteBuf = ewp.AppendUDPDomainFrame(
			c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep,
			target.Domain, target.Port, data,
		)
	} else {
		c.udpWriteBuf = ewp.AppendUDPAddrFrame(
			c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep,
			target.Addr, data,
		)
	}

	return c.Write(c.udpWriteBuf)
}

func (c *Conn) writeTrojanUDPPooled(target transport.Endpoint, data []byte) error {
	// P1-UDP-OPT: 使用可重用缓冲区
	length := uint16(len(data))
	addrLen := 7
	if target.Domain != "" {
		addrLen = 1 + 1 + len(target.Domain) + 2
	} else if target.Addr.Addr().Is6() {
		addrLen = 19
	}

	requiredCap := addrLen + 4 + len(data)
	if cap(c.udpWriteBuf) < requiredCap {
		c.udpWriteBuf = make([]byte, 0, requiredCap)
	}

	c.udpWriteBuf = c.udpWriteBuf[:0]

	if target.Domain != "" {
		c.udpWriteBuf = append(c.udpWriteBuf, trojan.AddressTypeDomain, byte(len(target.Domain)))
		c.udpWriteBuf = append(c.udpWriteBuf, []byte(target.Domain)...)
		c.udpWriteBuf = append(c.udpWriteBuf, byte(target.Port>>8), byte(target.Port))
	} else {
		c.udpWriteBuf = trojan.AppendAddrPort(c.udpWriteBuf, target.Addr)
	}
	c.udpWriteBuf = append(c.udpWriteBuf, byte(length>>8), byte(length))
	c.udpWriteBuf = append(c.udpWriteBuf, trojan.CRLF...)
	c.udpWriteBuf = append(c.udpWriteBuf, data...)

	return c.socket.WriteMessage(gws.OpcodeBinary, c.udpWriteBuf)
}

// --- ReadUDP ---

func (c *Conn) ReadUDP() ([]byte, error) {
	select {
	case msg, ok := <-c.msgCh:
		if !ok {
			return nil, io.EOF
		}
		data := msg.Bytes()
		var result []byte
		var err error
		if c.useTrojan {
			result, err = decodeTrojanUDP(data)
		} else {
			if c.enableFlow && c.flowState != nil {
				data = c.flowState.ProcessDownlink(data)
			}
			result, err = ewp.DecodeUDPPayload(data)
		}
		msg.Close()
		return result, err
	case <-c.closeCh:
		return nil, io.EOF
	}
}

func (c *Conn) ReadUDPTo(buf []byte) (int, error) {
	payload, err := c.ReadUDP()
	if err != nil {
		return 0, err
	}
	return copy(buf, payload), nil
}

func (c *Conn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	select {
	case msg, ok := <-c.msgCh:
		if !ok {
			return 0, netip.AddrPort{}, io.EOF
		}
		data := msg.Bytes()
		var n int
		var addr netip.AddrPort
		var err error
		if c.useTrojan {
			var payload []byte
			payload, addr, err = decodeTrojanUDPWithAddr(data)
			if err == nil {
				n = copy(buf, payload)
			}
		} else {
			if c.enableFlow && c.flowState != nil {
				data = c.flowState.ProcessDownlink(data)
			}
			n, addr, err = ewp.DecodeUDPAddrPayloadTo(data, buf)
		}
		msg.Close()
		return n, addr, err
	case <-c.closeCh:
		return 0, netip.AddrPort{}, io.EOF
	}
}

func decodeTrojanUDP(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty trojan udp payload")
	}
	offset := 1
	var addrLen int
	switch data[0] {
	case trojan.AddressTypeIPv4:
		addrLen = 4
	case trojan.AddressTypeIPv6:
		addrLen = 16
	case trojan.AddressTypeDomain:
		if len(data) < 2 {
			return nil, fmt.Errorf("truncated trojan domain")
		}
		addrLen = int(data[1])
		offset++
	default:
		return nil, fmt.Errorf("unknown trojan address type: %d", data[0])
	}
	headerLen := offset + addrLen + 2
	if len(data) < headerLen+4 {
		return nil, fmt.Errorf("truncated trojan udp header")
	}
	payloadLen := int(data[headerLen])<<8 | int(data[headerLen+1])
	payloadStart := headerLen + 4
	if len(data) < payloadStart+payloadLen {
		return nil, fmt.Errorf("truncated trojan udp payload")
	}
	return data[payloadStart : payloadStart+payloadLen], nil
}

func decodeTrojanUDPWithAddr(data []byte) ([]byte, netip.AddrPort, error) {
	if len(data) < 1 {
		return nil, netip.AddrPort{}, fmt.Errorf("empty trojan udp payload")
	}
	offset := 1
	var addrLen int
	var remoteAddr netip.AddrPort

	switch data[0] {
	case trojan.AddressTypeIPv4:
		addrLen = 4
		if len(data) >= offset+addrLen+2 {
			ip := netip.AddrFrom4(*(*[4]byte)(data[offset : offset+addrLen]))
			port := binary.BigEndian.Uint16(data[offset+addrLen : offset+addrLen+2])
			remoteAddr = netip.AddrPortFrom(ip, port)
		}
	case trojan.AddressTypeIPv6:
		addrLen = 16
		if len(data) >= offset+addrLen+2 {
			ip := netip.AddrFrom16(*(*[16]byte)(data[offset : offset+addrLen]))
			port := binary.BigEndian.Uint16(data[offset+addrLen : offset+addrLen+2])
			remoteAddr = netip.AddrPortFrom(ip, port)
		}
	case trojan.AddressTypeDomain:
		if len(data) < 2 {
			return nil, netip.AddrPort{}, fmt.Errorf("truncated trojan domain")
		}
		addrLen = int(data[1])
		offset++
	default:
		return nil, netip.AddrPort{}, fmt.Errorf("unknown trojan address type: %d", data[0])
	}
	
	headerLen := offset + addrLen + 2
	if len(data) < headerLen+4 {
		return nil, netip.AddrPort{}, fmt.Errorf("truncated trojan udp header")
	}
	
	payloadLen := int(data[headerLen])<<8 | int(data[headerLen+1])
	payloadStart := headerLen + 4
	
	if len(data) < payloadStart+payloadLen {
		return nil, netip.AddrPort{}, fmt.Errorf("truncated trojan udp payload")
	}
	return data[payloadStart : payloadStart+payloadLen], remoteAddr, nil
}
