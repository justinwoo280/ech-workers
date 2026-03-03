package ewp

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// UDP over TCP 封装协议 (基于 Xray XUDP 简化实现)
//
// 帧格式:
// ┌─────────────────────────────────────────────────────────┐
// │ FrameLen(2) │ GlobalID(8) │ Status(1) │ AddrLen(1)     │
// ├─────────────────────────────────────────────────────────┤
// │ Address(n) │ Port(2) │ PayloadLen(2) │ Payload(n)      │
// └─────────────────────────────────────────────────────────┘
//
// Status:
//
//	0x01 = New  (新连接，AddrLen>0，包含目标地址)
//	0x02 = Keep (持续数据，AddrLen 可选；服务端回包时携带响应来源地址)
//	0x03 = End  (关闭连接)
const (
	UDPStatusNew  byte = 0x01
	UDPStatusKeep byte = 0x02
	UDPStatusEnd  byte = 0x03

	MaxUDPPacketSize = 65507
	// 最大帧体大小: GlobalID(8)+Status(1)+AddrLen(1)+IPv6addr(19)+PayloadLen(2)+payload(65507)
	udpFramePoolMax = 8 + 1 + 1 + 19 + 2 + MaxUDPPacketSize
)

// UDPPacket 表示一个 UDP 数据包
type UDPPacket struct {
	GlobalID [8]byte
	Status   byte
	Target   *net.UDPAddr
	Payload  []byte
}

// UDPPacketAddr 表示一个 UDP 数据包 (零堆分配 netip.AddrPort 版本)
type UDPPacketAddr struct {
	GlobalID [8]byte
	Status   byte
	Target   netip.AddrPort
	Payload  []byte
}

// udpFramePool 复用帧读取缓冲区，减少 DecodeUDPPacket 的堆分配。
// 帧内容在 decode 后只有 Payload 需要存活；其余字段已被解析为值类型。
var udpFramePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, udpFramePoolMax)
		return &b
	},
}

// EncodeUDPPacket 编码 UDP 包为字节流。
// 优化：直接将 IP 写入输出 buf，消除 addrBytes 中间分配。
func EncodeUDPPacket(pkt *UDPPacket) ([]byte, error) {
	addrLen := 0
	addrType := byte(0)
	var ip4 net.IP
	var ip6 net.IP

	if pkt.Target != nil {
		if v4 := pkt.Target.IP.To4(); v4 != nil {
			ip4 = v4
			addrLen = 7 // type(1) + ip4(4) + port(2)
			addrType = AddressTypeIPv4
		} else if v6 := pkt.Target.IP.To16(); v6 != nil {
			ip6 = v6
			addrLen = 19 // type(1) + ip6(16) + port(2)
			addrType = AddressTypeIPv6
		} else {
			return nil, errors.New("invalid target IP")
		}
	}

	payloadLen := len(pkt.Payload)
	// frameLen = GlobalID(8) + Status(1) + AddrLen(1) + addr(n) + PayloadLen(2) + payload(n)
	frameLen := 8 + 1 + 1 + addrLen + 2 + payloadLen
	totalLen := 2 + frameLen

	out := make([]byte, totalLen)
	binary.BigEndian.PutUint16(out[0:2], uint16(frameLen))
	copy(out[2:10], pkt.GlobalID[:])
	out[10] = pkt.Status
	out[11] = byte(addrLen)

	off := 12
	if addrLen > 0 {
		out[off] = addrType
		off++
		if addrType == AddressTypeIPv4 {
			copy(out[off:off+4], ip4)
			off += 4
		} else {
			copy(out[off:off+16], ip6)
			off += 16
		}
		binary.BigEndian.PutUint16(out[off:off+2], uint16(pkt.Target.Port))
		off += 2
	}

	binary.BigEndian.PutUint16(out[off:off+2], uint16(payloadLen))
	off += 2
	if payloadLen > 0 {
		copy(out[off:], pkt.Payload)
	}

	return out, nil
}

// EncodeUDPAddrPacket 编码 UDP 包为字节流 (零堆分配 netip.AddrPort 版本)
func EncodeUDPAddrPacket(pkt *UDPPacketAddr) ([]byte, error) {
	addrLen := 0
	addrType := byte(0)
	var ip4 [4]byte
	var ip6 [16]byte

	if pkt.Target.IsValid() {
		if pkt.Target.Addr().Is4() {
			ip4 = pkt.Target.Addr().As4()
			addrLen = 7 // type(1) + ip4(4) + port(2)
			addrType = AddressTypeIPv4
		} else if pkt.Target.Addr().Is6() {
			ip6 = pkt.Target.Addr().As16()
			addrLen = 19 // type(1) + ip6(16) + port(2)
			addrType = AddressTypeIPv6
		} else {
			return nil, errors.New("invalid target IP format")
		}
	}

	payloadLen := len(pkt.Payload)
	// frameLen = GlobalID(8) + Status(1) + AddrLen(1) + addr(n) + PayloadLen(2) + payload(n)
	frameLen := 8 + 1 + 1 + addrLen + 2 + payloadLen
	totalLen := 2 + frameLen

	out := make([]byte, totalLen)
	binary.BigEndian.PutUint16(out[0:2], uint16(frameLen))
	copy(out[2:10], pkt.GlobalID[:])
	out[10] = pkt.Status
	out[11] = byte(addrLen)

	off := 12
	if addrLen > 0 {
		out[off] = addrType
		off++
		if addrType == AddressTypeIPv4 {
			copy(out[off:off+4], ip4[:])
			off += 4
		} else {
			copy(out[off:off+16], ip6[:])
			off += 16
		}
		binary.BigEndian.PutUint16(out[off:off+2], pkt.Target.Port())
		off += 2
	}

	binary.BigEndian.PutUint16(out[off:off+2], uint16(payloadLen))
	off += 2
	if payloadLen > 0 {
		copy(out[off:], pkt.Payload)
	}

	return out, nil
}

// DecodeUDPPacket 从 reader 解码 UDP 包。
// 优化：lenBuf 在栈上分配；frameBuf 来自 sync.Pool 减少 GC 压力。
func DecodeUDPPacket(r io.Reader) (*UDPPacket, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))

	if frameLen < 11 {
		return nil, errors.New("frame too short")
	}

	// 从 pool 取帧缓冲（若帧超过 pool 最大值则降级分配）
	var frameBuf []byte
	var poolBufPtr *[]byte
	if frameLen <= udpFramePoolMax {
		poolBufPtr = udpFramePool.Get().(*[]byte)
		frameBuf = (*poolBufPtr)[:frameLen]
	} else {
		frameBuf = make([]byte, frameLen)
	}

	_, err := io.ReadFull(r, frameBuf)
	if err != nil {
		if poolBufPtr != nil {
			udpFramePool.Put(poolBufPtr)
		}
		return nil, err
	}

	pkt := &UDPPacket{}
	copy(pkt.GlobalID[:], frameBuf[0:8])
	pkt.Status = frameBuf[8]
	addrLen := int(frameBuf[9])

	offset := 10

	if addrLen > 0 {
		if offset+addrLen > len(frameBuf) {
			if poolBufPtr != nil {
				udpFramePool.Put(poolBufPtr)
			}
			return nil, errors.New("truncated address")
		}
		addrData := frameBuf[offset : offset+addrLen]
		offset += addrLen

		if len(addrData) < 1 {
			if poolBufPtr != nil {
				udpFramePool.Put(poolBufPtr)
			}
			return nil, errors.New("empty address data")
		}

		addrType := addrData[0]
		switch addrType {
		case AddressTypeIPv4:
			if len(addrData) < 7 {
				if poolBufPtr != nil {
					udpFramePool.Put(poolBufPtr)
				}
				return nil, errors.New("truncated IPv4 address")
			}
			// Copy IP bytes so they are independent of the pool buffer.
			ip := make(net.IP, 4)
			copy(ip, addrData[1:5])
			port := binary.BigEndian.Uint16(addrData[5:7])
			pkt.Target = &net.UDPAddr{IP: ip, Port: int(port)}

		case AddressTypeIPv6:
			if len(addrData) < 19 {
				if poolBufPtr != nil {
					udpFramePool.Put(poolBufPtr)
				}
				return nil, errors.New("truncated IPv6 address")
			}
			ip := make(net.IP, 16)
			copy(ip, addrData[1:17])
			port := binary.BigEndian.Uint16(addrData[17:19])
			pkt.Target = &net.UDPAddr{IP: ip, Port: int(port)}

		default:
			if poolBufPtr != nil {
				udpFramePool.Put(poolBufPtr)
			}
			return nil, errors.New("unsupported address type for UDP")
		}
	}

	if offset+2 > len(frameBuf) {
		if poolBufPtr != nil {
			udpFramePool.Put(poolBufPtr)
		}
		return nil, errors.New("truncated payload length")
	}
	payloadLen := int(binary.BigEndian.Uint16(frameBuf[offset : offset+2]))
	offset += 2

	if payloadLen > 0 {
		if offset+payloadLen > len(frameBuf) {
			if poolBufPtr != nil {
				udpFramePool.Put(poolBufPtr)
			}
			return nil, errors.New("truncated payload")
		}
		// Payload must be copied out before returning the pool buffer.
		pkt.Payload = make([]byte, payloadLen)
		copy(pkt.Payload, frameBuf[offset:offset+payloadLen])
	}

	if poolBufPtr != nil {
		udpFramePool.Put(poolBufPtr)
	}
	return pkt, nil
}

// UDPSession 管理 UDP 会话 (Full-Cone NAT)
type UDPSession struct {
	GlobalID   [8]byte
	LocalAddr  *net.UDPAddr
	RemoteConn *net.UDPConn
	LastTarget *net.UDPAddr
	LastActive time.Time
	mu         sync.Mutex
}

func (s *UDPSession) Lock()   { s.mu.Lock() }
func (s *UDPSession) Unlock() { s.mu.Unlock() }

// UDPSessionManager 管理所有 UDP 会话 (服务端使用)
type UDPSessionManager struct {
	sessions map[[8]byte]*UDPSession
	mu       sync.RWMutex
}

func NewUDPSessionManager() *UDPSessionManager {
	return &UDPSessionManager{
		sessions: make(map[[8]byte]*UDPSession),
	}
}

func (m *UDPSessionManager) Touch(globalID [8]byte) {
	m.mu.RLock()
	session := m.sessions[globalID]
	m.mu.RUnlock()
	if session != nil {
		session.Lock()
		session.LastActive = time.Now()
		session.Unlock()
	}
}

func (m *UDPSessionManager) CloseIdle(idleTimeout time.Duration) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, session := range m.sessions {
		session.Lock()
		idle := !session.LastActive.IsZero() && now.Sub(session.LastActive) > idleTimeout
		session.Unlock()
		if idle {
			if session.RemoteConn != nil {
				session.RemoteConn.Close()
			}
			delete(m.sessions, id)
		}
	}
}

func (m *UDPSessionManager) GetOrCreate(globalID [8]byte) (*UDPSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[globalID]; exists {
		return session, false
	}

	session := &UDPSession{GlobalID: globalID}
	m.sessions[globalID] = session
	return session, true
}

func (m *UDPSessionManager) Get(globalID [8]byte) *UDPSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[globalID]
}

func (m *UDPSessionManager) Remove(globalID [8]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[globalID]; exists {
		if session.RemoteConn != nil {
			session.RemoteConn.Close()
		}
		delete(m.sessions, globalID)
	}
}

func (m *UDPSessionManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, session := range m.sessions {
		if session.RemoteConn != nil {
			session.RemoteConn.Close()
		}
	}
	m.sessions = make(map[[8]byte]*UDPSession)
}

// globalIDBaseKey 用于 GlobalID 生成的密钥 (启动时随机生成)
var globalIDBaseKey [32]byte

func init() {
	crand.Read(globalIDBaseKey[:])
}

// NewGlobalID 生成一个新的随机 GlobalID (客户端 UDP 会话使用)
func NewGlobalID() [8]byte {
	var id [8]byte
	crand.Read(id[:])
	return id
}

// EncodeUDPKeepPacket 编码 StatusKeep UDP 包 (已建立会话后发送后续数据)
func EncodeUDPKeepPacket(globalID [8]byte, target string, payload []byte) ([]byte, error) {
	var udpAddr *net.UDPAddr
	if target != "" {
		addr, err := net.ResolveUDPAddr("udp", target)
		if err == nil {
			udpAddr = addr
		}
	}

	pkt := &UDPPacket{
		GlobalID: globalID,
		Status:   UDPStatusKeep,
		Target:   udpAddr,
		Payload:  payload,
	}
	return EncodeUDPPacket(pkt)
}

// EncodeUDPAddrKeepPacket 编码 StatusKeep UDP 包 (零分配 netip.AddrPort)
func EncodeUDPAddrKeepPacket(globalID [8]byte, target netip.AddrPort, payload []byte) ([]byte, error) {
	pkt := &UDPPacketAddr{
		GlobalID: globalID,
		Status:   UDPStatusKeep,
		Target:   target,
		Payload:  payload,
	}
	return EncodeUDPAddrPacket(pkt)
}

// DecodeUDPPayload 从 EWP UDP 帧字节中提取 payload (客户端收到服务端响应时使用)
func DecodeUDPPayload(data []byte) ([]byte, error) {
	pkt, err := DecodeUDPPacket(newBytesReader(data))
	if err != nil {
		return nil, err
	}
	return pkt.Payload, nil
}

// DecodeUDPPayloadTo extracts payload from EWP UDP frame into provided buffer.
// Returns the number of bytes read.
func DecodeUDPPayloadTo(data []byte, out []byte) (int, error) {
	pkt, err := DecodeUDPPacket(newBytesReader(data))
	if err != nil {
		return 0, err
	}
	n := copy(out, pkt.Payload)
	return n, nil
}

// DecodeUDPAddrPayloadTo extracts payload from EWP UDP frame into provided buffer,
// and returns the real remote address parsed directly as netip.AddrPort (zero-allocation).
func DecodeUDPAddrPayloadTo(data []byte, out []byte) (int, netip.AddrPort, error) {
	if len(data) < 13 {
		return 0, netip.AddrPort{}, errors.New("frame too short")
	}
	frameLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < frameLen+2 {
		return 0, netip.AddrPort{}, errors.New("incomplete frame length")
	}

	// data[2:10] is GlobalID, data[10] is Status
	addrLen := int(data[11])
	offset := 12

	var addr netip.AddrPort
	if addrLen > 0 {
		if offset+addrLen > len(data) {
			return 0, netip.AddrPort{}, errors.New("truncated address")
		}
		addrData := data[offset : offset+addrLen]
		offset += addrLen

		if len(addrData) < 1 {
			return 0, netip.AddrPort{}, errors.New("empty address data")
		}

		switch addrData[0] {
		case AddressTypeIPv4:
			if len(addrData) < 7 {
				return 0, netip.AddrPort{}, errors.New("truncated IPv4 address")
			}
			ip := netip.AddrFrom4(*(*[4]byte)(addrData[1:5]))
			port := binary.BigEndian.Uint16(addrData[5:7])
			addr = netip.AddrPortFrom(ip, port)
		case AddressTypeIPv6:
			if len(addrData) < 19 {
				return 0, netip.AddrPort{}, errors.New("truncated IPv6 address")
			}
			ip := netip.AddrFrom16(*(*[16]byte)(addrData[1:17]))
			port := binary.BigEndian.Uint16(addrData[17:19])
			addr = netip.AddrPortFrom(ip, port)
		default:
			return 0, netip.AddrPort{}, errors.New("unsupported address type for UDP")
		}
	}

	if offset+2 > len(data) {
		return 0, netip.AddrPort{}, errors.New("truncated payload length")
	}
	payloadLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if payloadLen > 0 {
		if offset+payloadLen > len(data) {
			return 0, netip.AddrPort{}, errors.New("truncated payload")
		}
		n := copy(out, data[offset:offset+payloadLen])
		return n, addr, nil
	}

	return 0, addr, nil
}

// DecodeUDPAddrPacketTo reads from an io.Reader, unpacks the EWP UDP frame into the provided buffer,
// and returns the real remote address parsed directly as netip.AddrPort (zero-allocation).
func DecodeUDPAddrPacketTo(r io.Reader, out []byte) (int, netip.AddrPort, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))

	if frameLen < 11 {
		return 0, netip.AddrPort{}, errors.New("frame too short")
	}

	var frameBuf []byte
	var poolBufPtr *[]byte
	if frameLen <= udpFramePoolMax {
		poolBufPtr = udpFramePool.Get().(*[]byte)
		frameBuf = (*poolBufPtr)[:frameLen]
	} else {
		frameBuf = make([]byte, frameLen)
	}

	_, err := io.ReadFull(r, frameBuf)
	if err != nil {
		if poolBufPtr != nil {
			udpFramePool.Put(poolBufPtr)
		}
		return 0, netip.AddrPort{}, err
	}

	addrLen := int(frameBuf[9])
	offset := 10

	var addr netip.AddrPort
	if addrLen > 0 {
		if offset+addrLen > len(frameBuf) {
			if poolBufPtr != nil {
				udpFramePool.Put(poolBufPtr)
			}
			return 0, netip.AddrPort{}, errors.New("truncated address")
		}
		addrData := frameBuf[offset : offset+addrLen]
		offset += addrLen

		if len(addrData) < 1 {
			if poolBufPtr != nil {
				udpFramePool.Put(poolBufPtr)
			}
			return 0, netip.AddrPort{}, errors.New("empty address data")
		}

		switch addrData[0] {
		case AddressTypeIPv4:
			if len(addrData) < 7 {
				if poolBufPtr != nil {
					udpFramePool.Put(poolBufPtr)
				}
				return 0, netip.AddrPort{}, errors.New("truncated IPv4 address")
			}
			ip := netip.AddrFrom4(*(*[4]byte)(addrData[1:5]))
			port := binary.BigEndian.Uint16(addrData[5:7])
			addr = netip.AddrPortFrom(ip, port)
		case AddressTypeIPv6:
			if len(addrData) < 19 {
				if poolBufPtr != nil {
					udpFramePool.Put(poolBufPtr)
				}
				return 0, netip.AddrPort{}, errors.New("truncated IPv6 address")
			}
			ip := netip.AddrFrom16(*(*[16]byte)(addrData[1:17]))
			port := binary.BigEndian.Uint16(addrData[17:19])
			addr = netip.AddrPortFrom(ip, port)
		default:
			if poolBufPtr != nil {
				udpFramePool.Put(poolBufPtr)
			}
			return 0, netip.AddrPort{}, errors.New("unsupported address type for UDP")
		}
	}

	if offset+2 > len(frameBuf) {
		if poolBufPtr != nil {
			udpFramePool.Put(poolBufPtr)
		}
		return 0, netip.AddrPort{}, errors.New("truncated payload length")
	}
	payloadLen := int(binary.BigEndian.Uint16(frameBuf[offset : offset+2]))
	offset += 2

	var n int
	if payloadLen > 0 {
		if offset+payloadLen > len(frameBuf) {
			if poolBufPtr != nil {
				udpFramePool.Put(poolBufPtr)
			}
			return 0, netip.AddrPort{}, errors.New("truncated payload")
		}
		n = copy(out, frameBuf[offset:offset+payloadLen])
	}

	if poolBufPtr != nil {
		udpFramePool.Put(poolBufPtr)
	}
	return n, addr, nil
}

type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// GenerateGlobalID 生成 GlobalID (基于源地址哈希)
func GenerateGlobalID(addr *net.UDPAddr) [8]byte {
	var id [8]byte
	if addr == nil {
		return id
	}

	h := sha256.New()
	h.Write(globalIDBaseKey[:])
	h.Write(addr.IP)
	h.Write([]byte{byte(addr.Port >> 8), byte(addr.Port)})

	sum := h.Sum(nil)
	copy(id[:], sum[:8])
	return id
}
