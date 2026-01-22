package ewp

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
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
//   0x01 = New (新连接，包含完整地址)
//   0x02 = Keep (保持连接，地址可选)
//   0x03 = End (关闭连接)

const (
	UDPStatusNew  byte = 0x01
	UDPStatusKeep byte = 0x02
	UDPStatusEnd  byte = 0x03

	// 最大 UDP 包大小
	MaxUDPPacketSize = 65507
	// UDP 帧头最小长度: FrameLen(2) + GlobalID(8) + Status(1) + PayloadLen(2)
	UDPFrameHeaderMin = 13
)

// UDPPacket 表示一个 UDP 数据包
type UDPPacket struct {
	GlobalID [8]byte      // 会话标识 (源地址哈希)
	Status   byte         // 状态
	Target   *net.UDPAddr // 目标地址 (Status=New 时必须)
	Payload  []byte       // 数据
}

// EncodeUDPPacket 编码 UDP 包为字节流
func EncodeUDPPacket(pkt *UDPPacket) ([]byte, error) {
	// 计算帧长度
	addrLen := 0
	var addrBytes []byte

	if pkt.Status == UDPStatusNew && pkt.Target != nil {
		// 编码地址
		if ip4 := pkt.Target.IP.To4(); ip4 != nil {
			addrBytes = make([]byte, 1+4+2) // type + ip4 + port
			addrBytes[0] = AddressTypeIPv4
			copy(addrBytes[1:5], ip4)
			binary.BigEndian.PutUint16(addrBytes[5:7], uint16(pkt.Target.Port))
		} else if ip6 := pkt.Target.IP.To16(); ip6 != nil {
			addrBytes = make([]byte, 1+16+2) // type + ip6 + port
			addrBytes[0] = AddressTypeIPv6
			copy(addrBytes[1:17], ip6)
			binary.BigEndian.PutUint16(addrBytes[17:19], uint16(pkt.Target.Port))
		} else {
			return nil, errors.New("invalid target IP")
		}
		addrLen = len(addrBytes)
	}

	payloadLen := len(pkt.Payload)
	frameLen := 8 + 1 + 1 + addrLen + 2 + payloadLen // GlobalID + Status + AddrLen + Addr + PayloadLen + Payload

	buf := make([]byte, 2+frameLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(frameLen))
	copy(buf[2:10], pkt.GlobalID[:])
	buf[10] = pkt.Status
	buf[11] = byte(addrLen)

	offset := 12
	if addrLen > 0 {
		copy(buf[offset:offset+addrLen], addrBytes)
		offset += addrLen
	}

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(payloadLen))
	offset += 2

	if payloadLen > 0 {
		copy(buf[offset:], pkt.Payload)
	}

	return buf, nil
}

// DecodeUDPPacket 从 reader 解码 UDP 包
func DecodeUDPPacket(r io.Reader) (*UDPPacket, error) {
	// 读取帧长度
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	frameLen := binary.BigEndian.Uint16(lenBuf)

	if frameLen < 11 { // 最小: GlobalID(8) + Status(1) + AddrLen(1) + PayloadLen(2) - 1
		return nil, errors.New("frame too short")
	}

	// 读取帧数据
	frameBuf := make([]byte, frameLen)
	if _, err := io.ReadFull(r, frameBuf); err != nil {
		return nil, err
	}

	pkt := &UDPPacket{}
	copy(pkt.GlobalID[:], frameBuf[0:8])
	pkt.Status = frameBuf[8]
	addrLen := int(frameBuf[9])

	offset := 10

	// 解析地址 (如果有)
	if addrLen > 0 {
		if offset+addrLen > len(frameBuf) {
			return nil, errors.New("truncated address")
		}
		addrData := frameBuf[offset : offset+addrLen]
		offset += addrLen

		if len(addrData) < 1 {
			return nil, errors.New("empty address data")
		}

		addrType := addrData[0]
		switch addrType {
		case AddressTypeIPv4:
			if len(addrData) < 7 { // type + ip4 + port
				return nil, errors.New("truncated IPv4 address")
			}
			ip := net.IP(addrData[1:5])
			port := binary.BigEndian.Uint16(addrData[5:7])
			pkt.Target = &net.UDPAddr{IP: ip, Port: int(port)}

		case AddressTypeIPv6:
			if len(addrData) < 19 { // type + ip6 + port
				return nil, errors.New("truncated IPv6 address")
			}
			ip := net.IP(addrData[1:17])
			port := binary.BigEndian.Uint16(addrData[17:19])
			pkt.Target = &net.UDPAddr{IP: ip, Port: int(port)}

		default:
			return nil, errors.New("unsupported address type for UDP")
		}
	}

	// 读取 payload 长度
	if offset+2 > len(frameBuf) {
		return nil, errors.New("truncated payload length")
	}
	payloadLen := binary.BigEndian.Uint16(frameBuf[offset : offset+2])
	offset += 2

	// 读取 payload
	if payloadLen > 0 {
		if offset+int(payloadLen) > len(frameBuf) {
			return nil, errors.New("truncated payload")
		}
		pkt.Payload = make([]byte, payloadLen)
		copy(pkt.Payload, frameBuf[offset:offset+int(payloadLen)])
	}

	return pkt, nil
}

// UDPSession 管理 UDP 会话 (Full-Cone NAT)
type UDPSession struct {
	GlobalID   [8]byte
	LocalAddr  *net.UDPAddr // 客户端源地址
	RemoteConn *net.UDPConn // 到目标的连接
	LastTarget *net.UDPAddr // 最后的目标地址
	mu         sync.Mutex
}

// Lock 锁定会话
func (s *UDPSession) Lock() {
	s.mu.Lock()
}

// Unlock 解锁会话
func (s *UDPSession) Unlock() {
	s.mu.Unlock()
}

// UDPSessionManager 管理所有 UDP 会话 (服务端使用)
type UDPSessionManager struct {
	sessions map[[8]byte]*UDPSession
	mu       sync.RWMutex
}

// NewUDPSessionManager 创建会话管理器
func NewUDPSessionManager() *UDPSessionManager {
	return &UDPSessionManager{
		sessions: make(map[[8]byte]*UDPSession),
	}
}

// GetOrCreate 获取或创建会话
func (m *UDPSessionManager) GetOrCreate(globalID [8]byte) (*UDPSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[globalID]; exists {
		return session, false
	}

	session := &UDPSession{
		GlobalID: globalID,
	}
	m.sessions[globalID] = session
	return session, true
}

// Get 获取会话
func (m *UDPSessionManager) Get(globalID [8]byte) *UDPSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[globalID]
}

// Remove 删除会话
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

// Close 关闭所有会话
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
	// 启动时生成随机密钥
	crand.Read(globalIDBaseKey[:])
}

// GenerateGlobalID 生成 GlobalID (基于源地址哈希)
// 使用 SHA256 + 随机密钥，更安全
func GenerateGlobalID(addr *net.UDPAddr) [8]byte {
	var id [8]byte
	if addr == nil {
		return id
	}

	// 使用 HMAC-like 结构: SHA256(baseKey || addr)
	h := sha256.New()
	h.Write(globalIDBaseKey[:])
	h.Write(addr.IP)
	h.Write([]byte{byte(addr.Port >> 8), byte(addr.Port)})
	
	sum := h.Sum(nil)
	copy(id[:], sum[:8])
	return id
}
