package trojan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
)

// Handler 处理 Trojan 连接的接口
type Handler interface {
	HandleTCP(ctx context.Context, conn net.Conn, target string, user string) error
	HandleUDP(ctx context.Context, conn *PacketConn, target string, user string) error
}

// FallbackHandler 处理认证失败时的 fallback 连接
type FallbackHandler interface {
	HandleFallback(conn net.Conn, header []byte) error
}

// User 代表一个 Trojan 用户
type User struct {
	Name     string
	Password string
	Key      [KeyLength]byte
}

// Service 是 Trojan 服务端核心
type Service struct {
	users           map[string]*User      // name -> user
	keys            map[[KeyLength]byte]*User // key -> user
	handler         Handler
	fallbackHandler FallbackHandler
	mu              sync.RWMutex
}

// NewService 创建新的 Trojan 服务
func NewService(handler Handler) *Service {
	return &Service{
		users:   make(map[string]*User),
		keys:    make(map[[KeyLength]byte]*User),
		handler: handler,
	}
}

// SetFallbackHandler 设置 fallback 处理器
func (s *Service) SetFallbackHandler(h FallbackHandler) {
	s.fallbackHandler = h
}

// AddUser 添加用户
func (s *Service) AddUser(name, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := GenerateKey(password)
	user := &User{
		Name:     name,
		Password: password,
		Key:      key,
	}
	s.users[name] = user
	s.keys[key] = user
}

// AddUserByPassword 通过密码添加用户（使用密码作为用户名）
func (s *Service) AddUserByPassword(password string) {
	s.AddUser(password, password)
}

// RemoveUser 移除用户
func (s *Service) RemoveUser(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user, ok := s.users[name]; ok {
		delete(s.keys, user.Key)
		delete(s.users, name)
	}
}

// UpdateUsers 批量更新用户
func (s *Service) UpdateUsers(passwords []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users = make(map[string]*User)
	s.keys = make(map[[KeyLength]byte]*User)

	for _, password := range passwords {
		key := GenerateKey(password)
		user := &User{
			Name:     password,
			Password: password,
			Key:      key,
		}
		s.users[password] = user
		s.keys[key] = user
	}
}

// GetValidKeys 获取所有有效密钥映射（用于握手验证）
func (s *Service) GetValidKeys() map[[KeyLength]byte]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[[KeyLength]byte]string)
	for key, user := range s.keys {
		result[key] = user.Password
	}
	return result
}

// UserCount 返回用户数量
func (s *Service) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// HandleConnection 处理新连接
func (s *Service) HandleConnection(ctx context.Context, conn net.Conn) error {
	// 读取密钥
	keyBuf := make([]byte, KeyLength)
	n, err := io.ReadFull(conn, keyBuf)
	if err != nil {
		return s.handleFallback(conn, keyBuf[:n], err)
	}

	var key [KeyLength]byte
	copy(key[:], keyBuf)

	// 验证用户
	s.mu.RLock()
	user, ok := s.keys[key]
	s.mu.RUnlock()

	if !ok {
		return s.handleFallback(conn, keyBuf, fmt.Errorf("invalid key"))
	}

	// 读取 CRLF
	crlfBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, crlfBuf); err != nil {
		return fmt.Errorf("read CRLF: %w", err)
	}

	// 读取命令
	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, cmdBuf); err != nil {
		return fmt.Errorf("read command: %w", err)
	}
	command := cmdBuf[0]

	// 验证命令
	switch command {
	case CommandTCP, CommandUDP, CommandMux:
	default:
		return fmt.Errorf("unknown command: %d", command)
	}

	// 读取目标地址
	addr, err := DecodeAddress(conn)
	if err != nil {
		return fmt.Errorf("decode address: %w", err)
	}

	// 读取 CRLF
	if _, err := io.ReadFull(conn, crlfBuf); err != nil {
		return fmt.Errorf("read CRLF: %w", err)
	}

	target := addr.String()

	// 分发处理
	switch command {
	case CommandTCP:
		return s.handler.HandleTCP(ctx, conn, target, user.Name)
	case CommandUDP:
		return s.handler.HandleUDP(ctx, NewPacketConn(conn), target, user.Name)
	case CommandMux:
		// Mux 多路复用
		muxHandler := &muxHandlerAdapter{handler: s.handler}
		return HandleMuxConnection(ctx, conn, user.Name, muxHandler)
	default:
		return fmt.Errorf("unknown command: %d", command)
	}
}

// handleFallback 处理认证失败的连接
func (s *Service) handleFallback(conn net.Conn, header []byte, err error) error {
	if s.fallbackHandler == nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// 创建带缓存的连接，将已读取的数据放回
	cachedConn := &CachedConn{
		Conn:   conn,
		cached: bytes.NewReader(header),
	}

	return s.fallbackHandler.HandleFallback(cachedConn, header)
}

// CachedConn 是带有缓存数据的连接包装器
type CachedConn struct {
	net.Conn
	cached *bytes.Reader
}

// Read 先读取缓存数据，再读取底层连接
func (c *CachedConn) Read(p []byte) (n int, err error) {
	if c.cached != nil && c.cached.Len() > 0 {
		n, err = c.cached.Read(p)
		if err == io.EOF {
			err = nil
		}
		if n > 0 {
			return n, err
		}
	}
	return c.Conn.Read(p)
}

// PacketConn 是 Trojan UDP 数据包连接
type PacketConn struct {
	net.Conn
}

// NewPacketConn 创建新的 PacketConn
func NewPacketConn(conn net.Conn) *PacketConn {
	return &PacketConn{Conn: conn}
}

// ReadPacket 读取 UDP 数据包
func (c *PacketConn) ReadPacket() ([]byte, *Address, error) {
	addr, err := DecodeAddress(c.Conn)
	if err != nil {
		return nil, nil, fmt.Errorf("read address: %w", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lengthBuf); err != nil {
		return nil, nil, fmt.Errorf("read length: %w", err)
	}
	length := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])

	crlfBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, crlfBuf); err != nil {
		return nil, nil, fmt.Errorf("read crlf: %w", err)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return nil, nil, fmt.Errorf("read payload: %w", err)
	}

	return payload, addr, nil
}

// WritePacket 写入 UDP 数据包
func (c *PacketConn) WritePacket(payload []byte, dest *Address) error {
	addrBytes, err := dest.Encode()
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}

	length := uint16(len(payload))

	// 合并写入以减少系统调用
	buf := make([]byte, 0, len(addrBytes)+2+2+len(payload))
	buf = append(buf, addrBytes...)
	buf = append(buf, byte(length>>8), byte(length))
	buf = append(buf, CRLF...)
	buf = append(buf, payload...)

	_, err = c.Conn.Write(buf)
	return err
}

// FrontHeadroom 返回 UDP 数据包头部需要的额外空间
func (c *PacketConn) FrontHeadroom() int {
	return MaxSocksaddrLength + 4
}

// Close 关闭连接
func (c *PacketConn) Close() error {
	return c.Conn.Close()
}

// muxHandlerAdapter 将 Handler 适配为 MuxHandler
type muxHandlerAdapter struct {
	handler Handler
}

func (a *muxHandlerAdapter) HandleTCP(ctx context.Context, conn net.Conn, target string, user string) error {
	return a.handler.HandleTCP(ctx, conn, target, user)
}

func (a *muxHandlerAdapter) HandleUDP(ctx context.Context, conn *PacketConn, target string, user string) error {
	return a.handler.HandleUDP(ctx, conn, target, user)
}
