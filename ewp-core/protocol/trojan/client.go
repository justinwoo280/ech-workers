package trojan

import (
	"io"
	"net"
	"sync"
)

// ClientConn 是 Trojan TCP 客户端连接
type ClientConn struct {
	net.Conn
	key           [KeyLength]byte
	destination   *Address
	headerWritten bool
	mu            sync.Mutex
}

// NewClientConn 创建新的 Trojan TCP 客户端连接
func NewClientConn(conn net.Conn, password string, target string) (*ClientConn, error) {
	addr, err := ParseAddress(target)
	if err != nil {
		return nil, err
	}

	return &ClientConn{
		Conn:        conn,
		key:         GenerateKey(password),
		destination: addr,
	}, nil
}

// NewClientConnWithKey 使用预生成的密钥创建连接
func NewClientConnWithKey(conn net.Conn, key [KeyLength]byte, destination *Address) *ClientConn {
	return &ClientConn{
		Conn:        conn,
		key:         key,
		destination: destination,
	}
}

// NeedHandshake 返回是否需要握手
func (c *ClientConn) NeedHandshake() bool {
	return !c.headerWritten
}

// Write 写入数据，首次写入时发送握手
func (c *ClientConn) Write(p []byte) (int, error) {
	if c.headerWritten {
		return c.Conn.Write(p)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.headerWritten {
		return c.Conn.Write(p)
	}

	// 构建握手数据（一次性写入减少系统调用）
	addrBytes, err := c.destination.Encode()
	if err != nil {
		return 0, err
	}

	headerLen := KeyLength + 2 + 1 + len(addrBytes) + 2
	buf := make([]byte, 0, headerLen+len(p))
	buf = append(buf, c.key[:]...)
	buf = append(buf, CRLF...)
	buf = append(buf, CommandTCP)
	buf = append(buf, addrBytes...)
	buf = append(buf, CRLF...)
	buf = append(buf, p...)

	_, err = c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}

	c.headerWritten = true
	return len(p), nil
}

// Read 读取数据
func (c *ClientConn) Read(p []byte) (int, error) {
	return c.Conn.Read(p)
}

// FrontHeadroom 返回握手头部需要的额外空间
func (c *ClientConn) FrontHeadroom() int {
	if !c.headerWritten {
		return KeyLength + 5 + MaxSocksaddrLength
	}
	return 0
}

// Upstream 返回底层连接
func (c *ClientConn) Upstream() net.Conn {
	return c.Conn
}

// ClientPacketConn 是 Trojan UDP 客户端连接
type ClientPacketConn struct {
	net.Conn
	key           [KeyLength]byte
	destination   *Address
	headerWritten bool
	mu            sync.Mutex
}

// NewClientPacketConn 创建新的 Trojan UDP 客户端连接
func NewClientPacketConn(conn net.Conn, password string, target string) (*ClientPacketConn, error) {
	addr, err := ParseAddress(target)
	if err != nil {
		return nil, err
	}

	return &ClientPacketConn{
		Conn:        conn,
		key:         GenerateKey(password),
		destination: addr,
	}, nil
}

// NewClientPacketConnWithKey 使用预生成的密钥创建连接
func NewClientPacketConnWithKey(conn net.Conn, key [KeyLength]byte, destination *Address) *ClientPacketConn {
	return &ClientPacketConn{
		Conn:        conn,
		key:         key,
		destination: destination,
	}
}

// NeedHandshake 返回是否需要握手
func (c *ClientPacketConn) NeedHandshake() bool {
	return !c.headerWritten
}

// WritePacket 写入 UDP 数据包
func (c *ClientPacketConn) WritePacket(payload []byte, dest *Address) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	destBytes, err := dest.Encode()
	if err != nil {
		return err
	}
	length := uint16(len(payload))

	if !c.headerWritten {
		// 首次写入：发送握手 + 数据包
		addrBytes, err := c.destination.Encode()
		if err != nil {
			return err
		}

		headerLen := KeyLength + 2 + 1 + len(addrBytes) + 2
		packetHeaderLen := len(destBytes) + 2 + 2
		buf := make([]byte, 0, headerLen+packetHeaderLen+len(payload))

		// 握手头
		buf = append(buf, c.key[:]...)
		buf = append(buf, CRLF...)
		buf = append(buf, CommandUDP)
		buf = append(buf, addrBytes...)
		buf = append(buf, CRLF...)

		// 数据包头
		buf = append(buf, destBytes...)
		buf = append(buf, byte(length>>8), byte(length))
		buf = append(buf, CRLF...)
		buf = append(buf, payload...)

		_, err = c.Conn.Write(buf)
		if err != nil {
			return err
		}

		c.headerWritten = true
		return nil
	}

	// 后续写入：只发送数据包
	buf := make([]byte, 0, len(destBytes)+2+2+len(payload))
	buf = append(buf, destBytes...)
	buf = append(buf, byte(length>>8), byte(length))
	buf = append(buf, CRLF...)
	buf = append(buf, payload...)

	_, err = c.Conn.Write(buf)
	return err
}

// ReadPacket 读取 UDP 数据包
func (c *ClientPacketConn) ReadPacket() ([]byte, *Address, error) {
	addr, err := DecodeAddress(c.Conn)
	if err != nil {
		return nil, nil, err
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lengthBuf); err != nil {
		return nil, nil, err
	}
	length := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])

	crlfBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, crlfBuf); err != nil {
		return nil, nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return nil, nil, err
	}

	return payload, addr, nil
}

// FrontHeadroom 返回数据包头部需要的额外空间
func (c *ClientPacketConn) FrontHeadroom() int {
	if !c.headerWritten {
		return KeyLength + 2*MaxSocksaddrLength + 9
	}
	return MaxSocksaddrLength + 4
}

// Upstream 返回底层连接
func (c *ClientPacketConn) Upstream() net.Conn {
	return c.Conn
}

// Close 关闭连接
func (c *ClientPacketConn) Close() error {
	return c.Conn.Close()
}
