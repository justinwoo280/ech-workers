package trojan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/xtaci/smux"
)

// MuxHandler 处理 Mux 多路复用连接的接口
type MuxHandler interface {
	HandleTCP(ctx context.Context, conn net.Conn, target string, user string) error
	HandleUDP(ctx context.Context, conn *PacketConn, target string, user string) error
}

// HandleMuxConnection 处理 Mux 多路复用连接
func HandleMuxConnection(ctx context.Context, conn net.Conn, user string, handler MuxHandler) error {
	config := smux.DefaultConfig()
	config.KeepAliveDisabled = true

	session, err := smux.Server(conn, config)
	if err != nil {
		return fmt.Errorf("create mux session: %w", err)
	}
	defer session.Close()

	var wg sync.WaitGroup

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if err == io.EOF || session.IsClosed() {
				break
			}
			log.Printf("[Mux] Accept stream error: %v", err)
			break
		}

		wg.Add(1)
		go func(stream *smux.Stream) {
			defer wg.Done()
			defer stream.Close()

			if err := handleMuxStream(ctx, stream, user, handler); err != nil {
				log.Printf("[Mux] Stream error: %v", err)
			}
		}(stream)
	}

	wg.Wait()
	return nil
}

// handleMuxStream 处理单个 Mux 流
func handleMuxStream(ctx context.Context, conn net.Conn, user string, handler MuxHandler) error {
	reader := bufio.NewReader(conn)

	// 读取命令
	command, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("read command: %w", err)
	}

	// 读取目标地址
	addr, err := decodeAddressFromReader(reader)
	if err != nil {
		return fmt.Errorf("read destination: %w", err)
	}

	target := addr.String()

	// 如果 reader 中还有缓存数据，需要包装连接
	if reader.Buffered() > 0 {
		buffered := make([]byte, reader.Buffered())
		_, err = io.ReadFull(reader, buffered)
		if err != nil {
			return err
		}
		conn = &cachedStreamConn{
			Conn:   conn,
			cached: buffered,
		}
	}

	switch command {
	case CommandTCP:
		return handler.HandleTCP(ctx, conn, target, user)
	case CommandUDP:
		return handler.HandleUDP(ctx, NewPacketConn(conn), target, user)
	default:
		return fmt.Errorf("unknown command: %d", command)
	}
}

// decodeAddressFromReader 从 bufio.Reader 解码地址
func decodeAddressFromReader(r *bufio.Reader) (*Address, error) {
	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read address type: %w", err)
	}

	addr := &Address{Type: typeByte}

	switch addr.Type {
	case AddressTypeIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return nil, fmt.Errorf("read IPv4 address: %w", err)
		}
		addr.Host = net.IP(ipBuf).String()

	case AddressTypeIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return nil, fmt.Errorf("read IPv6 address: %w", err)
		}
		addr.Host = net.IP(ipBuf).String()

	case AddressTypeDomain:
		lenByte, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read domain length: %w", err)
		}
		domainBuf := make([]byte, lenByte)
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return nil, fmt.Errorf("read domain name: %w", err)
		}
		addr.Host = string(domainBuf)

	default:
		return nil, fmt.Errorf("unknown address type: %d", addr.Type)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}
	addr.Port = uint16(portBuf[0])<<8 | uint16(portBuf[1])

	return addr, nil
}

// cachedStreamConn 是带有缓存数据的流连接
type cachedStreamConn struct {
	net.Conn
	cached []byte
	offset int
	mu     sync.Mutex
}

func (c *cachedStreamConn) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	if c.offset < len(c.cached) {
		n = copy(p, c.cached[c.offset:])
		c.offset += n
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}
