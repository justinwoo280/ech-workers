package gvisor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	tun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"ewp-core/log"
)

// UDPRouteKey is a zero-allocation map key for the write-side conn cache.
// Both fields are value types (no pointers), so the struct lives on the stack
// and sync.Map stores it without additional heap allocation.
type UDPRouteKey struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

type cachedUDPConn struct {
	conn     *gonet.UDPConn
	lastUsed atomic.Int64 // UnixNano; updated on every Write
}

type StackConfig struct {
	MTU        int
	TCPHandler func(conn *gonet.TCPConn)
	UDPHandler func(payload []byte, src netip.AddrPort, dst netip.AddrPort)
}

type Stack struct {
	ipStack   *stack.Stack
	tunDev    tun.Device
	config    *StackConfig
	connCache sync.Map // UDPRouteKey → *cachedUDPConn
	stopClean chan struct{}
}

// NewStack creates a new gVisor TCP/IP stack attached to the given wireguard-go TUN device
func NewStack(tunDev tun.Device, config *StackConfig) (*Stack, error) {
	if config.TCPHandler == nil || config.UDPHandler == nil {
		return nil, errors.New("TCP and UDP handlers are required")
	}

	ipStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	ep, err := newEndpoint(tunDev, uint32(config.MTU))
	if err != nil {
		return nil, fmt.Errorf("create gvisor endpoint: %w", err)
	}

	nicID := tcpip.NICID(1)
	if err := ipStack.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}

	ipStack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	// Enable Promiscuous mode and Spoofing to allow transparent proxying and return traffic
	if err := ipStack.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %v", err)
	}
	if err := ipStack.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %v", err)
	}

	s := &Stack{
		ipStack:   ipStack,
		tunDev:    tunDev,
		config:    config,
		stopClean: make(chan struct{}),
	}
	s.setupTCPForwarder()
	s.setupUDPForwarder()
	go s.connCacheCleanup()

	return s, nil
}

// tcpipAddrToNetipAddr safely converts a gVisor tcpip.Address (4 or 16 bytes)
// to a Go netip.Addr without panicking on length mismatch.
func tcpipAddrToNetipAddr(addr tcpip.Address) netip.Addr {
	switch addr.Len() {
	case 4:
		return netip.AddrFrom4(addr.As4())
	case 16:
		return netip.AddrFrom16(addr.As16())
	default:
		return netip.Addr{}
	}
}

func (s *Stack) setupTCPForwarder() {
	tcpForwarder := tcp.NewForwarder(s.ipStack, 0, 10000, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		// Read the transport ID BEFORE Complete() — gVisor releases the
		// internal segment after Complete(), making r.ID() panic.
		id := r.ID()
		src := netip.AddrPortFrom(tcpipAddrToNetipAddr(id.RemoteAddress), id.RemotePort)
		dst := netip.AddrPortFrom(tcpipAddrToNetipAddr(id.LocalAddress), id.LocalPort)

		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.V("[gVisor TCP] create endpoint failed: %v", err)
			r.Complete(true)
			return
		}

		r.Complete(false)

		log.V("[gVisor TCP] Connection request: %s -> %s", src, dst)

		conn := gonet.NewTCPConn(&wq, ep)

		go func() {
			defer conn.Close()
			s.config.TCPHandler(conn)
		}()
	})

	s.ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
}

func (s *Stack) setupUDPForwarder() {
	udpForwarder := udp.NewForwarder(s.ipStack, func(r *udp.ForwarderRequest) bool {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.V("[gVisor UDP] create endpoint failed: %v", err)
			return false
		}

		id := r.ID()
		src := netip.AddrPortFrom(tcpipAddrToNetipAddr(id.RemoteAddress), id.RemotePort)
		dst := netip.AddrPortFrom(tcpipAddrToNetipAddr(id.LocalAddress), id.LocalPort)

		conn := gonet.NewUDPConn(&wq, ep)
		go s.udpReadLoop(conn, src, dst)

		return true
	})

	s.ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
}

// udpReadLoop reads incoming UDP packets from the gVisor endpoint and dispatches
// them to the configured handler. Uses gonet.UDPConn (high-level API) so that
// the waiter is managed internally and a single pre-allocated buffer serves the
// entire session lifetime — zero per-packet heap allocation.
func (s *Stack) udpReadLoop(conn *gonet.UDPConn, src, dst netip.AddrPort) {
	defer conn.Close()

	buf := make([]byte, s.config.MTU+4)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			s.config.UDPHandler(buf[:n], src, dst)
		}
	}
}

// WriteUDP injects a UDP packet into the gVisor stack so it is delivered back
// to the TUN client. src is who the packet appears to come FROM (e.g. the remote
// server), dst is the TUN client who receives it.
//
// Connections are cached by (src, dst) key and reused across calls — a single
// gonet.DialUDP per unique route instead of one per packet.
func (s *Stack) WriteUDP(p []byte, src netip.AddrPort, dst netip.AddrPort) error {
	key := UDPRouteKey{Src: src, Dst: dst}

	if v, ok := s.connCache.Load(key); ok {
		c := v.(*cachedUDPConn)
		c.lastUsed.Store(time.Now().UnixNano())
		_, err := c.conn.Write(p)
		return err
	}

	conn, err := s.dialUDP(src, dst)
	if err != nil {
		return err
	}

	c := &cachedUDPConn{conn: conn}
	c.lastUsed.Store(time.Now().UnixNano())

	if actual, loaded := s.connCache.LoadOrStore(key, c); loaded {
		conn.Close()
		ac := actual.(*cachedUDPConn)
		ac.lastUsed.Store(time.Now().UnixNano())
		_, err = ac.conn.Write(p)
		return err
	}

	_, err = conn.Write(p)
	return err
}

// ReleaseWriteConn immediately evicts and closes the cached conn for (src, dst).
// Call this when the corresponding proxy session ends to free resources eagerly.
func (s *Stack) ReleaseWriteConn(src, dst netip.AddrPort) {
	key := UDPRouteKey{Src: src, Dst: dst}
	if v, ok := s.connCache.LoadAndDelete(key); ok {
		v.(*cachedUDPConn).conn.Close()
	}
}

func (s *Stack) dialUDP(src, dst netip.AddrPort) (*gonet.UDPConn, error) {
	var netProto tcpip.NetworkProtocolNumber
	var laddr, raddr tcpip.FullAddress

	if src.Addr().Is4() || src.Addr().Is4In6() {
		netProto = ipv4.ProtocolNumber
		laddr = tcpip.FullAddress{Addr: tcpip.AddrFrom4(src.Addr().Unmap().As4()), Port: src.Port()}
		raddr = tcpip.FullAddress{Addr: tcpip.AddrFrom4(dst.Addr().Unmap().As4()), Port: dst.Port()}
	} else {
		netProto = ipv6.ProtocolNumber
		laddr = tcpip.FullAddress{Addr: tcpip.AddrFrom16(src.Addr().As16()), Port: src.Port()}
		raddr = tcpip.FullAddress{Addr: tcpip.AddrFrom16(dst.Addr().As16()), Port: dst.Port()}
	}

	conn, err := gonet.DialUDP(s.ipStack, &laddr, &raddr, netProto)
	if err != nil {
		return nil, fmt.Errorf("DialUDP: %v", err)
	}
	return conn, nil
}

// connCacheCleanup runs in the background and evicts idle cached conns.
func (s *Stack) connCacheCleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	const idleTimeout = 5 * time.Minute

	for {
		select {
		case <-s.stopClean:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-idleTimeout).UnixNano()
			s.connCache.Range(func(k, v any) bool {
				c := v.(*cachedUDPConn)
				if c.lastUsed.Load() < cutoff {
					if _, deleted := s.connCache.LoadAndDelete(k); deleted {
						c.conn.Close()
					}
				}
				return true
			})
		}
	}
}

// WriteUDPWithContext is like WriteUDP but respects context cancellation.
func (s *Stack) WriteUDPWithContext(ctx context.Context, p []byte, src netip.AddrPort, dst netip.AddrPort) error {
	done := make(chan error, 1)
	go func() { done <- s.WriteUDP(p, src, dst) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Stack) Close() {
	close(s.stopClean)

	s.connCache.Range(func(k, v any) bool {
		s.connCache.Delete(k)
		v.(*cachedUDPConn).conn.Close()
		return true
	})

	if s.ipStack != nil {
		s.ipStack.Close()
	}
	if s.tunDev != nil {
		s.tunDev.Close()
	}
}
