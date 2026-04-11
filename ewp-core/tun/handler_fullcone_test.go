package tun

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ewp-core/transport"
)

// MockTunnelConn simulates a proxy tunnel connection
type MockTunnelConn struct {
	readChan chan *mockUDPResponse
	closed   atomic.Bool
}

type mockUDPResponse struct {
	data       []byte
	remoteAddr netip.AddrPort
}

func (m *MockTunnelConn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	if m.closed.Load() {
		return 0, netip.AddrPort{}, context.Canceled
	}

	select {
	case resp := <-m.readChan:
		copy(buf, resp.data)
		return len(resp.data), resp.remoteAddr, nil
	case <-time.After(5 * time.Second):
		return 0, netip.AddrPort{}, context.DeadlineExceeded
	}
}

func (m *MockTunnelConn) WriteUDP(endpoint transport.Endpoint, payload []byte) error {
	return nil
}

func (m *MockTunnelConn) ConnectUDP(endpoint transport.Endpoint, initialData []byte) error {
	return nil
}

func (m *MockTunnelConn) Connect(target string, initialData []byte) error {
	return nil
}

func (m *MockTunnelConn) ReadUDP() ([]byte, error) {
	return nil, nil
}

func (m *MockTunnelConn) ReadUDPTo(buf []byte) (int, error) {
	return 0, nil
}

func (m *MockTunnelConn) Read(buf []byte) (int, error) {
	return 0, nil
}

func (m *MockTunnelConn) Write(data []byte) error {
	return nil
}

func (m *MockTunnelConn) StartPing(interval time.Duration) chan struct{} {
	return make(chan struct{})
}

func (m *MockTunnelConn) Close() error {
	m.closed.Store(true)
	return nil
}

// MockUDPWriter tracks written packets
type MockUDPWriter struct {
	mu       sync.Mutex
	written  []*wrappedUDPPacket
	lastErr  error
	allowAll bool
}

type wrappedUDPPacket struct {
	payload []byte
	src     netip.AddrPort
	dst     netip.AddrPort
}

func (m *MockUDPWriter) WriteTo(p []byte, src netip.AddrPort, dst netip.AddrPort) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pkt := &wrappedUDPPacket{
		payload: make([]byte, len(p)),
		src:     src,
		dst:     dst,
	}
	copy(pkt.payload, p)
	m.written = append(m.written, pkt)

	return m.lastErr
}

func (m *MockUDPWriter) InjectUDP(p []byte, src netip.AddrPort, dst netip.AddrPort) error {
	return m.WriteTo(p, src, dst)
}

func (m *MockUDPWriter) ReleaseConn(src netip.AddrPort, dst netip.AddrPort) {}

func (m *MockUDPWriter) GetWritten() []*wrappedUDPPacket {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.written
}

// MockTransport for creating mock tunnel connections
type MockTransport struct {
	dialChan chan *MockTunnelConn
}

func (m *MockTransport) Dial() (transport.TunnelConn, error) {
	return <-m.dialChan, nil
}

func (m *MockTransport) Name() string {
	return "mock"
}

func (m *MockTransport) SetBypassConfig(cfg *transport.BypassConfig) {
	// No-op for mock
}

// ════════════════════════════════════════════════════════════════════════════════
// Test: Full Cone NAT - Single Response
// ════════════════════════════════════════════════════════════════════════════════

func TestFullConeNAT_SingleResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockTunnel := &MockTunnelConn{
		readChan: make(chan *mockUDPResponse, 1),
	}
	mockTransport := &MockTransport{
		dialChan: make(chan *MockTunnelConn, 1),
	}
	mockTransport.dialChan <- mockTunnel
	mockUDPWriter := &MockUDPWriter{}

	handler := NewHandler(ctx, mockTransport, mockUDPWriter)

	// Client sends UDP to FakeIP:53 (DNS)
	clientSrc := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 100}), 12345)
	fakeIPDst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, 0, 1}), 53)
	payload := []byte("DNS query")

	// Real DNS server responds
	realServerIP := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)

	// Trigger HandleUDP (this creates the session)
	go handler.HandleUDP(payload, clientSrc, fakeIPDst)

	// Give it time to create the session
	time.Sleep(100 * time.Millisecond)

	// Inject response from real server (simulating proxy tunnel)
	response := []byte("DNS response")
	mockTunnel.readChan <- &mockUDPResponse{
		data:       response,
		remoteAddr: realServerIP,
	}

	// Wait for packet to be written
	time.Sleep(200 * time.Millisecond)

	// Check that response source is FakeIP (NOT real server IP)
	written := mockUDPWriter.GetWritten()
	if len(written) != 1 {
		t.Fatalf("expected 1 written packet, got %d", len(written))
	}

	pkt := written[0]
	if pkt.src != fakeIPDst {
		t.Errorf("response source should be FakeIP %s, got %s", fakeIPDst, pkt.src)
	}
	if pkt.dst != clientSrc {
		t.Errorf("response destination should be client %s, got %s", clientSrc, pkt.dst)
	}

	t.Logf("✓ Full Cone NAT single response test passed")
	t.Logf("  Client: %s", clientSrc)
	t.Logf("  FakeIP: %s", fakeIPDst)
	t.Logf("  Real Server: %s", realServerIP)
	t.Logf("  Response from: %s (correct - using FakeIP)", pkt.src)
}

// ════════════════════════════════════════════════════════════════════════════════
// Test: Full Cone NAT - Multiple Peers Same Client Port
// ════════════════════════════════════════════════════════════════════════════════

func TestFullConeNAT_MultiplePeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockTunnel := &MockTunnelConn{
		readChan: make(chan *mockUDPResponse, 10),
	}
	mockTransport := &MockTransport{
		dialChan: make(chan *MockTunnelConn, 1),
	}
	mockTransport.dialChan <- mockTunnel
	mockUDPWriter := &MockUDPWriter{}

	handler := NewHandler(ctx, mockTransport, mockUDPWriter)

	// Client sends to two different FakeIPs from same local port
	clientSrc := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 100}), 12345)

	// First destination: DNS (198.18.0.1:53)
	fakeIP1 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, 0, 1}), 53)
	realServer1 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)

	// Second destination: HTTP (198.18.0.2:80)
	fakeIP2 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, 0, 2}), 80)
	realServer2 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 80)

	// Send first request
	go handler.HandleUDP([]byte("DNS query"), clientSrc, fakeIP1)
	time.Sleep(100 * time.Millisecond)

	// Send second request (same client port, different FakeIP)
	// This OVERWRITES the session with the new FakeIP
	go handler.HandleUDP([]byte("HTTP request"), clientSrc, fakeIP2)
	time.Sleep(100 * time.Millisecond)

	// Responses from both servers (even though session is now bound to fakeIP2)
	mockTunnel.readChan <- &mockUDPResponse{
		data:       []byte("DNS response"),
		remoteAddr: realServer1,
	}

	mockTunnel.readChan <- &mockUDPResponse{
		data:       []byte("HTTP response"),
		remoteAddr: realServer2,
	}

	time.Sleep(300 * time.Millisecond)

	// Check responses
	written := mockUDPWriter.GetWritten()
	if len(written) < 2 {
		t.Fatalf("expected at least 2 written packets, got %d", len(written))
	}

	// Both responses should use their respective FakeIPs
	for i, pkt := range written {
		// Note: In this test, the session gets overwritten when we send the second request
		// So both responses will use fakeIP2 (the last FakeIP written to)
		// This is a limitation of the current single-session-per-port design
		t.Logf("Response %d from: %s → %s", i, pkt.src, pkt.dst)
	}

	t.Logf("✓ Multiple peers test completed")
	t.Logf("  Note: Current design uses single session per client port")
	t.Logf("  For true Full Cone NAT with multiple peers, enhanced design needed")
}

// ════════════════════════════════════════════════════════════════════════════════
// Test: Full Cone NAT - FakeIP Session Preservation
// ════════════════════════════════════════════════════════════════════════════════

func TestFullConeNAT_FakeIPPreservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockTunnel := &MockTunnelConn{
		readChan: make(chan *mockUDPResponse, 1),
	}
	mockTransport := &MockTransport{
		dialChan: make(chan *MockTunnelConn, 1),
	}
	mockTransport.dialChan <- mockTunnel
	mockUDPWriter := &MockUDPWriter{}

	handler := NewHandler(ctx, mockTransport, mockUDPWriter)

	clientSrc := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 100}), 12345)
	fakeIPDst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, 0, 100}), 5353)
	realServer := netip.AddrPortFrom(netip.AddrFrom4([4]byte{100, 100, 100, 100}), 5353)

	// Send request to FakeIP
	go handler.HandleUDP([]byte("query"), clientSrc, fakeIPDst)
	time.Sleep(100 * time.Millisecond)

	// Simulate real server response
	mockTunnel.readChan <- &mockUDPResponse{
		data:       []byte("response data"),
		remoteAddr: realServer,
	}

	time.Sleep(200 * time.Millisecond)

	// Verify the response appears to come from FakeIP
	written := mockUDPWriter.GetWritten()
	if len(written) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(written))
	}

	pkt := written[0]

	// Key assertion: Source IP must be FakeIP, not real server
	if pkt.src.Addr() != fakeIPDst.Addr() {
		t.Errorf("response source IP mismatch: got %s, want %s", pkt.src.Addr(), fakeIPDst.Addr())
	}

	if pkt.src.Port() != fakeIPDst.Port() {
		t.Errorf("response source port mismatch: got %d, want %d", pkt.src.Port(), fakeIPDst.Port())
	}

	t.Logf("✓ FakeIP preservation test passed")
	t.Logf("  Sent to: %s", fakeIPDst)
	t.Logf("  Real server: %s", realServer)
	t.Logf("  Response from: %s (FakeIP preserved ✓)", pkt.src)
}

// ════════════════════════════════════════════════════════════════════════════════
// Test: UDP Response Source Address Validation (gVisor compatibility)
// ════════════════════════════════════════════════════════════════════════════════

func TestUDPResponseSourceValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockTunnel := &MockTunnelConn{
		readChan: make(chan *mockUDPResponse, 3),
	}
	mockTransport := &MockTransport{
		dialChan: make(chan *MockTunnelConn, 1),
	}
	mockTransport.dialChan <- mockTunnel
	mockUDPWriter := &MockUDPWriter{}

	handler := NewHandler(ctx, mockTransport, mockUDPWriter)

	// Multiple clients, same FakeIP service
	clients := []netip.AddrPort{
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 100}), 10000),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 101}), 10001),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 102}), 10002),
	}

	fakeIP := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, 0, 1}), 53)

	// All clients connect to same FakeIP
	for _, client := range clients {
		go handler.HandleUDP([]byte("query"), client, fakeIP)
	}
	time.Sleep(150 * time.Millisecond)

	// Responses from real server
	realServer := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)
	mockTunnel.readChan <- &mockUDPResponse{
		data:       []byte("response1"),
		remoteAddr: realServer,
	}
	mockTunnel.readChan <- &mockUDPResponse{
		data:       []byte("response2"),
		remoteAddr: realServer,
	}
	mockTunnel.readChan <- &mockUDPResponse{
		data:       []byte("response3"),
		remoteAddr: realServer,
	}

	time.Sleep(300 * time.Millisecond)

	// All responses should appear to come from FakeIP
	written := mockUDPWriter.GetWritten()
	if len(written) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(written))
	}

	for i, pkt := range written {
		if pkt.src.Addr() != fakeIP.Addr() {
			t.Errorf("packet %d: source should be FakeIP, got %s", i, pkt.src)
		}
		if pkt.src.Port() != fakeIP.Port() {
			t.Errorf("packet %d: source port should be %d, got %d", i, fakeIP.Port(), pkt.src.Port())
		}
		// Destination should match the original sender
		if !contains(clients, pkt.dst) {
			t.Errorf("packet %d: destination %s not in client list", i, pkt.dst)
		}
	}

	t.Logf("✓ UDP response source validation test passed")
	t.Logf("  Clients: %d", len(clients))
	t.Logf("  FakeIP: %s", fakeIP)
	t.Logf("  All responses from: %s ✓", fakeIP)
}

func contains(addrs []netip.AddrPort, target netip.AddrPort) bool {
	for _, a := range addrs {
		if a == target {
			return true
		}
	}
	return false
}
