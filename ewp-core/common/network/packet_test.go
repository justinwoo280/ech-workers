package network

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"ewp-core/transport"
)

// mockPacketConn is a mock implementation of PacketConn for testing
type mockPacketConn struct {
	readPackets  [][]byte
	readAddrs    []transport.Endpoint
	readIndex    int
	writePackets [][]byte
	writeAddrs   []transport.Endpoint
	readErr      error
	writeErr     error
	closed       bool
	mu           sync.Mutex
}

func (m *mockPacketConn) ReadPacket(buf []byte) (int, transport.Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.readErr != nil {
		return 0, transport.Endpoint{}, m.readErr
	}
	if m.readIndex >= len(m.readPackets) {
		return 0, transport.Endpoint{}, io.EOF
	}

	n := copy(buf, m.readPackets[m.readIndex])
	addr := m.readAddrs[m.readIndex]
	m.readIndex++
	return n, addr, nil
}

func (m *mockPacketConn) WritePacket(payload []byte, addr transport.Endpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writeErr != nil {
		return m.writeErr
	}

	m.writePackets = append(m.writePackets, append([]byte(nil), payload...))
	m.writeAddrs = append(m.writeAddrs, addr)
	return nil
}

func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func TestCopyPacket(t *testing.T) {
	// Create mock source with test data
	src := &mockPacketConn{
		readPackets: [][]byte{
			[]byte("hello"),
			[]byte("world"),
		},
		readAddrs: []transport.Endpoint{
			{Domain: "example.com", Port: 80},
			{Domain: "test.com", Port: 443},
		},
	}
	dst := &mockPacketConn{}

	// Run CopyPacket in a goroutine
	done := make(chan error)
	go func() {
		done <- CopyPacket(dst, src)
	}()

	// Wait for completion
	err := <-done
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}

	// Verify written packets
	if len(dst.writePackets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(dst.writePackets))
	}

	if string(dst.writePackets[0]) != "hello" {
		t.Errorf("expected 'hello', got '%s'", dst.writePackets[0])
	}
	if string(dst.writePackets[1]) != "world" {
		t.Errorf("expected 'world', got '%s'", dst.writePackets[1])
	}

	if dst.writeAddrs[0].Domain != "example.com" || dst.writeAddrs[0].Port != 80 {
		t.Errorf("unexpected address: %+v", dst.writeAddrs[0])
	}
	if dst.writeAddrs[1].Domain != "test.com" || dst.writeAddrs[1].Port != 443 {
		t.Errorf("unexpected address: %+v", dst.writeAddrs[1])
	}
}

func TestCopyPacketWriteError(t *testing.T) {
	src := &mockPacketConn{
		readPackets: [][]byte{[]byte("test")},
		readAddrs:   []transport.Endpoint{{Domain: "test.com", Port: 80}},
	}
	dst := &mockPacketConn{
		writeErr: errors.New("write error"),
	}

	err := CopyPacket(dst, src)
	if err == nil || err.Error() != "write error" {
		t.Errorf("expected write error, got %v", err)
	}
}

func TestCopyPacketReadError(t *testing.T) {
	src := &mockPacketConn{
		readErr: errors.New("read error"),
	}
	dst := &mockPacketConn{}

	err := CopyPacket(dst, src)
	if err == nil || err.Error() != "read error" {
		t.Errorf("expected read error, got %v", err)
	}
}

func TestTimeoutPacketConn(t *testing.T) {
	// Create a mock connection
	mock := &mockPacketConn{
		readPackets: [][]byte{[]byte("test")},
		readAddrs:   []transport.Endpoint{{Domain: "test.com", Port: 80}},
	}

	// Wrap with 100ms timeout
	tpc := NewTimeoutPacketConn(mock, 100*time.Millisecond)

	// Read should succeed and reset timer
	buf := make([]byte, 1024)
	n, addr, err := tpc.ReadPacket(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:n]) != "test" {
		t.Errorf("expected 'test', got '%s'", buf[:n])
	}
	if addr.Domain != "test.com" {
		t.Errorf("unexpected address: %+v", addr)
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Connection should be closed
	if !mock.closed {
		t.Error("expected connection to be closed after timeout")
	}
}

func TestTimeoutPacketConnActivity(t *testing.T) {
	mock := &mockPacketConn{
		readPackets: [][]byte{
			[]byte("packet1"),
			[]byte("packet2"),
		},
		readAddrs: []transport.Endpoint{
			{Domain: "test.com", Port: 80},
			{Domain: "test.com", Port: 80},
		},
	}

	// Wrap with 50ms timeout
	tpc := NewTimeoutPacketConn(mock, 50*time.Millisecond)

	// Read first packet
	buf := make([]byte, 1024)
	_, _, err := tpc.ReadPacket(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait 30ms (less than timeout)
	time.Sleep(30 * time.Millisecond)

	// Read second packet (should reset timer)
	_, _, err = tpc.ReadPacket(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Connection should still be open
	if mock.closed {
		t.Error("connection should not be closed yet")
	}

	// Now wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Connection should be closed now
	if !mock.closed {
		t.Error("expected connection to be closed after timeout")
	}
}

func TestTimeoutPacketConnClose(t *testing.T) {
	mock := &mockPacketConn{}
	tpc := NewTimeoutPacketConn(mock, 1*time.Second)

	// Close should stop the timer
	err := tpc.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mock.closed {
		t.Error("expected underlying connection to be closed")
	}

	// Double close should be safe
	err = tpc.Close()
	if err != nil {
		t.Fatalf("unexpected error on double close: %v", err)
	}
}
