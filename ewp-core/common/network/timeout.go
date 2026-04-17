package network

import (
	"sync"
	"time"

	"ewp-core/transport"
)

// TimeoutPacketConn wraps a PacketConn with idle timeout.
// If no read or write activity occurs within the timeout duration,
// the connection is automatically closed.
type TimeoutPacketConn struct {
	conn    PacketConn
	timeout time.Duration
	timer   *time.Timer
	mu      sync.Mutex
	closed  bool
}

// NewTimeoutPacketConn creates a new PacketConn with idle timeout.
// The connection will be automatically closed if no activity occurs
// for the specified duration.
func NewTimeoutPacketConn(conn PacketConn, timeout time.Duration) *TimeoutPacketConn {
	tpc := &TimeoutPacketConn{
		conn:    conn,
		timeout: timeout,
	}
	tpc.timer = time.AfterFunc(timeout, tpc.close)
	return tpc
}

// ReadPacket reads a packet and resets the idle timer.
func (tpc *TimeoutPacketConn) ReadPacket(buf []byte) (int, transport.Endpoint, error) {
	n, addr, err := tpc.conn.ReadPacket(buf)
	if err != nil {
		return n, addr, err
	}
	tpc.resetTimer()
	return n, addr, nil
}

// WritePacket writes a packet and resets the idle timer.
func (tpc *TimeoutPacketConn) WritePacket(payload []byte, addr transport.Endpoint) error {
	err := tpc.conn.WritePacket(payload, addr)
	if err != nil {
		return err
	}
	tpc.resetTimer()
	return nil
}

// Close closes the connection and stops the timer.
func (tpc *TimeoutPacketConn) Close() error {
	tpc.mu.Lock()
	defer tpc.mu.Unlock()
	if tpc.closed {
		return nil
	}
	tpc.closed = true
	tpc.timer.Stop()
	return tpc.conn.Close()
}

func (tpc *TimeoutPacketConn) resetTimer() {
	tpc.mu.Lock()
	defer tpc.mu.Unlock()
	if !tpc.closed {
		tpc.timer.Reset(tpc.timeout)
	}
}

func (tpc *TimeoutPacketConn) close() {
	tpc.mu.Lock()
	defer tpc.mu.Unlock()
	if !tpc.closed {
		tpc.closed = true
		tpc.conn.Close()
	}
}
