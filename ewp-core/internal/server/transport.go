package server

import (
	"io"
	"net"
	"sync"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
)

type HandshakeResult struct {
	Target      string
	Response    []byte
	FlowState   *ewp.FlowState
	InitialData []byte
	IsUDP       bool
	UserID      string
}

type ProtocolHandler interface {
	Handshake(data []byte, clientIP string) (*HandshakeResult, error)
}

type TransportAdapter interface {
	Read() ([]byte, error)
	Write([]byte) error
	Close() error
}

type TunnelForwarder struct {
	transport   TransportAdapter
	remote      net.Conn
	flowState   *ewp.FlowState
	bufferPool  *sync.Pool
	done        chan struct{}
	enableFlow  bool
}

func NewTunnelForwarder(transport TransportAdapter, remote net.Conn, flowState *ewp.FlowState) *TunnelForwarder {
	return &TunnelForwarder{
		transport:  transport,
		remote:     remote,
		flowState:  flowState,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
		done:       make(chan struct{}, 2),
		enableFlow: flowState != nil,
	}
}

func (tf *TunnelForwarder) Forward() {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		tf.forwardUplink()
	}()

	go func() {
		defer wg.Done()
		tf.forwardDownlink()
	}()

	wg.Wait()
	tf.transport.Close()
	tf.remote.Close()
}

func (tf *TunnelForwarder) forwardUplink() {
	defer func() { tf.done <- struct{}{} }()

	for {
		data, err := tf.transport.Read()
		if err != nil {
			if err != io.EOF {
				log.V("[Forwarder] Uplink read error: %v", err)
			}
			return
		}

		if len(data) == 0 {
			continue
		}

		if tf.enableFlow && tf.flowState != nil {
			data = tf.flowState.ProcessUplink(data)
		}

		if _, err := tf.remote.Write(data); err != nil {
			log.V("[Forwarder] Uplink write error: %v", err)
			return
		}
	}
}

func (tf *TunnelForwarder) forwardDownlink() {
	defer func() { tf.done <- struct{}{} }()

	buf := tf.bufferPool.Get().([]byte)
	defer tf.bufferPool.Put(buf)

	var writeOnceUserUUID []byte
	if tf.enableFlow && tf.flowState != nil {
		writeOnceUserUUID = make([]byte, 16)
	}

	for {
		n, err := tf.remote.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.V("[Forwarder] Downlink read error: %v", err)
			}
			return
		}

		if n == 0 {
			continue
		}

		data := buf[:n]

		if tf.enableFlow && tf.flowState != nil {
			data = tf.flowState.PadDownlink(data, &writeOnceUserUUID)
		}

		sendData := make([]byte, len(data))
		copy(sendData, data)

		if err := tf.transport.Write(sendData); err != nil {
			log.V("[Forwarder] Downlink write error: %v", err)
			return
		}
	}
}

func (tf *TunnelForwarder) Wait() <-chan struct{} {
	done := make(chan struct{})
	go func() {
		<-tf.done
		close(done)
	}()
	return done
}
