package grpc

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"
	pb "ewp-core/proto"

	"google.golang.org/grpc"
)

type Conn struct {
	conn              *grpc.ClientConn
	stream            grpc.ClientStream
	uuid              [16]byte
	password          string
	mu                sync.Mutex
	enableFlow        bool
	useTrojan         bool
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte
	udpGlobalID       [8]byte
}

func NewConn(conn *grpc.ClientConn, stream grpc.ClientStream, uuid [16]byte, password string, enableFlow, useTrojan bool) *Conn {
	return &Conn{
		conn:       conn,
		stream:     stream,
		uuid:       uuid,
		password:   password,
		enableFlow: enableFlow,
		useTrojan:  useTrojan,
	}
}

func (c *Conn) Connect(target string, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojan(target, initialData)
	}
	return c.connectEWP(target, initialData)
}

func (c *Conn) connectTrojan(target string, initialData []byte) error {
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	key := trojan.GenerateKey(c.password)

	// Build Trojan handshake
	var handshakeData []byte
	handshakeData = append(handshakeData, key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandTCP)

	addrBytes, err := addr.Encode()
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	handshakeData = append(handshakeData, addrBytes...)
	handshakeData = append(handshakeData, trojan.CRLF...)

	// Append initial data
	if len(initialData) > 0 {
		handshakeData = append(handshakeData, initialData...)
	}

	c.mu.Lock()
	err = c.stream.SendMsg(&pb.SocketData{Content: handshakeData})
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send trojan handshake: %w", err)
	}

	log.V("[Trojan] gRPC handshake sent, target: %s", target)
	return nil
}

func (c *Conn) ConnectUDP(target string, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojanUDP(target, initialData)
	}
	return c.connectEWPUDP(target, initialData)
}

func (c *Conn) connectTrojanUDP(target string, initialData []byte) error {
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	key := trojan.GenerateKey(c.password)

	// Build Trojan UDP handshake (without raw initial data)
	var handshakeData []byte
	handshakeData = append(handshakeData, key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandUDP)

	addrBytes, err := addr.Encode()
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	handshakeData = append(handshakeData, addrBytes...)
	handshakeData = append(handshakeData, trojan.CRLF...)

	c.mu.Lock()
	err = c.stream.SendMsg(&pb.SocketData{Content: handshakeData})
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send trojan UDP handshake: %w", err)
	}

	// Send EWP UDPStatusNew as separate message to establish session on server
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	c.udpGlobalID = ewp.NewGlobalID()

	pkt := &ewp.UDPPacket{
		GlobalID: c.udpGlobalID,
		Status:   ewp.UDPStatusNew,
		Target:   udpAddr,
		Payload:  initialData,
	}

	encoded, err := ewp.EncodeUDPPacket(pkt)
	if err != nil {
		return fmt.Errorf("encode UDP new packet: %w", err)
	}

	if err := c.Write(encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
	}

	log.V("[Trojan] gRPC UDP handshake sent, target: %s", target)
	return nil
}

func (c *Conn) connectEWP(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	c.mu.Lock()
	err = c.stream.SendMsg(&pb.SocketData{Content: handshakeData})
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	respMsg := &pb.SocketData{}
	err = c.stream.RecvMsg(respMsg)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respMsg.Content, req.Version, req.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	if len(initialData) > 0 {
		var writeErr error
		for retry := 0; retry < 3; retry++ {
			if retry > 0 {
				time.Sleep(time.Duration(retry*10) * time.Millisecond)
			}

			if err := c.Write(initialData); err != nil {
				writeErr = err
				if retry < 2 && (err == io.EOF ||
					strings.Contains(err.Error(), "connection reset") ||
					strings.Contains(err.Error(), "broken pipe") ||
					strings.Contains(err.Error(), "use of closed network connection")) {
					log.V("[gRPC] Send initial data failed, retry %d/3: %v", retry+1, err)
					continue
				}
				break
			} else {
				writeErr = nil
				break
			}
		}

		if writeErr != nil {
			return fmt.Errorf("send initial data: %w", writeErr)
		}
	}

	log.V("[EWP] gRPC handshake success, target: %s", target)
	return nil
}

func (c *Conn) connectEWPUDP(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	// Use CommandUDP for UDP connections
	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	c.mu.Lock()
	err = c.stream.SendMsg(&pb.SocketData{Content: handshakeData})
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	respMsg := &pb.SocketData{}
	err = c.stream.RecvMsg(respMsg)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respMsg.Content, req.Version, req.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	// Always send UDPStatusNew to establish session on server (with target address)
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	c.udpGlobalID = ewp.NewGlobalID()

	pkt := &ewp.UDPPacket{
		GlobalID: c.udpGlobalID,
		Status:   ewp.UDPStatusNew,
		Target:   udpAddr,
		Payload:  initialData,
	}

	encoded, err := ewp.EncodeUDPPacket(pkt)
	if err != nil {
		return fmt.Errorf("encode UDP packet: %w", err)
	}

	if err := c.Write(encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
	}

	log.V("[EWP] gRPC UDP handshake success, target: %s", target)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel (StatusKeep)
func (c *Conn) WriteUDP(target string, data []byte) error {
	encoded, err := ewp.EncodeUDPKeepPacket(c.udpGlobalID, data)
	if err != nil {
		return fmt.Errorf("encode UDP keep packet: %w", err)
	}
	return c.Write(encoded)
}

// ReadUDP reads and decodes an EWP-framed UDP response packet
func (c *Conn) ReadUDP() ([]byte, error) {
	resp := &pb.SocketData{}
	if err := c.stream.RecvMsg(resp); err != nil {
		return nil, err
	}
	data := resp.Content
	if !c.useTrojan && c.enableFlow && c.flowState != nil {
		data = c.flowState.ProcessDownlink(data)
	}
	return ewp.DecodeUDPPayload(data)
}

func (c *Conn) Read(buf []byte) (int, error) {
	resp := &pb.SocketData{}
	err := c.stream.RecvMsg(resp)
	if err != nil {
		return 0, err
	}

	data := resp.Content

	// Only apply flow processing for EWP mode
	if !c.useTrojan && c.enableFlow && c.flowState != nil {
		data = c.flowState.ProcessDownlink(data)
	}

	n := copy(buf, data)
	return n, nil
}

func (c *Conn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stream == nil {
		return io.EOF
	}

	var writeData []byte
	// Only apply flow processing for EWP mode
	if !c.useTrojan && c.enableFlow && c.flowState != nil {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}

	err := c.stream.SendMsg(&pb.SocketData{Content: writeData})
	if err != nil {
		if strings.Contains(err.Error(), "transport is closing") ||
			strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "broken pipe") {
			return io.EOF
		}
	}
	return err
}

func (c *Conn) Close() error {
	if c.stream != nil {
		c.stream.CloseSend()
	}
	return nil
}

func (c *Conn) StartPing(interval time.Duration) chan struct{} {
	stopChan := make(chan struct{})
	return stopChan
}
