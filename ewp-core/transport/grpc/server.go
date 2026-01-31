package grpc

import (
	pb "ewp-core/proto"
)

type ServerAdapter struct {
	stream pb.ProxyService_TunnelServer
}

func NewServerAdapter(stream pb.ProxyService_TunnelServer) *ServerAdapter {
	return &ServerAdapter{
		stream: stream,
	}
}

func (a *ServerAdapter) Read() ([]byte, error) {
	msg, err := a.stream.Recv()
	if err != nil {
		return nil, err
	}
	return msg.GetContent(), nil
}

func (a *ServerAdapter) Write(data []byte) error {
	sendData := make([]byte, len(data))
	copy(sendData, data)
	return a.stream.Send(&pb.SocketData{Content: sendData})
}

func (a *ServerAdapter) Close() error {
	return nil
}
