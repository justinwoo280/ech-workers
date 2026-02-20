package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	commonnet "ewp-core/common/net"
	log "ewp-core/log"
	"ewp-core/internal/server"
	pb "ewp-core/proto"
	grpctransport "ewp-core/transport/grpc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
)

type proxyServer struct {
	pb.UnimplementedProxyServiceServer
}

type grpcServerStream struct {
	grpc.ServerStream
}

func (s *grpcServerStream) Send(m *pb.SocketData) error {
	return s.ServerStream.SendMsg(m)
}

func (s *grpcServerStream) Recv() (*pb.SocketData, error) {
	m := new(pb.SocketData)
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func tunnelHandler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(*proxyServer).Tunnel(&grpcServerStream{stream})
}

func (s *proxyServer) Tunnel(stream pb.ProxyService_TunnelServer) error {
	clientIP := "unknown"
	if p, ok := peer.FromContext(stream.Context()); ok {
		clientIP = p.Addr.String()
	}
	log.Info("gRPC client connected from %s", clientIP)

	firstMsg, err := stream.Recv()
	if err != nil {
		log.Warn("gRPC: Failed to read handshake: %v", err)
		return err
	}

	opts := server.TunnelOptions{
		Protocol:  newProtocolHandler(),
		Transport: grpctransport.NewServerAdapter(stream),
		ClientIP:  clientIP,
		Timeout:   10 * time.Second,
	}
	return server.EstablishTunnel(context.Background(), firstMsg.GetContent(), opts)
}

func startGRPCServer() {
	lis, err := commonnet.ListenTFO("tcp", ":"+port)
	if err != nil {
		log.Fatalf("gRPC listen failed: %v", err)
	}
	log.Info("gRPC listener ready (TFO)")

	s := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.MaxConcurrentStreams(100),
		grpc.InitialWindowSize(1<<20),
		grpc.InitialConnWindowSize(1<<20),
		grpc.WriteBufferSize(32*1024),
		grpc.ReadBufferSize(32*1024),
	)
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: grpcService,
		HandlerType: (*pb.ProxyServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Tunnel",
				Handler:       tunnelHandler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "tunnel.proto",
	}, &proxyServer{})
	log.Info("gRPC service: /%s/Tunnel", grpcService)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("Gracefully stopping gRPC server")
		s.GracefulStop()
	}()

	log.Info("gRPC server listening (no TLS)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("gRPC serve failed: %v", err)
	}
}
