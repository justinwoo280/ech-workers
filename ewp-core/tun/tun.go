package tun

import (
	"fmt"

	"ewp-core/log"
	"ewp-core/transport"
)

type Config struct {
	IP        string
	Gateway   string
	Mask      string
	DNS       string
	MTU       int
	Transport transport.Transport
}

type TUN struct {
	device     *Device
	stack      *Stack
	tcpHandler *TCPHandler
	udpHandler *UDPHandler
	config     *Config
}

func New(cfg *Config) (*TUN, error) {
	if !IsAdmin() {
		return nil, fmt.Errorf("TUN mode requires administrator privileges")
	}

	device, err := NewDevice(cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create device failed: %w", err)
	}

	if err := device.Configure(cfg.IP, cfg.Gateway, cfg.Mask, cfg.DNS); err != nil {
		device.Close()
		return nil, fmt.Errorf("configure device failed: %w", err)
	}

	stack, err := NewStack(cfg.MTU, cfg.Gateway)
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("create network stack failed: %w", err)
	}

	device.AttachEndpoint(stack.Endpoint())

	if err := ConfigureRouting(cfg.Gateway); err != nil {
		device.Close()
		return nil, fmt.Errorf("configure routing failed: %w", err)
	}

	tcpHandler := NewTCPHandler(stack.Stack(), cfg.Transport)
	udpHandler := NewUDPHandler(stack.Stack(), cfg.Transport, cfg.DNS)

	return &TUN{
		device:     device,
		stack:      stack,
		tcpHandler: tcpHandler,
		udpHandler: udpHandler,
		config:     cfg,
	}, nil
}

func (t *TUN) Start() error {
	t.device.Start()

	go func() {
		if err := t.tcpHandler.Start(); err != nil {
			log.Printf("[TUN] TCP handler error: %v", err)
		}
	}()

	t.udpHandler.Start()

	log.Printf("[TUN] TUN mode started, IP: %s", t.config.IP)

	select {}
}

func (t *TUN) Close() error {
	log.Printf("[TUN] Stopping TUN mode...")

	if t.udpHandler != nil {
		t.udpHandler.Close()
	}

	CleanupRouting(t.config.Gateway)

	if t.device != nil {
		return t.device.Close()
	}

	return nil
}
