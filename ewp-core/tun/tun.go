package tun

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"ewp-core/log"
	"ewp-core/transport"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
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
	device  tun.Tun
	stack   tun.Stack
	handler *Handler
	config  *Config
	ctx     context.Context
	cancel  context.CancelFunc
}

type tunLogger struct{}

func (l *tunLogger) Trace(args ...interface{})                   { log.V(fmt.Sprint(args...)) }
func (l *tunLogger) Debug(args ...interface{})                   { log.V(fmt.Sprint(args...)) }
func (l *tunLogger) Info(args ...interface{})                    { log.Printf(fmt.Sprint(args...)) }
func (l *tunLogger) Warn(args ...interface{})                    { log.Printf(fmt.Sprint(args...)) }
func (l *tunLogger) Error(args ...interface{})                   { log.Printf(fmt.Sprint(args...)) }
func (l *tunLogger) Fatal(args ...interface{})                   { log.Printf(fmt.Sprint(args...)) }
func (l *tunLogger) Panic(args ...interface{})                   { log.Printf(fmt.Sprint(args...)) }
func (l *tunLogger) TraceContext(ctx context.Context, args ...interface{}) { log.V(fmt.Sprint(args...)) }
func (l *tunLogger) DebugContext(ctx context.Context, args ...interface{}) { log.V(fmt.Sprint(args...)) }
func (l *tunLogger) InfoContext(ctx context.Context, args ...interface{})  { log.Printf(fmt.Sprint(args...)) }
func (l *tunLogger) WarnContext(ctx context.Context, args ...interface{})  { log.Printf(fmt.Sprint(args...)) }
func (l *tunLogger) ErrorContext(ctx context.Context, args ...interface{}) { log.Printf(fmt.Sprint(args...)) }
func (l *tunLogger) FatalContext(ctx context.Context, args ...interface{}) { log.Printf(fmt.Sprint(args...)) }
func (l *tunLogger) PanicContext(ctx context.Context, args ...interface{}) { log.Printf(fmt.Sprint(args...)) }

var _ logger.Logger = (*tunLogger)(nil)

func New(cfg *Config) (*TUN, error) {
	ctx, cancel := context.WithCancel(context.Background())

	handler := NewHandler(ctx, cfg.Transport)

	mtu := uint32(cfg.MTU)
	if mtu == 0 {
		mtu = 1500
	}

	inet4Addr, err := netip.ParsePrefix(cfg.IP + "/24")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("parse IP address failed: %w", err)
	}

	dnsAddrs := []netip.Addr{}
	if cfg.DNS != "" {
		dnsAddr, err := netip.ParseAddr(cfg.DNS)
		if err == nil {
			dnsAddrs = append(dnsAddrs, dnsAddr)
		}
	}

	tunOptions := tun.Options{
		Name:         "ewp-tun",
		Inet4Address: []netip.Prefix{inet4Addr},
		MTU:          mtu,
		AutoRoute:    true,
		DNSServers:   dnsAddrs,
		Logger:       &tunLogger{},
	}

	tunDevice, err := tun.New(tunOptions)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create TUN device failed: %w", err)
	}

	stackOptions := tun.StackOptions{
		Context:    ctx,
		Tun:        tunDevice,
		TunOptions: tunOptions,
		Handler:    handler,
		Logger:     &tunLogger{},
		UDPTimeout: 5 * time.Minute,
	}

	stack, err := tun.NewStack("system", stackOptions)
	if err != nil {
		tunDevice.Close()
		cancel()
		return nil, fmt.Errorf("create stack failed: %w", err)
	}

	return &TUN{
		device:  tunDevice,
		stack:   stack,
		handler: handler,
		config:  cfg,
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

func (t *TUN) Start() error {
	if err := t.stack.Start(); err != nil {
		return fmt.Errorf("start stack failed: %w", err)
	}

	log.Printf("[TUN] TUN mode started, IP: %s", t.config.IP)

	select {}
}

func (t *TUN) Close() error {
	log.Printf("[TUN] Stopping TUN mode...")

	if t.stack != nil {
		t.stack.Close()
	}

	if t.device != nil {
		t.device.Close()
	}

	if t.cancel != nil {
		t.cancel()
	}

	log.Printf("[TUN] TUN mode stopped")
	return nil
}
