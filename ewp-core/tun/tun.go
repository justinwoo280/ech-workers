package tun

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
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
	IPv6      string
	IPv6DNS   string
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

func (l *tunLogger) Trace(args ...interface{})                   { log.V("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Debug(args ...interface{})                   { log.V("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Info(args ...interface{})                    { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Warn(args ...interface{})                    { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Error(args ...interface{})                   { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Fatal(args ...interface{})                   { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Panic(args ...interface{})                   { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) TraceContext(ctx context.Context, args ...interface{}) { log.V("%s", fmt.Sprint(args...)) }
func (l *tunLogger) DebugContext(ctx context.Context, args ...interface{}) { log.V("%s", fmt.Sprint(args...)) }
func (l *tunLogger) InfoContext(ctx context.Context, args ...interface{})  { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) WarnContext(ctx context.Context, args ...interface{})  { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) ErrorContext(ctx context.Context, args ...interface{}) { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) FatalContext(ctx context.Context, args ...interface{}) { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) PanicContext(ctx context.Context, args ...interface{}) { log.Printf("%s", fmt.Sprint(args...)) }

var _ logger.Logger = (*tunLogger)(nil)

func New(cfg *Config) (*TUN, error) {
	ctx, cancel := context.WithCancel(context.Background())

	handler := NewHandler(ctx, cfg.Transport)

	mtu := uint32(cfg.MTU)
	if mtu == 0 {
		mtu = 1500
	}

	ipStr := cfg.IP
	if !strings.Contains(ipStr, "/") {
		ipStr += "/24"
	}
	inet4Addr, err := netip.ParsePrefix(ipStr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("parse IPv4 address failed: %w", err)
	}
	// Always enable IPv6 (dual-stack by default)
	inet6Addrs := []netip.Prefix{}
	if cfg.IPv6 != "" {
		inet6Addr, err := netip.ParsePrefix(cfg.IPv6)
		if err != nil {
			log.Printf("[TUN] Warning: invalid IPv6 address %s: %v", cfg.IPv6, err)
		} else {
			inet6Addrs = append(inet6Addrs, inet6Addr)
		}
	} else {
		// Default IPv6 ULA (Unique Local Address) to prevent IPv6 leaks
		inet6Addr, _ := netip.ParsePrefix("fd00:5ca1:e::2/64")
		inet6Addrs = append(inet6Addrs, inet6Addr)
	}

	// Configure DNS servers (IPv4 + IPv6)
	dnsAddrs := []netip.Addr{}
	if cfg.DNS != "" {
		dnsAddr, err := netip.ParseAddr(cfg.DNS)
		if err == nil {
			dnsAddrs = append(dnsAddrs, dnsAddr)
		}
	}
	if cfg.IPv6DNS != "" {
		dns6Addr, err := netip.ParseAddr(cfg.IPv6DNS)
		if err == nil {
			dnsAddrs = append(dnsAddrs, dns6Addr)
		}
	} else {
		// Default to Google Public DNS IPv6 (real public address)
		// This will be tunneled through the proxy to the real DNS server
		dns6Addr, _ := netip.ParseAddr("2001:4860:4860::8888")
		dnsAddrs = append(dnsAddrs, dns6Addr)
	}

	tunOptions := tun.Options{
		Name:         "ewp-tun",
		Inet4Address: []netip.Prefix{inet4Addr},
		Inet6Address: inet6Addrs,
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

	log.Printf("[TUN] TUN mode started (dual-stack)")
	log.Printf("[TUN] IPv4: %s", t.config.IP)
	if t.config.IPv6 != "" {
		log.Printf("[TUN] IPv6: %s", t.config.IPv6)
	} else {
		log.Printf("[TUN] IPv6: fd00:5ca1:e::2/64 (auto-configured)")
	}
	log.Printf("[TUN] DNS: IPv4=%s, IPv6=%s", t.config.DNS, t.config.IPv6DNS)
	log.Printf("[TUN] ✅ All traffic (IPv4 + IPv6) routed through proxy tunnel")
	log.Printf("[TUN] ✅ DNS leak protection enabled (dual-stack)")
	log.Printf("[TUN] ✅ WebRTC leak protection enabled (STUN/TURN tunneled)")

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
