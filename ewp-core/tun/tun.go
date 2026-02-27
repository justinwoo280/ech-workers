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
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
)

type Config struct {
	IP          string
	DNS         string
	IPv6        string
	IPv6DNS     string
	MTU         int
	Stack       string
	AutoRoute   bool
	StrictRoute bool
	Transport   transport.Transport
}

type TUN struct {
	device           tun.Tun
	stack            tun.Stack
	handler          *Handler
	config           *Config
	ctx              context.Context
	cancel           context.CancelFunc
	networkMonitor   tun.NetworkUpdateMonitor
	interfaceMonitor tun.DefaultInterfaceMonitor
}

type tunLogger struct{}

func (l *tunLogger) Trace(args ...interface{}) { log.V("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Debug(args ...interface{}) { log.V("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Info(args ...interface{})  { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Warn(args ...interface{})  { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Error(args ...interface{}) { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Fatal(args ...interface{}) { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) Panic(args ...interface{}) { log.Printf("%s", fmt.Sprint(args...)) }
func (l *tunLogger) TraceContext(ctx context.Context, args ...interface{}) {
	log.V("%s", fmt.Sprint(args...))
}
func (l *tunLogger) DebugContext(ctx context.Context, args ...interface{}) {
	log.V("%s", fmt.Sprint(args...))
}
func (l *tunLogger) InfoContext(ctx context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}
func (l *tunLogger) WarnContext(ctx context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}
func (l *tunLogger) ErrorContext(ctx context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}
func (l *tunLogger) FatalContext(ctx context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}
func (l *tunLogger) PanicContext(ctx context.Context, args ...interface{}) {
	log.Printf("%s", fmt.Sprint(args...))
}

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
	inet6Addrs := []netip.Prefix{}
	if cfg.IPv6 != "" {
		inet6Addr, err := netip.ParsePrefix(cfg.IPv6)
		if err != nil {
			log.Printf("[TUN] Warning: invalid IPv6 address %s: %v", cfg.IPv6, err)
		} else {
			inet6Addrs = append(inet6Addrs, inet6Addr)
		}
	}

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
	}

	stackName := cfg.Stack
	if stackName == "" {
		stackName = "system"
	}
	cfg.Stack = stackName

	tunLog := &tunLogger{}
	interfaceFinder := control.NewDefaultInterfaceFinder()

	networkMonitor, err := tun.NewNetworkUpdateMonitor(tunLog)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create network monitor failed: %w", err)
	}
	if err := networkMonitor.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start network monitor failed: %w", err)
	}

	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, tunLog, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		networkMonitor.Close()
		cancel()
		return nil, fmt.Errorf("create interface monitor failed: %w", err)
	}
	if err := interfaceMonitor.Start(); err != nil {
		networkMonitor.Close()
		cancel()
		return nil, fmt.Errorf("start interface monitor failed: %w", err)
	}

	tunOptions := tun.Options{
		Name:             "ewp-tun",
		Inet4Address:     []netip.Prefix{inet4Addr},
		Inet6Address:     inet6Addrs,
		MTU:              mtu,
		AutoRoute:        cfg.AutoRoute,
		StrictRoute:      cfg.StrictRoute,
		DNSServers:       dnsAddrs,
		InterfaceFinder:  interfaceFinder,
		InterfaceMonitor: interfaceMonitor,
		Logger:           tunLog,
	}

	tunDevice, err := tun.New(tunOptions)
	if err != nil {
		interfaceMonitor.Close()
		networkMonitor.Close()
		cancel()
		return nil, fmt.Errorf("create TUN device failed: %w", err)
	}

	stackOptions := tun.StackOptions{
		Context:         ctx,
		Tun:             tunDevice,
		TunOptions:      tunOptions,
		Handler:         handler,
		Logger:          tunLog,
		UDPTimeout:      5 * time.Minute,
		InterfaceFinder: interfaceFinder,
	}

	stack, err := tun.NewStack(stackName, stackOptions)
	if err != nil {
		tunDevice.Close()
		interfaceMonitor.Close()
		networkMonitor.Close()
		cancel()
		return nil, fmt.Errorf("create stack failed: %w", err)
	}

	return &TUN{
		device:           tunDevice,
		stack:            stack,
		handler:          handler,
		config:           cfg,
		ctx:              ctx,
		cancel:           cancel,
		networkMonitor:   networkMonitor,
		interfaceMonitor: interfaceMonitor,
	}, nil
}

func (t *TUN) Start() error {
	if err := t.stack.Start(); err != nil {
		return fmt.Errorf("start stack failed: %w", err)
	}

	log.Printf("[TUN] TUN mode started (stack=%s, auto_route=%v, strict_route=%v)",
		t.config.Stack, t.config.AutoRoute, t.config.StrictRoute)
	log.Printf("[TUN] IPv4: %s", t.config.IP)
	if t.config.IPv6 != "" {
		log.Printf("[TUN] IPv6: %s", t.config.IPv6)
	}
	log.Printf("[TUN] DNS: IPv4=%s, IPv6=%s", t.config.DNS, t.config.IPv6DNS)

	<-t.ctx.Done()
	return nil
}

func (t *TUN) Close() error {
	log.Printf("[TUN] Stopping TUN mode...")

	if t.cancel != nil {
		t.cancel()
	}

	if t.stack != nil {
		t.stack.Close()
	}

	if t.device != nil {
		t.device.Close()
	}

	if t.interfaceMonitor != nil {
		t.interfaceMonitor.Close()
	}

	if t.networkMonitor != nil {
		t.networkMonitor.Close()
	}

	log.Printf("[TUN] TUN mode stopped")
	return nil
}
