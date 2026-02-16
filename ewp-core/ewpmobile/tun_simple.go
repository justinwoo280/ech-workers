//go:build android

package ewpmobile

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/tun"
	"ewp-core/transport"

	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
)

// tunLogger implements logger.Logger for sing-tun
type simpleTunLogger struct{}

func (l *simpleTunLogger) Trace(args ...interface{})                             { log.V(fmt.Sprint(args...)) }
func (l *simpleTunLogger) Debug(args ...interface{})                             { log.V(fmt.Sprint(args...)) }
func (l *simpleTunLogger) Info(args ...interface{})                              { log.Printf(fmt.Sprint(args...)) }
func (l *simpleTunLogger) Warn(args ...interface{})                              { log.Printf(fmt.Sprint(args...)) }
func (l *simpleTunLogger) Error(args ...interface{})                             { log.Printf(fmt.Sprint(args...)) }
func (l *simpleTunLogger) Fatal(args ...interface{})                             { log.Printf(fmt.Sprint(args...)) }
func (l *simpleTunLogger) Panic(args ...interface{})                             { log.Printf(fmt.Sprint(args...)) }
func (l *simpleTunLogger) TraceContext(ctx context.Context, args ...interface{}) { log.V(fmt.Sprint(args...)) }
func (l *simpleTunLogger) DebugContext(ctx context.Context, args ...interface{}) { log.V(fmt.Sprint(args...)) }
func (l *simpleTunLogger) InfoContext(ctx context.Context, args ...interface{})  { log.Printf(fmt.Sprint(args...)) }
func (l *simpleTunLogger) WarnContext(ctx context.Context, args ...interface{})  { log.Printf(fmt.Sprint(args...)) }
func (l *simpleTunLogger) ErrorContext(ctx context.Context, args ...interface{}) { log.Printf(fmt.Sprint(args...)) }
func (l *simpleTunLogger) FatalContext(ctx context.Context, args ...interface{}) { log.Printf(fmt.Sprint(args...)) }
func (l *simpleTunLogger) PanicContext(ctx context.Context, args ...interface{}) { log.Printf(fmt.Sprint(args...)) }

var _ logger.Logger = (*simpleTunLogger)(nil)

// SimpleTUN 简化的 TUN 管理器，专为 Android Kotlin VPNService 设计
// 不使用 C 导出，而是提供 Go 原生接口供 GoMobile 绑定
type SimpleTUN struct {
	mu         sync.RWMutex
	tunDevice  singtun.Tun
	tunStack   singtun.Stack
	tunHandler *tun.Handler
	running    bool
	ctx        context.Context
	cancel     context.CancelFunc
	
	fd        int
	mtu       int
	transport transport.Transport
}

// NewSimpleTUN 创建简化的 TUN 实例
func NewSimpleTUN(fd int, mtu int) (*SimpleTUN, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid file descriptor: %d", fd)
	}
	
	if mtu <= 0 {
		mtu = 1500
	}
	
	return &SimpleTUN{
		fd:      fd,
		mtu:     mtu,
		running: false,
	}, nil
}

// SetTransport 设置传输层（必须在 Start 之前调用）
func (st *SimpleTUN) SetTransport(serverAddr string, token string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	if st.running {
		return fmt.Errorf("cannot set transport while running")
	}
	
	// 这里可以创建传输层实例
	// 暂时留空，让调用者自己管理传输层
	log.Printf("[SimpleTUN] Transport configured: %s", serverAddr)
	
	return nil
}

// Start 启动 TUN
func (st *SimpleTUN) Start(ip, gateway, mask, dns string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	if st.running {
		return fmt.Errorf("TUN already running")
	}
	
	if st.transport == nil {
		return fmt.Errorf("transport not set")
	}
	
	log.Printf("[SimpleTUN] Starting with FD=%d, MTU=%d", st.fd, st.mtu)
	
	// 1. 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	st.ctx = ctx
	st.cancel = cancel
	
	// 2. 创建处理器
	st.tunHandler = tun.NewHandler(ctx, st.transport)
	
	// 3. 解析地址
	inet4Addr, err := netip.ParsePrefix(ip + "/24")
	if err != nil {
		cancel()
		return fmt.Errorf("parse IP address failed: %w", err)
	}
	
	dnsAddr, err := netip.ParseAddr(dns)
	if err != nil {
		cancel()
		return fmt.Errorf("parse DNS address failed: %w", err)
	}
	
	// 4. 配置 TUN 选项
	tunOptions := singtun.Options{
		Name:            "ewp-simple",
		Inet4Address:    []netip.Prefix{inet4Addr},
		MTU:             uint32(st.mtu),
		AutoRoute:       false, // Android VPNService handles routing
		DNSServers:      []netip.Addr{dnsAddr},
		FileDescriptor:  st.fd,
		Logger:          &simpleTunLogger{},
	}
	
	// 5. 创建 TUN 设备
	st.tunDevice, err = singtun.New(tunOptions)
	if err != nil {
		cancel()
		return fmt.Errorf("create TUN device failed: %w", err)
	}
	
	// 6. 创建网络栈
	stackOptions := singtun.StackOptions{
		Context:    ctx,
		Tun:        st.tunDevice,
		TunOptions: tunOptions,
		Handler:    st.tunHandler,
		Logger:     &simpleTunLogger{},
		UDPTimeout: 5 * time.Minute,
	}
	
	st.tunStack, err = singtun.NewStack("system", stackOptions)
	if err != nil {
		st.tunDevice.Close()
		cancel()
		return fmt.Errorf("create network stack failed: %w", err)
	}
	
	// 7. 启动网络栈
	if err := st.tunStack.Start(); err != nil {
		st.tunStack.Close()
		st.tunDevice.Close()
		cancel()
		return fmt.Errorf("start network stack failed: %w", err)
	}
	
	st.running = true
	log.Printf("[SimpleTUN] Started successfully")
	
	return nil
}

// Stop 停止 TUN
func (st *SimpleTUN) Stop() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	if !st.running {
		return nil
	}
	
	log.Printf("[SimpleTUN] Stopping...")
	
	// 停止网络栈
	if st.tunStack != nil {
		st.tunStack.Close()
		st.tunStack = nil
	}
	
	// 关闭设备
	if st.tunDevice != nil {
		st.tunDevice.Close()
		st.tunDevice = nil
	}
	
	// 取消上下文
	if st.cancel != nil {
		st.cancel()
	}
	
	st.running = false
	log.Printf("[SimpleTUN] Stopped")
	
	return nil
}

// IsRunning 检查运行状态
func (st *SimpleTUN) IsRunning() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.running
}

// GetStats 获取统计信息（返回 JSON 字符串）
func (st *SimpleTUN) GetStats() string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	if !st.running {
		return `{"running":false}`
	}
	
	return fmt.Sprintf(`{"running":true,"mtu":%d,"fd":%d}`, st.mtu, st.fd)
}
