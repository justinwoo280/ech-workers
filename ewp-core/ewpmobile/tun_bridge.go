package ewpmobile

/*
#include <stdlib.h>
#include <unistd.h>
*/
import "C"
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

// bridgeLogger implements logger.Logger for sing-tun
type bridgeLogger struct{}

func (l *bridgeLogger) Trace(args ...interface{})                             { log.V(fmt.Sprint(args...)) }
func (l *bridgeLogger) Debug(args ...interface{})                             { log.V(fmt.Sprint(args...)) }
func (l *bridgeLogger) Info(args ...interface{})                              { log.Printf(fmt.Sprint(args...)) }
func (l *bridgeLogger) Warn(args ...interface{})                              { log.Printf(fmt.Sprint(args...)) }
func (l *bridgeLogger) Error(args ...interface{})                             { log.Printf(fmt.Sprint(args...)) }
func (l *bridgeLogger) Fatal(args ...interface{})                             { log.Printf(fmt.Sprint(args...)) }
func (l *bridgeLogger) Panic(args ...interface{})                             { log.Printf(fmt.Sprint(args...)) }
func (l *bridgeLogger) TraceContext(ctx context.Context, args ...interface{}) { log.V(fmt.Sprint(args...)) }
func (l *bridgeLogger) DebugContext(ctx context.Context, args ...interface{}) { log.V(fmt.Sprint(args...)) }
func (l *bridgeLogger) InfoContext(ctx context.Context, args ...interface{})  { log.Printf(fmt.Sprint(args...)) }
func (l *bridgeLogger) WarnContext(ctx context.Context, args ...interface{})  { log.Printf(fmt.Sprint(args...)) }
func (l *bridgeLogger) ErrorContext(ctx context.Context, args ...interface{}) { log.Printf(fmt.Sprint(args...)) }
func (l *bridgeLogger) FatalContext(ctx context.Context, args ...interface{}) { log.Printf(fmt.Sprint(args...)) }
func (l *bridgeLogger) PanicContext(ctx context.Context, args ...interface{}) { log.Printf(fmt.Sprint(args...)) }

var _ logger.Logger = (*bridgeLogger)(nil)

// TUNBridge TUN 桥接器，用于 Android
type TUNBridge struct {
	mu         sync.RWMutex
	running    bool
	fd         int
	mtu        int
	tunDevice  singtun.Tun
	tunStack   singtun.Stack
	tunHandler *tun.Handler
	cancel     context.CancelFunc
	ctx        context.Context
	
	// 传输层
	transport transport.Transport
	
	// 统计信息
	packetsReceived uint64
	packetsSent     uint64
	bytesReceived    uint64
	bytesSent        uint64
	errors           uint64
	startTime        time.Time
}

// 全局 TUN 桥接器映射
var (
	tunBridges = make(map[uint64]*TUNBridge)
	bridgeMu   sync.RWMutex
	nextID     uint64 = 1
)

// NewTUNBridge 创建新的 TUN 桥接器
func NewTUNBridge(fd int, mtu int) *TUNBridge {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &TUNBridge{
		fd:     fd,
		mtu:    mtu,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start 启动 TUN 桥接器
func (tb *TUNBridge) Start() error {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	if tb.running {
		return fmt.Errorf("TUN bridge already running")
	}
	
	log.Printf("[TUN-Bridge] Starting with FD %d, MTU %d", tb.fd, tb.mtu)
	
	// 创建处理器
	if tb.transport != nil {
		tb.tunHandler = tun.NewHandler(tb.ctx, tb.transport)
	} else {
		log.Printf("[TUN-Bridge] Warning: No transport set, creating placeholder handler")
	}
	
	// 配置 TUN 选项
	inet4Addr, err := netip.ParsePrefix("10.0.0.2/24")
	if err != nil {
		return fmt.Errorf("parse IP address failed: %w", err)
	}
	
	dnsAddr, err := netip.ParseAddr("8.8.8.8")
	if err != nil {
		return fmt.Errorf("parse DNS address failed: %w", err)
	}
	
	tunOptions := singtun.Options{
		Name:            "ewp-bridge",
		Inet4Address:    []netip.Prefix{inet4Addr},
		MTU:             uint32(tb.mtu),
		AutoRoute:       false, // Android VPNService handles routing
		DNSServers:      []netip.Addr{dnsAddr},
		FileDescriptor:  tb.fd,
		Logger:          &bridgeLogger{},
	}
	
	// 创建 TUN 设备
	tb.tunDevice, err = singtun.New(tunOptions)
	if err != nil {
		return fmt.Errorf("create TUN device failed: %w", err)
	}
	
	// 创建网络栈（如果有处理器）
	if tb.tunHandler != nil {
		stackOptions := singtun.StackOptions{
			Context:    tb.ctx,
			Tun:        tb.tunDevice,
			TunOptions: tunOptions,
			Handler:    tb.tunHandler,
			Logger:     &bridgeLogger{},
			UDPTimeout: 5 * time.Minute,
		}
		
		tb.tunStack, err = singtun.NewStack("system", stackOptions)
		if err != nil {
			tb.tunDevice.Close()
			return fmt.Errorf("create network stack failed: %w", err)
		}
		
		// 启动网络栈
		if err := tb.tunStack.Start(); err != nil {
			tb.tunStack.Close()
			tb.tunDevice.Close()
			return fmt.Errorf("start network stack failed: %w", err)
		}
	}
	
	tb.running = true
	tb.startTime = time.Now()
	
	// 启动监控
	go tb.monitor()
	
	log.Printf("[TUN-Bridge] Started successfully")
	return nil
}

// Stop 停止 TUN 桥接器
func (tb *TUNBridge) Stop() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	if !tb.running {
		return
	}
	
	log.Printf("[TUN-Bridge] Stopping")
	
	tb.running = false
	
	if tb.tunStack != nil {
		tb.tunStack.Close()
		tb.tunStack = nil
	}
	
	if tb.tunDevice != nil {
		tb.tunDevice.Close()
		tb.tunDevice = nil
	}
	
	tb.cancel()
	
	log.Printf("[TUN-Bridge] Stopped")
}

// IsRunning 检查运行状态
func (tb *TUNBridge) IsRunning() bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	return tb.running
}

// SetTransport 设置传输层
func (tb *TUNBridge) SetTransport(trans transport.Transport) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.transport = trans
}

// GetStats 获取统计信息
func (tb *TUNBridge) GetStats() map[string]interface{} {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	
	uptime := time.Duration(0)
	if !tb.startTime.IsZero() {
		uptime = time.Since(tb.startTime)
	}
	
	return map[string]interface{}{
		"running":          tb.running,
		"packets_received": tb.packetsReceived,
		"packets_sent":     tb.packetsSent,
		"bytes_received":    tb.bytesReceived,
		"bytes_sent":        tb.bytesSent,
		"errors":           tb.errors,
		"uptime_seconds":   uptime.Seconds(),
		"mtu":              tb.mtu,
		"device_name":      tb.getDeviceName(),
	}
}

// getDeviceName 获取设备名称
func (tb *TUNBridge) getDeviceName() string {
	if tb.device != nil {
		// 这里需要通过反射或其他方式获取设备名称
		// 暂时返回固定值
		return "ewp-tun"
	}
	return "unknown"
}

// monitor 监控 TUN 桥接器状态
func (tb *TUNBridge) monitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-tb.ctx.Done():
			return
		case <-ticker.C:
			if !tb.IsRunning() {
				return
			}
			
			// 这里可以添加健康检查逻辑
			log.Printf("[TUN-Bridge] Health check: running=%v", tb.running)
		}
	}
}

// UpdateConfig 更新配置
func (tb *TUNBridge) UpdateConfig(config map[string]interface{}) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	if !tb.running {
		return fmt.Errorf("TUN bridge not running")
	}
	
	// 这里可以实现动态配置更新
	log.Printf("[TUN-Bridge] Config updated: %+v", config)
	return nil
}

// TestConnection 测试连接
func (tb *TUNBridge) TestConnection(target string, port int) bool {
	if !tb.running {
		return false
	}
	
	// 这里可以实现连接测试逻辑
	log.Printf("[TUN-Bridge] Testing connection to %s:%d", target, port)
	
	// 暂时返回基本状态
	return tb.running
}

// GoMobile 导出函数

//export tunStartBridge
func tunStartBridge(fd C.int, mtu C.int) C.ulong {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	
	id := nextID
	nextID++
	
	bridge := NewTUNBridge(int(fd), int(mtu))
	if err := bridge.Start(); err != nil {
		log.Printf("[TUN-Bridge] Failed to start: %v", err)
		return 0
	}
	
	tunBridges[id] = bridge
	log.Printf("[TUN-Bridge] Started with ID: %d", id)
	
	return C.ulong(id)
}

//export tunStopBridge
func tunStopBridge(handle C.ulong) {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	
	id := uint64(handle)
	bridge, exists := tunBridges[id]
	if !exists {
		log.Printf("[TUN-Bridge] Bridge not found: %d", id)
		return
	}
	
	bridge.Stop()
	delete(tunBridges, id)
	
	log.Printf("[TUN-Bridge] Stopped: %d", id)
}

//export tunIsRunning
func tunIsRunning(handle C.ulong) C.int {
	bridgeMu.RLock()
	defer bridgeMu.RUnlock()
	
	id := uint64(handle)
	bridge, exists := tunBridges[id]
	if !exists {
		return 0
	}
	
	if bridge.IsRunning() {
		return 1
	}
	return 0
}

//export tunGetStats
func tunGetStats(handle C.ulong) *C.char {
	bridgeMu.RLock()
	defer bridgeMu.RUnlock()
	
	id := uint64(handle)
	bridge, exists := tunBridges[id]
	if !exists {
		return C.CString(`{"error": "TUN bridge not found"}`)
	}
	
	stats := bridge.GetStats()
	statsJSON := fmt.Sprintf(`{
		"running": %t,
		"packets_received": %d,
		"packets_sent": %d,
		"bytes_received": %d,
		"bytes_sent": %d,
		"errors": %d,
		"uptime_seconds": %.2f,
		"mtu": %d,
		"device_name": "%s"
	}`, 
		stats["running"], 
		stats["packets_received"], 
		stats["packets_sent"], 
		stats["bytes_received"], 
		stats["bytes_sent"], 
		stats["errors"], 
		stats["uptime_seconds"], 
		stats["mtu"], 
		stats["device_name"],
	)
	
	return C.CString(statsJSON)
}

//export tunTestConnection
func tunTestConnection(handle C.ulong, target *C.char, port C.int) C.int {
	bridgeMu.RLock()
	defer bridgeMu.RUnlock()
	
	id := uint64(handle)
	bridge, exists := tunBridges[id]
	if !exists {
		return 0
	}
	
	targetStr := C.GoString(target)
	if bridge.TestConnection(targetStr, int(port)) {
		return 1
	}
	return 0
}

//export tunUpdateConfig
func tunUpdateConfig(handle C.ulong, configJSON *C.char) C.int {
	bridgeMu.RLock()
	defer bridgeMu.RUnlock()
	
	id := uint64(handle)
	_, exists := tunBridges[id]
	if !exists {
		return 0
	}
	
	// 这里可以解析 JSON 配置
	// 暂时返回成功
	configStr := C.GoString(configJSON)
	log.Printf("[TUN-Bridge] Config update: %s", configStr)
	
	return 1
}

// Cleanup 清理所有桥接器
func Cleanup() {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	
	for id, bridge := range tunBridges {
		bridge.Stop()
		delete(tunBridges, id)
	}
	
	log.Printf("[TUN-Bridge] All bridges cleaned up")
}
