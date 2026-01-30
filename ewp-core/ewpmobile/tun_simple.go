//go:build android

package ewpmobile

import (
	"fmt"
	"log"
	"sync"

	"ewp-core/tun"
	"ewp-core/transport"
)

// SimpleTUN 简化的 TUN 管理器，专为 Android Kotlin VPNService 设计
// 不使用 C 导出，而是提供 Go 原生接口供 GoMobile 绑定
type SimpleTUN struct {
	mu        sync.RWMutex
	device    *tun.Device
	stack     *tun.Stack
	tcpHandler *tun.TCPHandler
	udpHandler *tun.UDPHandler
	running   bool
	
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
	
	log.Printf("[SimpleTUN] Starting with FD=%d, MTU=%d", st.fd, st.mtu)
	
	// 1. 创建设备
	device, err := tun.NewDeviceFromFD(st.fd, st.mtu)
	if err != nil {
		return fmt.Errorf("create device failed: %w", err)
	}
	st.device = device
	
	// 2. 创建网络栈
	stack, err := tun.NewStack(st.mtu, gateway)
	if err != nil {
		device.Close()
		return fmt.Errorf("create stack failed: %w", err)
	}
	st.stack = stack
	
	// 3. 附加端点
	device.AttachEndpoint(stack.Endpoint())
	
	// 4. 配置网络（Android 上由 VPNService 处理）
	if err := device.Configure(ip, gateway, mask, dns); err != nil {
		log.Printf("[SimpleTUN] Configure warning: %v", err)
	}
	
	// 5. 启动设备
	device.Start()
	
	// 6. 创建处理器（如果有传输层）
	if st.transport != nil {
		st.tcpHandler = tun.NewTCPHandler(stack.Stack(), st.transport)
		st.udpHandler = tun.NewUDPHandler(stack.Stack(), st.transport, dns)
		
		go func() {
			if err := st.tcpHandler.Start(); err != nil {
				log.Printf("[SimpleTUN] TCP handler error: %v", err)
			}
		}()
		
		st.udpHandler.Start()
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
	
	// 停止处理器
	if st.udpHandler != nil {
		st.udpHandler.Close()
		st.udpHandler = nil
	}
	
	// 关闭设备
	if st.device != nil {
		st.device.Close()
		st.device = nil
	}
	
	// 清理网络栈
	if st.stack != nil {
		st.stack.Close()
		st.stack = nil
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
