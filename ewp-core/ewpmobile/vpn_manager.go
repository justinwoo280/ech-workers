package ewpmobile

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"
	"ewp-core/transport/grpc"
	"ewp-core/transport/websocket"
	"ewp-core/transport/xhttp"
	"ewp-core/tun"
)

// VPNManager 统一的 VPN 管理器，集成连接和 TUN 功能
type VPNManager struct {
	mu           sync.RWMutex
	running      bool
	ctx          context.Context
	cancel       context.CancelFunc
	
	// 传输层
	transport    transport.Transport
	
	// TUN 相关
	tunFD        int
	tunMTU       int
	device       *tun.Device
	stack        *tun.Stack
	tcpHandler   *tun.TCPHandler
	udpHandler   *tun.UDPHandler
	
	// 配置
	config       *VPNConfig
	
	// 统计
	startTime    time.Time
	bytesUp      uint64
	bytesDown    uint64
	connections  uint64
}

// VPNConfig VPN 配置
type VPNConfig struct {
	// 服务器配置
	ServerAddr   string
	ServerIP     string
	Token        string
	Password     string
	
	// 协议配置
	Protocol     string  // "ws" / "grpc" / "xhttp"
	AppProtocol  string  // "ewp" / "trojan"
	Path         string  // WebSocket 路径 或 gRPC 服务名
	
	// 安全配置
	EnableECH    bool
	EnableFlow   bool
	EnablePQC    bool
	ECHDomain    string
	DNSServer    string
	
	// TUN 配置
	TunIP        string
	TunGateway   string
	TunMask      string
	TunDNS       string
	TunMTU       int
}

// NewVPNManager 创建 VPN 管理器
func NewVPNManager() *VPNManager {
	return &VPNManager{
		running: false,
	}
}

// Start 启动 VPN（连接 + TUN）
func (vm *VPNManager) Start(tunFD int, config *VPNConfig) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	
	if vm.running {
		return fmt.Errorf("VPN already running")
	}
	
	log.Printf("[VPNManager] Starting VPN: server=%s, protocol=%s", config.ServerAddr, config.Protocol)
	
	// 检查 socket 保护器
	if !IsSocketProtectorSet() {
		log.Printf("[VPNManager] Warning: Socket protector not set, may cause VPN loop")
	}
	
	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	vm.ctx = ctx
	vm.cancel = cancel
	vm.config = config
	vm.tunFD = tunFD
	vm.tunMTU = config.TunMTU
	if vm.tunMTU <= 0 {
		vm.tunMTU = 1400
	}
	
	// 1. 初始化 ECH（如果启用）
	var echMgr *tls.ECHManager
	if config.EnableECH {
		log.Printf("[VPNManager] Initializing ECH...")
		echDomain := config.ECHDomain
		if echDomain == "" {
			echDomain = "cloudflare-ech.com"
		}
		dnsServer := config.DNSServer
		if dnsServer == "" {
			dnsServer = "dns.alidns.com/dns-query"
		}
		
		echMgr = tls.NewECHManager(echDomain, dnsServer)
		if err := echMgr.Refresh(); err != nil {
			log.Printf("[VPNManager] ECH initialization failed: %v, falling back to plain TLS", err)
			config.EnableECH = false
		}
	}
	
	// 2. 创建传输层
	log.Printf("[VPNManager] Creating transport: %s", config.Protocol)
	useTrojan := config.AppProtocol == "trojan"
	var err error
	
	switch config.Protocol {
	case "ws", "websocket":
		vm.transport = websocket.NewWithProtocol(
			config.ServerAddr,
			config.ServerIP,
			config.Token,
			config.Password,
			config.EnableECH,
			config.EnableFlow,
			config.EnablePQC,
			useTrojan,
			config.Path,
			echMgr,
		)
	case "grpc":
		vm.transport = grpc.NewWithProtocol(
			config.ServerAddr,
			config.ServerIP,
			config.Token,
			config.Password,
			config.EnableECH,
			config.EnableFlow,
			config.EnablePQC,
			useTrojan,
			config.Path,
			echMgr,
		)
	case "xhttp":
		vm.transport = xhttp.NewWithProtocol(
			config.ServerAddr,
			config.ServerIP,
			config.Token,
			config.Password,
			config.EnableECH,
			config.EnableFlow,
			config.EnablePQC,
			useTrojan,
			config.Path,
			echMgr,
		)
	default:
		cancel()
		return fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}
	
	// 3. 测试连接
	log.Printf("[VPNManager] Testing connection...")
	testConn, err := vm.transport.Dial()
	if err != nil {
		cancel()
		return fmt.Errorf("connection test failed: %w", err)
	}
	testConn.Close()
	log.Printf("[VPNManager] Connection test successful")
	
	// 4. 创建 TUN 设备
	log.Printf("[VPNManager] Creating TUN device from FD=%d, MTU=%d", tunFD, vm.tunMTU)
	vm.device, err = tun.NewDeviceFromFD(tunFD, vm.tunMTU)
	if err != nil {
		cancel()
		return fmt.Errorf("create TUN device failed: %w", err)
	}
	
	// 5. 创建网络栈
	gateway := config.TunGateway
	if gateway == "" {
		gateway = "10.0.0.1"
	}
	log.Printf("[VPNManager] Creating network stack with gateway=%s", gateway)
	vm.stack, err = tun.NewStack(vm.tunMTU, gateway)
	if err != nil {
		vm.device.Close()
		cancel()
		return fmt.Errorf("create network stack failed: %w", err)
	}
	
	// 6. 附加端点
	vm.device.AttachEndpoint(vm.stack.Endpoint())
	
	// 7. 配置网络（Android 上由 VPNService 处理）
	ip := config.TunIP
	if ip == "" {
		ip = "10.0.0.2"
	}
	mask := config.TunMask
	if mask == "" {
		mask = "255.255.255.0"
	}
	dns := config.TunDNS
	if dns == "" {
		dns = "8.8.8.8"
	}
	if err := vm.device.Configure(ip, gateway, mask, dns); err != nil {
		log.Printf("[VPNManager] Configure warning: %v", err)
	}
	
	// 8. 启动设备
	vm.device.Start()
	
	// 9. 创建 TCP/UDP 处理器
	log.Printf("[VPNManager] Starting TCP/UDP handlers...")
	vm.tcpHandler = tun.NewTCPHandler(vm.stack.Stack(), vm.transport)
	vm.udpHandler = tun.NewUDPHandler(vm.stack.Stack(), vm.transport, dns)
	
	go func() {
		if err := vm.tcpHandler.Start(); err != nil {
			log.Printf("[VPNManager] TCP handler error: %v", err)
		}
	}()
	
	vm.udpHandler.Start()
	
	vm.running = true
	vm.startTime = time.Now()
	
	log.Printf("[VPNManager] VPN started successfully")
	return nil
}

// Stop 停止 VPN
func (vm *VPNManager) Stop() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	
	if !vm.running {
		return nil
	}
	
	log.Printf("[VPNManager] Stopping VPN...")
	
	// 取消上下文
	if vm.cancel != nil {
		vm.cancel()
	}
	
	// 停止 UDP 处理器
	if vm.udpHandler != nil {
		vm.udpHandler.Close()
		vm.udpHandler = nil
	}
	
	// 停止 TCP 处理器
	if vm.tcpHandler != nil {
		// TCP handler 会自动停止
		vm.tcpHandler = nil
	}
	
	// 关闭设备
	if vm.device != nil {
		vm.device.Close()
		vm.device = nil
	}
	
	// 关闭网络栈
	if vm.stack != nil {
		vm.stack.Close()
		vm.stack = nil
	}
	
	// 清空传输层引用
	if vm.transport != nil {
		vm.transport = nil
	}
	
	vm.running = false
	
	log.Printf("[VPNManager] VPN stopped")
	return nil
}

// IsRunning 检查运行状态
func (vm *VPNManager) IsRunning() bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.running
}

// GetStats 获取统计信息（返回 JSON 字符串）
func (vm *VPNManager) GetStats() string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	
	if !vm.running {
		return `{"running":false}`
	}
	
	uptime := time.Since(vm.startTime).Seconds()
	
	stats := map[string]interface{}{
		"running":       true,
		"uptime":        uptime,
		"bytes_up":      vm.bytesUp,
		"bytes_down":    vm.bytesDown,
		"connections":   vm.connections,
		"server_addr":   vm.config.ServerAddr,
		"protocol":      vm.config.Protocol,
		"app_protocol":  vm.config.AppProtocol,
		"enable_ech":    vm.config.EnableECH,
		"enable_flow":   vm.config.EnableFlow,
		"tun_mtu":       vm.tunMTU,
	}
	
	// 传输层统计（暂未实现）
	
	jsonData, _ := json.Marshal(stats)
	return string(jsonData)
}

// UpdateStats 更新统计信息（内部使用）
func (vm *VPNManager) UpdateStats(bytesUp, bytesDown uint64) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.bytesUp += bytesUp
	vm.bytesDown += bytesDown
}

// IncrementConnections 增加连接计数
func (vm *VPNManager) IncrementConnections() {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.connections++
}
