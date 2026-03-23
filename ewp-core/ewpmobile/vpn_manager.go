//go:build android

package ewpmobile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"ewp-core/common/tls"
	"ewp-core/dns"
	"ewp-core/log"
	"ewp-core/transport"
	"ewp-core/transport/grpc"
	"ewp-core/transport/h3grpc"
	"ewp-core/transport/websocket"
	"ewp-core/transport/xhttp"
	"ewp-core/tun"
	ewpgvisor "ewp-core/tun/gvisor"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type gvisorUDPWriter struct {
	stack *ewpgvisor.Stack
}

func (w *gvisorUDPWriter) WriteTo(p []byte, src netip.AddrPort, dst netip.AddrPort) error {
	if w.stack == nil {
		return fmt.Errorf("stack is nil")
	}
	return w.stack.WriteUDP(p, src, dst)
}

func (w *gvisorUDPWriter) InjectUDP(p []byte, src netip.AddrPort, dst netip.AddrPort) error {
	if w.stack == nil {
		return fmt.Errorf("stack is nil")
	}
	return w.stack.InjectUDP(p, src, dst)
}

func (w *gvisorUDPWriter) ReleaseConn(src netip.AddrPort, dst netip.AddrPort) {
	if w.stack != nil {
		w.stack.ReleaseWriteConn(src, dst)
	}
}

// vpnManager 统一的 VPN 管理器，集成连接和 TUN 功能
type vpnManager struct {
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc

	// 传输层
	transport transport.Transport

	// TUN 相关
	tunFD      int
	tunMTU     int
	tunDevice  wgtun.Device
	tunStack   *ewpgvisor.Stack
	tunHandler *tun.Handler

	// 配置
	config *VPNConfig

	// 统计
	startTime   time.Time
	bytesUp     uint64
	bytesDown   uint64
	connections uint64
}

// VPNConfig VPN 配置
type VPNConfig struct {
	// 服务器配置
	ServerAddr string // 连接目标（IP 或域名，直接 DNS 解析后建立 TCP 连接）
	Token      string
	Password   string

	// 协议配置
	Protocol    string // "ws" / "grpc" / "xhttp" / "h3grpc"
	AppProtocol string // "ewp" / "trojan"
	Path        string // WebSocket 路径 或 gRPC 服务名
	XhttpMode   string // "auto" / "stream-one" / "stream-down"（仅 xhttp）

	// Host/SNI 配置（CDN 场景）
	Host string // HTTP Host 头覆盖（留空则同 ServerAddr）
	SNI  string // TLS SNI 覆盖（留空则同 Host）

	// TLS 配置
	EnableTLS     bool   // 是否启用 TLS（移动端一般始终 true）
	MinTLSVersion string // "1.2" 或 "1.3"
	EnableMozillaCA bool // 是否使用内置 Mozilla Root CAs

	// gRPC / H3gRPC 附加配置
	UserAgent   string // 自定义 User-Agent
	ContentType string // H3gRPC Content-Type

	// 安全配置
	EnableECH  bool
	EnableFlow bool
	EnablePQC  bool
	ECHDomain  string
	DNSServer  string

	// TUN 配置
	TunIP      string
	TunGateway string
	TunMask    string
	TunDNS     string
	TunMTU     int
}

// newVPNManager 创建 VPN 管理器
func newVPNManager() *vpnManager {
	return &vpnManager{
		running: false,
	}
}

// Start 启动 VPN（连接 + TUN）
func (vm *vpnManager) Start(tunFD int, config *VPNConfig) error {
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
			dnsServer = "https://223.5.5.5/dns-query"
		} else if !strings.HasPrefix(dnsServer, "https://") && !strings.HasPrefix(dnsServer, "http://") {
			dnsServer = "https://" + dnsServer
		}

		echMgr = tls.NewECHManager(echDomain, dnsServer)
		if IsSocketProtectorSet() {
			echMgr.SetBypassDialer(makeProtectedBypassConfig().TCPDialer)
		}
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
		var wsT *websocket.Transport
		wsT, err = websocket.NewWithProtocol(
			config.ServerAddr,
			config.Token,
			config.Password,
			config.EnableECH,
			config.EnableMozillaCA,
			config.EnableFlow,
			config.EnablePQC,
			useTrojan,
			config.Path,
			echMgr,
		)
		if err == nil && config.Host != "" {
			wsT.SetHost(config.Host)
		}
		vm.transport = wsT
	case "grpc":
		var grpcT *grpc.Transport
		grpcT, err = grpc.NewWithProtocol(
			config.ServerAddr,
			config.Token,
			config.Password,
			config.EnableECH,
			config.EnableMozillaCA,
			config.EnableFlow,
			config.EnablePQC,
			useTrojan,
			config.Path,
			echMgr,
		)
		if err == nil {
			if config.UserAgent != "" {
				grpcT.SetUserAgent(config.UserAgent)
			}
			if config.Host != "" {
				grpcT.SetAuthority(config.Host)
			}
		}
		vm.transport = grpcT
	case "xhttp":
		var xhttpT *xhttp.Transport
		xhttpT, err = xhttp.NewWithProtocol(
			config.ServerAddr,
			config.Token,
			config.Password,
			config.EnableECH,
			config.EnableMozillaCA,
			config.EnableFlow,
			config.EnablePQC,
			useTrojan,
			config.Path,
			echMgr,
		)
		if err == nil {
			if config.XhttpMode != "" {
				xhttpT.SetMode(config.XhttpMode)
			}
			if config.Host != "" {
				xhttpT.SetHost(config.Host)
			}
		}
		vm.transport = xhttpT
	case "h3grpc":
		var h3T *h3grpc.Transport
		h3T, err = h3grpc.NewWithProtocol(
			config.ServerAddr,
			config.Token,
			config.Password,
			config.EnableECH,
			config.EnableMozillaCA,
			config.EnableFlow,
			config.EnablePQC,
			useTrojan,
			config.Path,
			echMgr,
		)
		if err == nil {
			if config.UserAgent != "" {
				h3T.SetUserAgent(config.UserAgent)
			}
			if config.ContentType != "" {
				h3T.SetContentType(config.ContentType)
			}
			if config.Host != "" {
				h3T.SetAuthority(config.Host)
			}
		}
		vm.transport = h3T
	default:
		cancel()
		return fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	if err != nil {
		cancel()
		return fmt.Errorf("failed to create transport: %w", err)
	}

	// Apply SNI override: config.SNI → config.Host → "" (transport falls back to parsed server host)
	effectiveSNI := config.SNI
	if effectiveSNI == "" {
		effectiveSNI = config.Host
	}
	if effectiveSNI != "" {
		switch t := vm.transport.(type) {
		case interface{ SetSNI(string) }:
			t.SetSNI(effectiveSNI)
		}
	}

	// 3. Android socket 保护：所有出站连接绑定到 VpnService.protect() 以避免 TUN 路由死循环
	if IsSocketProtectorSet() {
		vm.transport.SetBypassConfig(makeProtectedBypassConfig())
		log.Printf("[VPNManager] Socket protection applied to transport")
	} else {
		log.Printf("[VPNManager] Warning: No socket protector - transport may loop through TUN")
	}

	// 4. 初始化 TUN 处理器与 DNS 接管
	log.Printf("[VPNManager] Creating TUN handler...")

	// We prepare the udp writer interface ahead of time, pointing to the stack pointer later.
	udpWriter := &gvisorUDPWriter{stack: nil}
	vm.tunHandler = tun.NewHandler(ctx, vm.transport, udpWriter)

	// Initialize FakeIP pool for instant DNS responses
	fakeIPPool := dns.NewFakeIPPool()
	vm.tunHandler.SetFakeIPPool(fakeIPPool)
	log.Printf("[VPNManager] FakeIP DNS enabled")

	// 6. 创建 TUN 设备 (Android FileDescriptor)
	log.Printf("[VPNManager] Creating TUN device from FD=%d, MTU=%d", tunFD, vm.tunMTU)

	// 使用 CreateUnmonitoredTUNFromFD 而非 CreateTUNFromFile:
	// CreateTUNFromFile 内部调用 createNetlinkSocket() → unix.Bind(NETLINK_ROUTE)，
	// Android SELinux 对 untrusted_app 禁止此操作，导致 permission denied。
	// CreateUnmonitoredTUNFromFD 完全跳过 netlink（不监听接口 up/down 事件），
	// Android VpnService 已管理 TUN 生命周期，无需 netlink 事件。
	tunDevice, _, err := wgtun.CreateUnmonitoredTUNFromFD(tunFD)
	if err != nil {
		cancel()
		return fmt.Errorf("create TUN device failed: %w", err)
	}
	vm.tunDevice = tunDevice

	// 7. 创建网络栈 (use gvisor stack)
	log.Printf("[VPNManager] Creating network stack (gvisor)...")
	stackConfig := &ewpgvisor.StackConfig{
		MTU:        vm.tunMTU,
		TCPHandler: vm.tunHandler.HandleTCP,
		UDPHandler: vm.tunHandler.HandleUDP,
	}

	vm.tunStack, err = ewpgvisor.NewStack(vm.tunDevice, stackConfig)
	if err != nil {
		vm.tunDevice.Close()
		cancel()
		return fmt.Errorf("create gvisor stack failed: %w", err)
	}
	udpWriter.stack = vm.tunStack

	vm.running = true
	vm.startTime = time.Now()

	log.Printf("[VPNManager] VPN started successfully")
	return nil
}

// Stop 停止 VPN
func (vm *vpnManager) Stop() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return nil
	}

	log.Printf("[VPNManager] Stopping VPN...")

	// 停止网络栈
	if vm.tunStack != nil {
		vm.tunStack.Close()
		vm.tunStack = nil
	}

	// 关闭 TUN 设备
	if vm.tunDevice != nil {
		vm.tunDevice.Close()
		vm.tunDevice = nil
	}

	// 取消上下文
	if vm.cancel != nil {
		vm.cancel()
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
func (vm *vpnManager) IsRunning() bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.running
}

// GetStats 获取统计信息（返回 JSON 字符串）
func (vm *vpnManager) GetStats() string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if !vm.running {
		return `{"running":false}`
	}

	uptime := time.Since(vm.startTime).Seconds()

	stats := map[string]interface{}{
		"running":     true,
		"uptime":      uptime,
		"bytesUp":     vm.bytesUp,
		"bytesDown":   vm.bytesDown,
		"connections": vm.connections,
		"serverAddr":  vm.config.ServerAddr,
		"protocol":    vm.config.Protocol,
		"appProtocol": vm.config.AppProtocol,
		"enableEch":   vm.config.EnableECH,
		"enableFlow":  vm.config.EnableFlow,
		"tunMtu":      vm.tunMTU,
	}

	// 传输层统计（暂未实现）

	jsonData, _ := json.Marshal(stats)
	return string(jsonData)
}

// updateStats 更新统计信息（内部使用）
func (vm *vpnManager) updateStats(bytesUp, bytesDown uint64) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.bytesUp += bytesUp
	vm.bytesDown += bytesDown
}

// incrementConnections 增加连接计数
func (vm *vpnManager) incrementConnections() {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.connections++
}
