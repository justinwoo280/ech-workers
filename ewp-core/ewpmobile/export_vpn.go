package ewpmobile

import (
	"log"
	"sync"
)

// GoMobile 导出的 VPN 接口
// 提供简化的全局 VPN 管理功能

var (
	globalVPN *VPNManager
	vpnMu     sync.Mutex
)

// VPNConfigBuilder VPN 配置构建器（GoMobile 友好）
type VPNConfigBuilder struct {
	config *VPNConfig
}

// NewVPNConfig 创建 VPN 配置构建器
func NewVPNConfig(serverAddr, token string) *VPNConfigBuilder {
	return &VPNConfigBuilder{
		config: &VPNConfig{
			ServerAddr:   serverAddr,
			Token:        token,
			Protocol:     "ws",        // 默认 WebSocket
			AppProtocol:  "ewp",       // 默认 EWP
			Path:         "/",         // 默认路径
			EnableECH:    true,        // 默认启用 ECH
			EnableFlow:   true,        // 默认启用 Vision 流控
			EnablePQC:    false,       // 默认不启用 PQC
			TunMTU:       1400,        // 默认 MTU
		},
	}
}

// SetServerIP 设置服务器 IP（优选 IP）
func (b *VPNConfigBuilder) SetServerIP(ip string) *VPNConfigBuilder {
	b.config.ServerIP = ip
	return b
}

// SetPassword 设置密码（Trojan 协议需要）
func (b *VPNConfigBuilder) SetPassword(password string) *VPNConfigBuilder {
	b.config.Password = password
	return b
}

// SetProtocol 设置传输协议（ws/grpc/xhttp）
func (b *VPNConfigBuilder) SetProtocol(protocol string) *VPNConfigBuilder {
	b.config.Protocol = protocol
	return b
}

// SetAppProtocol 设置应用协议（ewp/trojan）
func (b *VPNConfigBuilder) SetAppProtocol(appProtocol string) *VPNConfigBuilder {
	b.config.AppProtocol = appProtocol
	return b
}

// SetPath 设置路径（WebSocket 路径或 gRPC 服务名）
func (b *VPNConfigBuilder) SetPath(path string) *VPNConfigBuilder {
	b.config.Path = path
	return b
}

// SetEnableECH 设置是否启用 ECH
func (b *VPNConfigBuilder) SetEnableECH(enable bool) *VPNConfigBuilder {
	b.config.EnableECH = enable
	return b
}

// SetEnableFlow 设置是否启用 Vision 流控
func (b *VPNConfigBuilder) SetEnableFlow(enable bool) *VPNConfigBuilder {
	b.config.EnableFlow = enable
	return b
}

// SetEnablePQC 设置是否启用后量子加密
func (b *VPNConfigBuilder) SetEnablePQC(enable bool) *VPNConfigBuilder {
	b.config.EnablePQC = enable
	return b
}

// SetECHDomain 设置 ECH 域名
func (b *VPNConfigBuilder) SetECHDomain(domain string) *VPNConfigBuilder {
	b.config.ECHDomain = domain
	return b
}

// SetDNSServer 设置 DNS 服务器
func (b *VPNConfigBuilder) SetDNSServer(server string) *VPNConfigBuilder {
	b.config.DNSServer = server
	return b
}

// SetTunIP 设置 TUN IP 地址
func (b *VPNConfigBuilder) SetTunIP(ip string) *VPNConfigBuilder {
	b.config.TunIP = ip
	return b
}

// SetTunGateway 设置 TUN 网关
func (b *VPNConfigBuilder) SetTunGateway(gateway string) *VPNConfigBuilder {
	b.config.TunGateway = gateway
	return b
}

// SetTunMask 设置 TUN 子网掩码
func (b *VPNConfigBuilder) SetTunMask(mask string) *VPNConfigBuilder {
	b.config.TunMask = mask
	return b
}

// SetTunDNS 设置 TUN DNS 服务器
func (b *VPNConfigBuilder) SetTunDNS(dns string) *VPNConfigBuilder {
	b.config.TunDNS = dns
	return b
}

// SetTunMTU 设置 TUN MTU
func (b *VPNConfigBuilder) SetTunMTU(mtu int) *VPNConfigBuilder {
	b.config.TunMTU = mtu
	return b
}

// Build 构建配置
func (b *VPNConfigBuilder) Build() *VPNConfig {
	return b.config
}

// ========== 全局 VPN 管理函数 ==========

// StartVPN 启动 VPN（全局单例）
// tunFD: Android VPNService 的 ParcelFileDescriptor.getFd()
// config: VPN 配置
func StartVPN(tunFD int, config *VPNConfig) error {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	
	// 如果已有 VPN 在运行，先停止
	if globalVPN != nil && globalVPN.IsRunning() {
		log.Printf("[VPN] Stopping existing VPN before starting new one")
		globalVPN.Stop()
	}
	
	// 创建新的 VPN 管理器
	globalVPN = NewVPNManager()
	
	// 启动 VPN
	return globalVPN.Start(tunFD, config)
}

// StopVPN 停止 VPN
func StopVPN() error {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	
	if globalVPN == nil {
		return nil
	}
	
	err := globalVPN.Stop()
	globalVPN = nil
	return err
}

// IsVPNRunning 检查 VPN 是否运行
func IsVPNRunning() bool {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	
	if globalVPN == nil {
		return false
	}
	
	return globalVPN.IsRunning()
}

// GetVPNStats 获取 VPN 统计信息（JSON 字符串）
func GetVPNStats() string {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	
	if globalVPN == nil {
		return `{"running":false}`
	}
	
	return globalVPN.GetStats()
}

// ========== 简化的快捷函数 ==========

// QuickStartVPN 快速启动 VPN（使用默认配置）
// 参数：
//   - tunFD: TUN 文件描述符
//   - serverAddr: 服务器地址（如 "xxx.workers.dev:443"）
//   - token: 认证令牌
func QuickStartVPN(tunFD int, serverAddr, token string) error {
	config := NewVPNConfig(serverAddr, token).Build()
	return StartVPN(tunFD, config)
}

// StartVPNWithProtocol 启动 VPN（指定协议）
// 参数：
//   - tunFD: TUN 文件描述符
//   - serverAddr: 服务器地址
//   - token: 认证令牌
//   - protocol: 传输协议（ws/grpc/xhttp）
//   - enableECH: 是否启用 ECH
func StartVPNWithProtocol(tunFD int, serverAddr, token, protocol string, enableECH bool) error {
	config := NewVPNConfig(serverAddr, token).
		SetProtocol(protocol).
		SetEnableECH(enableECH).
		Build()
	return StartVPN(tunFD, config)
}

// StartVPNTrojan 启动 Trojan 协议的 VPN
// 参数：
//   - tunFD: TUN 文件描述符
//   - serverAddr: 服务器地址
//   - password: Trojan 密码
//   - protocol: 传输协议（ws/grpc/xhttp）
func StartVPNTrojan(tunFD int, serverAddr, password, protocol string) error {
	config := NewVPNConfig(serverAddr, "").
		SetPassword(password).
		SetProtocol(protocol).
		SetAppProtocol("trojan").
		Build()
	return StartVPN(tunFD, config)
}

// ========== 高级配置函数 ==========

// StartVPNAdvanced 启动 VPN（完整配置）
// 参数示例：
//   serverAddr: "xxx.workers.dev:443"
//   serverIP: "104.16.1.2" (可选，优选 IP)
//   token: "your-uuid"
//   password: "" (Trojan 协议需要)
//   protocol: "ws" / "grpc" / "xhttp"
//   appProtocol: "ewp" / "trojan"
//   path: "/" (WebSocket 路径或 gRPC 服务名)
//   enableECH: true
//   enableFlow: true
//   enablePQC: false
func StartVPNAdvanced(
	tunFD int,
	serverAddr, serverIP, token, password string,
	protocol, appProtocol, path string,
	enableECH, enableFlow, enablePQC bool,
) error {
	config := &VPNConfig{
		ServerAddr:   serverAddr,
		ServerIP:     serverIP,
		Token:        token,
		Password:     password,
		Protocol:     protocol,
		AppProtocol:  appProtocol,
		Path:         path,
		EnableECH:    enableECH,
		EnableFlow:   enableFlow,
		EnablePQC:    enablePQC,
		TunMTU:       1400,
	}
	return StartVPN(tunFD, config)
}
