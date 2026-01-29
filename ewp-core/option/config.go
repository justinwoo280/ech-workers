package option

import (
	"flag"
	"fmt"

	"ewp-core/constant"
)

// Config represents the application configuration
type Config struct {
	// Proxy settings
	ListenAddr string
	ServerAddr string
	ServerIP   string
	Token      string
	Password   string  // Trojan 密码

	// Transport settings
	ProtoMode   string
	AppProtocol string  // 应用层协议: ewp 或 trojan
	XHTTPMode   string
	NumConns    int
	EnableFlow  bool
	EnablePQC   bool
	EnableMux   bool    // Trojan 多路复用

	// TLS/ECH settings
	DNSServer string
	ECHDomain string
	Fallback  bool

	// TUN settings
	TunMode    bool
	TunIP      string
	TunGateway string
	TunMask    string
	TunDNS     string
	TunMTU     int

	// Control settings
	ControlAddr string
	LogFilePath string
	Verbose     bool
}

// DefaultConfig returns a new Config with default values
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: constant.DefaultListenAddr,
		DNSServer:  constant.DefaultDNSServer,
		ECHDomain:  constant.DefaultECHDomain,
		NumConns:   constant.DefaultNumConns,
		ProtoMode:  constant.TransportWebSocket,
		XHTTPMode:  constant.DefaultXHTTPMode,
		EnableFlow: true,
		EnablePQC:  false,
		EnableMux:  false,
		Fallback:   false,
		TunMode:    false,
		TunIP:      constant.DefaultTunIP,
		TunGateway: constant.DefaultTunGateway,
		TunMask:    constant.DefaultTunMask,
		TunDNS:     constant.DefaultTunDNS,
		TunMTU:     constant.DefaultTunMTU,
		Verbose:    false,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ServerAddr == "" {
		return fmt.Errorf("server address (-f) is required")
	}

	if c.ProtoMode != constant.TransportWebSocket &&
		c.ProtoMode != constant.TransportGRPC &&
		c.ProtoMode != constant.TransportXHTTP {
		return fmt.Errorf("invalid transport mode: %s", c.ProtoMode)
	}

	if c.NumConns < 1 {
		return fmt.Errorf("number of connections must be at least 1")
	}

	if c.TunMode && c.TunMTU < 576 {
		return fmt.Errorf("TUN MTU must be at least 576")
	}

	return nil
}

// ParseFlags parses command-line flags into Config
func ParseFlags() (*Config, error) {
	cfg := DefaultConfig()

	flag.StringVar(&cfg.ListenAddr, "l", cfg.ListenAddr, "代理监听地址 (支持 SOCKS5 和 HTTP)")
	flag.StringVar(&cfg.ServerAddr, "f", "", "服务端地址 (支持: wss://host:port/path, grpcs://host:port, https://host:port/xhttp)")
	flag.StringVar(&cfg.ServerIP, "ip", "", "指定服务端 IP（绕过 DNS，TLS SNI 仍使用原 host）")
	flag.StringVar(&cfg.Token, "token", "", "身份验证令牌 (WebSocket) 或 UUID (gRPC)")
	flag.StringVar(&cfg.Password, "password", "", "Trojan 密码（启用 Trojan 协议时使用）")
	flag.StringVar(&cfg.AppProtocol, "protocol", "ewp", "应用层协议: ewp 或 trojan")
	flag.StringVar(&cfg.DNSServer, "dns", cfg.DNSServer, "ECH 查询 DoH 服务器")
	flag.StringVar(&cfg.ECHDomain, "ech", cfg.ECHDomain, "ECH 查询域名")
	flag.BoolVar(&cfg.Fallback, "fallback", cfg.Fallback, "禁用 ECH (普通 TLS 模式)")
	flag.IntVar(&cfg.NumConns, "n", cfg.NumConns, "并发连接数 (默认 1)")
	flag.StringVar(&cfg.ProtoMode, "mode", cfg.ProtoMode, "传输协议模式: ws (WebSocket)、grpc 或 xhttp")
	flag.StringVar(&cfg.XHTTPMode, "xhttp-mode", cfg.XHTTPMode, "XHTTP 模式: auto (自动选择)、stream-one (双向流) 或 stream-down (分离上下行)")
	flag.BoolVar(&cfg.EnableFlow, "flow", cfg.EnableFlow, "启用 Vision 流控协议（默认启用，提供流量混淆和零拷贝优化）")
	flag.BoolVar(&cfg.EnablePQC, "pqc", cfg.EnablePQC, "启用后量子密钥交换 X25519MLKEM768（需要 Go 1.24+，默认使用经典 X25519）")
	flag.BoolVar(&cfg.EnableMux, "mux", cfg.EnableMux, "启用 Trojan 多路复用（仅 Trojan 协议，单连接承载多个请求）")
	flag.StringVar(&cfg.ControlAddr, "control", "", "本地控制接口监听地址（仅用于 GUI 控制退出），例如 127.0.0.1:0")
	flag.StringVar(&cfg.LogFilePath, "logfile", "", "将日志追加写入到文件（用于 GUI 提权启动时仍能显示日志）")
	flag.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "详细日志模式（记录每个连接详情，高并发时会产生大量日志）")
	flag.BoolVar(&cfg.TunMode, "tun", cfg.TunMode, "启用 TUN 模式 (全局代理)")
	flag.StringVar(&cfg.TunIP, "tun-ip", cfg.TunIP, "TUN 设备 IP 地址")
	flag.StringVar(&cfg.TunGateway, "tun-gateway", cfg.TunGateway, "TUN 网关地址")
	flag.StringVar(&cfg.TunMask, "tun-mask", cfg.TunMask, "TUN 子网掩码")
	flag.StringVar(&cfg.TunDNS, "tun-dns", cfg.TunDNS, "TUN DNS 服务器")
	flag.IntVar(&cfg.TunMTU, "tun-mtu", cfg.TunMTU, "TUN MTU（建议约 1380，用于减少隧道封装导致的分片）")

	flag.Parse()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
