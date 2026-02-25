package option

import (
	"flag"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"ewp-core/constant"
)

// LegacyFlags holds command-line flags for backward compatibility
type LegacyFlags struct {
	ConfigFile string
	ListenAddr string
	ServerAddr string
	Host       string
	Token      string
	Password   string
	Protocol   string
	DNSServer  string
	ECHDomain  string
	Fallback   bool
	NumConns   int
	Mode       string
	XHTTPMode  string
	EnableFlow bool
	EnablePQC  bool
	EnableMux  bool
	Control    string
	LogFile    string
	Verbose    bool
	TunMode    bool
	TunIP      string
	TunGateway string
	TunMask    string
	TunDNS     string
	TunMTU     int
}

// ParseLegacyFlags parses command-line flags for backward compatibility
func ParseLegacyFlags() (*LegacyFlags, error) {
	flags := &LegacyFlags{}

	flag.StringVar(&flags.ConfigFile, "c", "", "配置文件路径 (JSON 格式)")
	flag.StringVar(&flags.ConfigFile, "config", "", "配置文件路径 (JSON 格式)")
	flag.StringVar(&flags.ListenAddr, "l", constant.DefaultListenAddr, "代理监听地址 (支持 SOCKS5 和 HTTP)")
	flag.StringVar(&flags.ServerAddr, "f", "", "服务端地址 (支持: wss://host:port/path, grpcs://host:port, https://host:port/xhttp)")
	flag.StringVar(&flags.Host, "host", "", "HTTP Host 头 / gRPC authority（CDN 场景：留空则同 -f 中的地址）")
	flag.StringVar(&flags.Token, "token", "", "身份验证令牌 (WebSocket) 或 UUID (gRPC)")
	flag.StringVar(&flags.Password, "password", "", "Trojan 密码（启用 Trojan 协议时使用）")
	flag.StringVar(&flags.Protocol, "protocol", "ewp", "应用层协议: ewp 或 trojan")
	flag.StringVar(&flags.DNSServer, "dns", constant.DefaultDNSServer, "ECH 查询 DoH 服务器")
	flag.StringVar(&flags.ECHDomain, "ech", constant.DefaultECHDomain, "ECH 查询域名")
	flag.BoolVar(&flags.Fallback, "fallback", false, "禁用 ECH (普通 TLS 模式)")
	flag.IntVar(&flags.NumConns, "n", constant.DefaultNumConns, "并发连接数 (默认 1)")
	flag.StringVar(&flags.Mode, "mode", constant.TransportWebSocket, "传输协议模式: ws (WebSocket)、grpc 或 xhttp")
	flag.StringVar(&flags.XHTTPMode, "xhttp-mode", constant.DefaultXHTTPMode, "XHTTP 模式: auto (自动选择)、stream-one (双向流) 或 stream-down (分离上下行)")
	flag.BoolVar(&flags.EnableFlow, "flow", true, "启用 Vision 流控协议（默认启用，提供流量混淆和零拷贝优化）")
	flag.BoolVar(&flags.EnablePQC, "pqc", false, "启用后量子密钥交换 X25519MLKEM768（需要 Go 1.24+，默认使用经典 X25519）")
	flag.BoolVar(&flags.EnableMux, "mux", false, "启用 Trojan 多路复用（仅 Trojan 协议，单连接承载多个请求）")
	flag.StringVar(&flags.Control, "control", "", "本地控制接口监听地址（仅用于 GUI 控制退出），例如 127.0.0.1:0")
	flag.StringVar(&flags.LogFile, "logfile", "", "将日志追加写入到文件（用于 GUI 提权启动时仍能显示日志）")
	flag.BoolVar(&flags.Verbose, "verbose", false, "详细日志模式（记录每个连接详情，高并发时会产生大量日志）")
	flag.BoolVar(&flags.TunMode, "tun", false, "启用 TUN 模式 (全局代理)")
	flag.StringVar(&flags.TunIP, "tun-ip", constant.DefaultTunIP, "TUN 设备 IP 地址")
	flag.StringVar(&flags.TunGateway, "tun-gateway", constant.DefaultTunGateway, "TUN 网关地址")
	flag.StringVar(&flags.TunMask, "tun-mask", constant.DefaultTunMask, "TUN 子网掩码")
	flag.StringVar(&flags.TunDNS, "tun-dns", constant.DefaultTunDNS, "TUN DNS 服务器")
	flag.IntVar(&flags.TunMTU, "tun-mtu", constant.DefaultTunMTU, "TUN MTU（建议约 1380，用于减少隧道封装导致的分片）")

	flag.Parse()

	return flags, nil
}

// ToRootConfig converts legacy flags to RootConfig
func (f *LegacyFlags) ToRootConfig() (*RootConfig, error) {
	cfg := DefaultRootConfig()

	// Configure logging
	if f.Verbose {
		cfg.Log.Level = "debug"
	} else {
		cfg.Log.Level = "info"
	}
	cfg.Log.File = f.LogFile

	// Configure inbound
	if f.TunMode {
		cfg.Inbounds = []InboundConfig{
			{
				Type:          "tun",
				Tag:           "tun-in",
				InterfaceName: "ewp-tun",
				Inet4Address:  f.TunIP + "/24",
				MTU:           f.TunMTU,
				AutoRoute:     true,
				Stack:         "gvisor",
			},
		}
	} else {
		cfg.Inbounds = []InboundConfig{
			{
				Type:   "mixed",
				Tag:    "mixed-in",
				Listen: f.ListenAddr,
				UDP:    true,
			},
		}
	}

	// Configure outbound
	if f.ServerAddr == "" {
		return nil, fmt.Errorf("server address (-f) is required")
	}

	outbound, err := f.createOutbound()
	if err != nil {
		return nil, err
	}

	cfg.Outbounds = []OutboundConfig{*outbound}

	// Configure route
	cfg.Route = &RouteConfig{
		Final: outbound.Tag,
		Rules: []RouteRule{},
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// createOutbound creates an outbound configuration from legacy flags
func (f *LegacyFlags) createOutbound() (*OutboundConfig, error) {
	// Parse server address
	parsed, err := parseServerAddress(f.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	outbound := &OutboundConfig{
		Server:     parsed.Host,
		ServerPort: parsed.Port,
		Host:       f.Host,
	}

	// Determine protocol type
	if f.Protocol == "trojan" {
		outbound.Type = "trojan"
		outbound.Tag = "trojan-out"
		outbound.Password = f.Password
		if outbound.Password == "" {
			outbound.Password = f.Token
		}

		// Trojan multiplex
		if f.EnableMux {
			outbound.Multiplex = &MultiplexConfig{
				Enabled:     true,
				Concurrency: 8,
				Padding:     false,
			}
		}
	} else {
		outbound.Type = "ewp"
		outbound.Tag = "ewp-out"
		outbound.UUID = f.Token

		// EWP flow control
		if f.EnableFlow {
			outbound.Flow = &FlowConfig{
				Enabled: true,
				Padding: []int{900, 500, 900, 256},
			}
		}
	}

	// Configure transport
	transport, err := f.createTransport(parsed)
	if err != nil {
		return nil, err
	}
	outbound.Transport = transport

	// Configure TLS
	tls := &TLSConfig{
		Enabled:    true,
		ServerName: parsed.Host,
		PQC:        f.EnablePQC,
	}

	if !f.Fallback {
		tls.ECH = &ECHConfig{
			Enabled:      true,
			ConfigDomain: f.ECHDomain,
			DOHServer:    f.DNSServer,
		}
	}

	// Set ALPN based on transport type
	switch f.Mode {
	case "h3grpc", "h3":
		tls.ALPN = []string{"h3"}
	case "grpc":
		tls.ALPN = []string{"h2"}
	case "ws", "xhttp":
		tls.ALPN = []string{"h2", "http/1.1"}
	}

	outbound.TLS = tls

	return outbound, nil
}

// createTransport creates transport configuration from legacy flags
func (f *LegacyFlags) createTransport(parsed *ParsedAddress) (*TransportConfig, error) {
	transport := &TransportConfig{}

	switch f.Mode {
	case constant.TransportWebSocket:
		transport.Type = "ws"
		transport.Path = parsed.Path
		if transport.Path == "" {
			transport.Path = "/ws"
		}

	case constant.TransportGRPC:
		transport.Type = "grpc"
		transport.ServiceName = strings.TrimPrefix(parsed.Path, "/")
		if transport.ServiceName == "" {
			transport.ServiceName = "ProxyService"
		}
		transport.IdleTimeout = "15s"
		transport.HealthCheckTimeout = "10s"
		transport.PermitWithoutStream = true
		transport.InitialWindowSize = 4 * 1024 * 1024

	case constant.TransportXHTTP:
		transport.Type = "xhttp"
		transport.Path = parsed.Path
		if transport.Path == "" {
			transport.Path = "/xhttp"
		}
		transport.Mode = f.XHTTPMode
		transport.Concurrency = f.NumConns

	case "h3grpc", "h3":
		transport.Type = "h3grpc"
		transport.ServiceName = "ProxyService"
		transport.GRPCWeb = &GRPCWebConfig{
			Mode:           "binary",
			MaxMessageSize: 4 * 1024 * 1024,
			Compression:    "none",
		}
		transport.Concurrency = f.NumConns
		transport.QUIC = &QUICConfig{
			InitialStreamWindowSize:     6 * 1024 * 1024,
			MaxStreamWindowSize:         16 * 1024 * 1024,
			InitialConnectionWindowSize: 15 * 1024 * 1024,
			MaxConnectionWindowSize:     25 * 1024 * 1024,
			MaxIdleTimeout:              "30s",
			KeepAlivePeriod:             "10s",
			DisablePathMTUDiscovery:     false,
		}

	default:
		return nil, fmt.Errorf("unsupported transport mode: %s", f.Mode)
	}

	return transport, nil
}

// ParsedAddress holds parsed server address components
type ParsedAddress struct {
	Scheme string
	Host   string
	Port   int
	Path   string
}

// parseServerAddress parses server address with optional scheme
func parseServerAddress(addr string) (*ParsedAddress, error) {
	parsed := &ParsedAddress{
		Scheme: "https",
		Path:   "/",
	}

	// Try to parse as URL first
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %w", err)
		}

		parsed.Scheme = u.Scheme
		parsed.Host = u.Hostname()
		parsed.Path = u.Path
		if parsed.Path == "" {
			parsed.Path = "/"
		}

		if u.Port() != "" {
			port, err := strconv.Atoi(u.Port())
			if err != nil {
				return nil, fmt.Errorf("invalid port: %w", err)
			}
			parsed.Port = port
		} else {
			parsed.Port = 443
		}

		// Normalize scheme
		switch strings.ToLower(parsed.Scheme) {
		case "wss", "ws":
			parsed.Scheme = "ws"
		case "grpcs", "grpc":
			parsed.Scheme = "grpc"
		case "https", "http":
			parsed.Scheme = "https"
		case "h3":
			parsed.Scheme = "h3"
		default:
			return nil, fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
		}

		return parsed, nil
	}

	// Parse as host:port
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid address format (expected host:port)")
	}

	parsed.Host = parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}
	parsed.Port = port

	return parsed, nil
}

// LoadConfigWithFallback loads config with fallback to legacy flags
func LoadConfigWithFallback() (*RootConfig, error) {
	flags, err := ParseLegacyFlags()
	if err != nil {
		return nil, err
	}

	// If config file specified, use it
	if flags.ConfigFile != "" {
		cfg, err := LoadConfig(flags.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
		return cfg, nil
	}

	// Try to find config file
	if cfgPath, err := FindConfigFile(); err == nil {
		cfg, err := LoadConfig(cfgPath)
		if err == nil {
			return cfg, nil
		}
		// If file exists but has errors, return the error
		return nil, fmt.Errorf("failed to load config file %s: %w", cfgPath, err)
	}

	// Fall back to legacy flags
	if flags.ServerAddr == "" {
		return nil, fmt.Errorf("server address (-f) is required, or provide config file (-c)")
	}

	cfg, err := flags.ToRootConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to convert legacy flags: %w", err)
	}

	return cfg, nil
}
