package option

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ewp-core/constant"
)

// RootConfig is the top-level configuration structure
type RootConfig struct {
	Log       LogConfig        `json:"log"`
	DNS       *DNSConfig       `json:"dns,omitempty"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
	Route     *RouteConfig     `json:"route,omitempty"`
}

// LogConfig configures logging behavior
type LogConfig struct {
	Level     string `json:"level"`      // debug, info, warn, error
	File      string `json:"file"`       // log file path (empty for stdout)
	Timestamp bool   `json:"timestamp"`  // show timestamp
}

// DNSConfig configures DNS resolution
type DNSConfig struct {
	Servers   []DNSServerConfig `json:"servers"`
	Final     string            `json:"final"`     // default server tag
	Bootstrap string            `json:"bootstrap"` // bootstrap DNS servers for resolving server address
}

// DNSServerConfig defines a DNS server
type DNSServerConfig struct {
	Tag     string `json:"tag"`
	Address string `json:"address"`           // IP, DoH URL, DoT server, or DoQ server
	Type    string `json:"type,omitempty"`    // "doh", "dot", "doq", or empty for system DNS
	Detour  string `json:"detour,omitempty"`  // route through specific outbound
}

// InboundConfig defines an inbound connection handler
type InboundConfig struct {
	Type string `json:"type"` // mixed, socks, http, tun
	Tag  string `json:"tag"`

	// For socks/http/mixed
	Listen string `json:"listen,omitempty"`
	UDP    bool   `json:"udp,omitempty"`

	// For TUN
	InterfaceName string   `json:"interface_name,omitempty"`
	Inet4Address  string   `json:"inet4_address,omitempty"`
	Inet6Address  string   `json:"inet6_address,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	AutoRoute     bool     `json:"auto_route,omitempty"`
	StrictRoute   bool     `json:"strict_route,omitempty"`
	Stack         string   `json:"stack,omitempty"`       // gvisor, system
	TunnelDNS     []string `json:"tunnel_dns,omitempty"`  // Remote DNS servers for TUN mode (format: "type:address", e.g., "doq:dns.google:853")
}

// OutboundConfig defines an outbound connection handler
type OutboundConfig struct {
	Type string `json:"type"` // ewp, trojan, direct, block
	Tag  string `json:"tag"`

	// Server settings (for ewp/trojan)
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	ServerIP   string `json:"server_ip,omitempty"`

	// Authentication
	UUID     string `json:"uuid,omitempty"`     // for ewp
	Password string `json:"password,omitempty"` // for trojan

	// Protocol-specific
	Transport  *TransportConfig  `json:"transport,omitempty"`
	TLS        *TLSConfig        `json:"tls,omitempty"`
	Flow       *FlowConfig       `json:"flow,omitempty"`       // for ewp
	Multiplex  *MultiplexConfig  `json:"multiplex,omitempty"`  // for trojan
}

// TransportConfig defines transport layer settings
type TransportConfig struct {
	Type string `json:"type"` // ws, grpc, h3grpc, xhttp

	// WebSocket
	Path                 string            `json:"path,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	MaxEarlyData         int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName  string            `json:"early_data_header_name,omitempty"`

	// gRPC / H3gRPC
	ServiceName         string         `json:"service_name,omitempty"`
	IdleTimeout         string         `json:"idle_timeout,omitempty"`
	HealthCheckTimeout  string         `json:"health_check_timeout,omitempty"`
	PermitWithoutStream bool           `json:"permit_without_stream,omitempty"`
	InitialWindowSize   int32          `json:"initial_window_size,omitempty"`

	// H3gRPC specific
	GRPCWeb     *GRPCWebConfig `json:"grpc_web,omitempty"`
	Concurrency int            `json:"concurrency,omitempty"`
	QUIC        *QUICConfig    `json:"quic,omitempty"`
	
	// Anti-DPI / Obfuscation (for gRPC/H3gRPC)
	UserAgent   string `json:"user_agent,omitempty"`    // Custom User-Agent (default: browser-like)
	ContentType string `json:"content_type,omitempty"`  // Custom Content-Type (default: application/octet-stream)

	// XHTTP
	Mode string `json:"mode,omitempty"` // auto, stream-one, stream-down
}

// GRPCWebConfig defines gRPC-Web specific settings
type GRPCWebConfig struct {
	Mode           string `json:"mode"`             // binary, text
	MaxMessageSize int    `json:"max_message_size"` // max message size in bytes
	Compression    string `json:"compression"`      // none, gzip
}

// QUICConfig defines QUIC protocol settings
type QUICConfig struct {
	InitialStreamWindowSize      int    `json:"initial_stream_window_size"`
	MaxStreamWindowSize          int    `json:"max_stream_window_size"`
	InitialConnectionWindowSize  int    `json:"initial_connection_window_size"`
	MaxConnectionWindowSize      int    `json:"max_connection_window_size"`
	MaxIdleTimeout               string `json:"max_idle_timeout"`
	KeepAlivePeriod              string `json:"keep_alive_period"`
	DisablePathMTUDiscovery      bool   `json:"disable_path_mtu_discovery"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	Enabled        bool        `json:"enabled"`
	ServerName     string      `json:"server_name,omitempty"`
	Insecure       bool        `json:"insecure,omitempty"`
	ALPN           []string    `json:"alpn,omitempty"`
	ECH            *ECHConfig  `json:"ech,omitempty"`
	PQC            bool        `json:"pqc,omitempty"`
	MinVersion     string      `json:"min_version,omitempty"`
	MaxVersion     string      `json:"max_version,omitempty"`
	CipherSuites   []string    `json:"cipher_suites,omitempty"`
	Certificate    string      `json:"certificate,omitempty"`
	CertificatePath string     `json:"certificate_path,omitempty"`
	Key            string      `json:"key,omitempty"`
	KeyPath        string      `json:"key_path,omitempty"`
}

// ECHConfig defines ECH settings
type ECHConfig struct {
	Enabled         bool   `json:"enabled"`
	ConfigDomain    string `json:"config_domain,omitempty"`
	DOHServer       string `json:"doh_server,omitempty"`
	FallbackOnError bool   `json:"fallback_on_error,omitempty"`
}

// FlowConfig defines Vision flow control settings
type FlowConfig struct {
	Enabled bool    `json:"enabled"`
	Padding []int   `json:"padding,omitempty"` // [long_max, long_min, short_max, short_min]
}

// MultiplexConfig defines multiplexing settings (for Trojan)
type MultiplexConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
	Padding     bool `json:"padding"`
}

// RouteConfig defines routing rules
type RouteConfig struct {
	Final               string       `json:"final"` // default outbound tag
	AutoDetectInterface bool         `json:"auto_detect_interface,omitempty"`
	Rules               []RouteRule  `json:"rules,omitempty"`
}

// RouteRule defines a single routing rule
type RouteRule struct {
	Inbound        []string `json:"inbound,omitempty"`
	Domain         []string `json:"domain,omitempty"`
	DomainSuffix   []string `json:"domain_suffix,omitempty"`
	DomainKeyword  []string `json:"domain_keyword,omitempty"`
	DomainRegex    []string `json:"domain_regex,omitempty"`
	IPCidr         []string `json:"ip_cidr,omitempty"`
	SourceIPCidr   []string `json:"source_ip_cidr,omitempty"`
	Protocol       []string `json:"protocol,omitempty"`
	Port           []int    `json:"port,omitempty"`
	PortRange      []string `json:"port_range,omitempty"`
	Outbound       string   `json:"outbound"` // target outbound tag
}

// DefaultRootConfig returns a RootConfig with sensible defaults
func DefaultRootConfig() *RootConfig {
	return &RootConfig{
		Log: LogConfig{
			Level:     "info",
			File:      "",
			Timestamp: true,
		},
		Inbounds: []InboundConfig{
			{
				Type:   "mixed",
				Tag:    "mixed-in",
				Listen: constant.DefaultListenAddr,
				UDP:    true,
			},
		},
		Outbounds: []OutboundConfig{},
		Route:     nil,
	}
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(path string) (*RootConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg RootConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// FindConfigFile searches for config file in standard locations
func FindConfigFile() (string, error) {
	candidates := []string{
		"config.json",
		filepath.Join(os.Getenv("HOME"), ".config", "ewp-core", "config.json"),
	}

	if appData := os.Getenv("APPDATA"); appData != "" {
		candidates = append(candidates, filepath.Join(appData, "ewp-core", "config.json"))
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("no config file found in standard locations")
}

// Validate validates the configuration
func (c *RootConfig) Validate() error {
	// Validate log level
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Log.Level] {
		return fmt.Errorf("invalid log level: %s", c.Log.Level)
	}

	// Validate inbounds
	inboundTags := make(map[string]bool)
	for i, inbound := range c.Inbounds {
		if inbound.Tag == "" {
			return fmt.Errorf("inbound[%d]: tag is required", i)
		}
		if inboundTags[inbound.Tag] {
			return fmt.Errorf("inbound[%d]: duplicate tag %s", i, inbound.Tag)
		}
		inboundTags[inbound.Tag] = true

		if err := inbound.Validate(); err != nil {
			return fmt.Errorf("inbound[%d] (%s): %w", i, inbound.Tag, err)
		}
	}

	// Validate outbounds
	if len(c.Outbounds) == 0 {
		return fmt.Errorf("at least one outbound is required")
	}

	outboundTags := make(map[string]bool)
	for i, outbound := range c.Outbounds {
		if outbound.Tag == "" {
			return fmt.Errorf("outbound[%d]: tag is required", i)
		}
		if outboundTags[outbound.Tag] {
			return fmt.Errorf("outbound[%d]: duplicate tag %s", i, outbound.Tag)
		}
		outboundTags[outbound.Tag] = true

		if err := outbound.Validate(); err != nil {
			return fmt.Errorf("outbound[%d] (%s): %w", i, outbound.Tag, err)
		}
	}

	// Validate route
	if c.Route != nil {
		if c.Route.Final == "" {
			return fmt.Errorf("route.final is required")
		}
		if !outboundTags[c.Route.Final] {
			return fmt.Errorf("route.final references unknown outbound: %s", c.Route.Final)
		}

		for i, rule := range c.Route.Rules {
			if rule.Outbound == "" {
				return fmt.Errorf("route.rules[%d]: outbound is required", i)
			}
			if !outboundTags[rule.Outbound] {
				return fmt.Errorf("route.rules[%d]: references unknown outbound: %s", i, rule.Outbound)
			}
		}
	}

	return nil
}

// Validate validates an inbound configuration
func (i *InboundConfig) Validate() error {
	validTypes := map[string]bool{"mixed": true, "socks": true, "http": true, "tun": true}
	if !validTypes[i.Type] {
		return fmt.Errorf("invalid type: %s", i.Type)
	}

	switch i.Type {
	case "mixed", "socks", "http":
		if i.Listen == "" {
			return fmt.Errorf("listen address is required for %s inbound", i.Type)
		}
	case "tun":
		if i.InterfaceName == "" {
			i.InterfaceName = "ewp-tun"
		}
		if i.Inet4Address == "" {
			i.Inet4Address = constant.DefaultTunIP + "/24"
		}
		if i.MTU == 0 {
			i.MTU = constant.DefaultTunMTU
		}
		if i.MTU < 576 {
			return fmt.Errorf("MTU must be at least 576")
		}
		if i.Stack == "" {
			i.Stack = "gvisor"
		}
	}

	return nil
}

// Validate validates an outbound configuration
func (o *OutboundConfig) Validate() error {
	validTypes := map[string]bool{"ewp": true, "trojan": true, "direct": true, "block": true}
	if !validTypes[o.Type] {
		return fmt.Errorf("invalid type: %s", o.Type)
	}

	switch o.Type {
	case "ewp":
		if o.Server == "" {
			return fmt.Errorf("server is required for ewp outbound")
		}
		if o.ServerPort <= 0 || o.ServerPort > 65535 {
			return fmt.Errorf("server_port must be between 1 and 65535")
		}
		if o.UUID == "" {
			return fmt.Errorf("uuid is required for ewp outbound")
		}
		if o.Transport != nil {
			if err := o.Transport.Validate(); err != nil {
				return fmt.Errorf("transport: %w", err)
			}
		}
		if o.TLS != nil {
			if err := o.TLS.Validate(); err != nil {
				return fmt.Errorf("tls: %w", err)
			}
		}

	case "trojan":
		if o.Server == "" {
			return fmt.Errorf("server is required for trojan outbound")
		}
		if o.ServerPort <= 0 || o.ServerPort > 65535 {
			return fmt.Errorf("server_port must be between 1 and 65535")
		}
		if o.Password == "" {
			return fmt.Errorf("password is required for trojan outbound")
		}
		if o.Transport != nil {
			if err := o.Transport.Validate(); err != nil {
				return fmt.Errorf("transport: %w", err)
			}
		}
		if o.TLS != nil {
			if err := o.TLS.Validate(); err != nil {
				return fmt.Errorf("tls: %w", err)
			}
		}

	case "direct", "block":
		// No additional validation needed
	}

	return nil
}

// Validate validates transport configuration
func (t *TransportConfig) Validate() error {
	validTypes := map[string]bool{"ws": true, "grpc": true, "h3grpc": true, "xhttp": true}
	if !validTypes[t.Type] {
		return fmt.Errorf("invalid type: %s", t.Type)
	}

	switch t.Type {
	case "ws":
		if t.Path == "" {
			t.Path = "/"
		}

	case "grpc":
		if t.ServiceName == "" {
			t.ServiceName = "ProxyService"
		}

	case "h3grpc":
		if t.ServiceName == "" {
			t.ServiceName = "ProxyService"
		}
		if t.GRPCWeb != nil {
			if t.GRPCWeb.Mode != "binary" && t.GRPCWeb.Mode != "text" {
				return fmt.Errorf("grpc_web.mode must be 'binary' or 'text'")
			}
		}

	case "xhttp":
		if t.Mode == "" {
			t.Mode = "auto"
		}
		validModes := map[string]bool{"auto": true, "stream-one": true, "stream-down": true}
		if !validModes[t.Mode] {
			return fmt.Errorf("invalid xhttp mode: %s", t.Mode)
		}
	}

	return nil
}

// Validate validates TLS configuration
func (t *TLSConfig) Validate() error {
	if t.ECH != nil && t.ECH.Enabled {
		if t.ECH.ConfigDomain == "" && t.ECH.DOHServer == "" {
			return fmt.Errorf("ech enabled but neither config_domain nor doh_server specified")
		}
	}

	// Validate ALPN for h3grpc
	if len(t.ALPN) > 0 {
		for _, alpn := range t.ALPN {
			alpn = strings.ToLower(alpn)
			if alpn != "h3" && alpn != "h2" && alpn != "http/1.1" {
				return fmt.Errorf("unsupported ALPN: %s", alpn)
			}
		}
	}

	return nil
}

// ToJSON converts configuration to JSON string
func (c *RootConfig) ToJSON(indent bool) (string, error) {
	var data []byte
	var err error

	if indent {
		data, err = json.MarshalIndent(c, "", "  ")
	} else {
		data, err = json.Marshal(c)
	}

	if err != nil {
		return "", err
	}

	return string(data), nil
}
