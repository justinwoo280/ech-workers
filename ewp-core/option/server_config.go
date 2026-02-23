package option

import (
	"encoding/json"
	"fmt"
	"os"
)

// ServerConfig represents server configuration
type ServerConfig struct {
	Log      LogConfig        `json:"log"`
	Listener ListenerConfig   `json:"listener"`
	Protocol ProtocolConfig   `json:"protocol"`
	TLS      *ServerTLSConfig `json:"tls,omitempty"`
	Advanced AdvancedConfig   `json:"advanced,omitempty"`
}

// ListenerConfig defines server listening settings
type ListenerConfig struct {
	Port    int      `json:"port"`              // Listen port
	Address string   `json:"address,omitempty"` // Listen address (default: 0.0.0.0)
	Modes   []string `json:"modes"`             // ws, grpc, xhttp, h3 (can enable multiple)

	// Mode-specific paths
	WSPath      string `json:"ws_path,omitempty"`      // WebSocket path
	XHTTPPath   string `json:"xhttp_path,omitempty"`   // XHTTP path
	GRPCService string `json:"grpc_service,omitempty"` // gRPC service name
}

// ProtocolConfig defines protocol settings
type ProtocolConfig struct {
	Type     string `json:"type"`               // ewp or trojan
	UUID     string `json:"uuid,omitempty"`     // For EWP
	Password string `json:"password,omitempty"` // For Trojan (comma-separated for multiple)

	// Flow control
	EnableFlow bool `json:"enable_flow,omitempty"`

	// Trojan specific
	Fallback string `json:"fallback,omitempty"` // Trojan fallback address
}

// ServerTLSConfig defines server TLS settings
type ServerTLSConfig struct {
	Enabled      bool     `json:"enabled"`
	CertFile     string   `json:"cert_file"`
	KeyFile      string   `json:"key_file"`
	ALPN         []string `json:"alpn,omitempty"` // h3, h2, http/1.1
	MinVersion   string   `json:"min_version,omitempty"`
	MaxVersion   string   `json:"max_version,omitempty"`
	CipherSuites []string `json:"cipher_suites,omitempty"`
}

// AdvancedConfig defines advanced settings
type AdvancedConfig struct {
	// gRPC-Web support
	EnableGRPCWeb bool `json:"enable_grpc_web,omitempty"`

	// Padding
	PaddingMin int `json:"padding_min,omitempty"`
	PaddingMax int `json:"padding_max,omitempty"`

	// SSE Headers for disguise
	SSEHeaders bool `json:"sse_headers,omitempty"`

	// HTTP/3 specific
	H3MaxBidiStreams int `json:"h3_max_bidi_streams,omitempty"`
	H3MaxUniStreams  int `json:"h3_max_uni_streams,omitempty"`

	// Buffer sizes
	ReadBufferSize  int `json:"read_buffer_size,omitempty"`
	WriteBufferSize int `json:"write_buffer_size,omitempty"`
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Log: LogConfig{
			Level:     "info",
			Timestamp: true,
		},
		Listener: ListenerConfig{
			Port:        8080,
			Address:     "0.0.0.0",
			Modes:       []string{"ws"},
			WSPath:      "/",
			XHTTPPath:   "/xhttp",
			GRPCService: "ProxyService",
		},
		Protocol: ProtocolConfig{
			Type:       "ewp",
			UUID:       "d342d11e-d424-4583-b36e-524ab1f0afa4",
			EnableFlow: false,
		},
		TLS: nil, // TLS disabled by default
		Advanced: AdvancedConfig{
			EnableGRPCWeb: true, // Enable by default for CDN compatibility
			PaddingMin:    100,
			PaddingMax:    1000,
			SSEHeaders:    true,
		},
	}
}

// LoadServerConfig loads server configuration from file
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate validates server configuration
func (c *ServerConfig) Validate() error {
	// Validate port
	if c.Listener.Port < 1 || c.Listener.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Listener.Port)
	}

	// Validate modes
	if len(c.Listener.Modes) == 0 {
		return fmt.Errorf("at least one mode must be enabled")
	}

	validModes := map[string]bool{"ws": true, "grpc": true, "xhttp": true, "h3": true}
	for _, mode := range c.Listener.Modes {
		if !validModes[mode] {
			return fmt.Errorf("invalid mode: %s", mode)
		}
	}

	// Validate protocol
	if c.Protocol.Type != "ewp" && c.Protocol.Type != "trojan" {
		return fmt.Errorf("invalid protocol type: %s", c.Protocol.Type)
	}

	if c.Protocol.Type == "ewp" && c.Protocol.UUID == "" {
		return fmt.Errorf("UUID is required for EWP protocol")
	}

	if c.Protocol.Type == "trojan" && c.Protocol.Password == "" {
		return fmt.Errorf("password is required for Trojan protocol")
	}

	// Validate TLS
	if c.TLS != nil && c.TLS.Enabled {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return fmt.Errorf("cert_file and key_file are required when TLS is enabled")
		}

		// Check if files exist
		if _, err := os.Stat(c.TLS.CertFile); os.IsNotExist(err) {
			return fmt.Errorf("cert file not found: %s", c.TLS.CertFile)
		}
		if _, err := os.Stat(c.TLS.KeyFile); os.IsNotExist(err) {
			return fmt.Errorf("key file not found: %s", c.TLS.KeyFile)
		}
	}

	// Validate HTTP/3 requirements
	for _, mode := range c.Listener.Modes {
		if mode == "h3" {
			if c.TLS == nil || !c.TLS.Enabled {
				return fmt.Errorf("HTTP/3 requires TLS to be enabled")
			}

			// Ensure h3 is in ALPN
			hasH3 := false
			for _, alpn := range c.TLS.ALPN {
				if alpn == "h3" {
					hasH3 = true
					break
				}
			}
			if !hasH3 {
				return fmt.Errorf("HTTP/3 mode requires 'h3' in TLS ALPN")
			}
		}
	}

	return nil
}

// ToJSON converts configuration to JSON
func (c *ServerConfig) ToJSON(indent bool) (string, error) {
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

// LoadServerConfigWithFallback loads config with fallback to env vars
func LoadServerConfigWithFallback(configPath string) (*ServerConfig, error) {
	// Try to load from config file
	if configPath != "" {
		return LoadServerConfig(configPath)
	}

	// Try standard locations
	candidates := []string{
		"server.json",
		"config.server.json",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			cfg, err := LoadServerConfig(path)
			if err == nil {
				return cfg, nil
			}
		}
	}

	// Fallback to environment variables and defaults
	return LoadFromEnv(), nil
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() *ServerConfig {
	cfg := DefaultServerConfig()

	// Override with environment variables
	if port := os.Getenv("PORT"); port != "" {
		fmt.Sscanf(port, "%d", &cfg.Listener.Port)
	}

	if uuid := os.Getenv("UUID"); uuid != "" {
		cfg.Protocol.UUID = uuid
	}

	if password := os.Getenv("PASSWORD"); password != "" {
		cfg.Protocol.Password = password
		cfg.Protocol.Type = "trojan"
	}

	if mode := os.Getenv("MODE"); mode != "" {
		cfg.Listener.Modes = []string{mode}
	}

	if os.Getenv("ENABLE_FLOW") == "true" {
		cfg.Protocol.EnableFlow = true
	}

	if fallback := os.Getenv("FALLBACK"); fallback != "" {
		cfg.Protocol.Fallback = fallback
	}

	if wsPath := os.Getenv("WS_PATH"); wsPath != "" {
		cfg.Listener.WSPath = wsPath
	}

	if grpcService := os.Getenv("GRPC_SERVICE"); grpcService != "" {
		cfg.Listener.GRPCService = grpcService
	}

	return cfg
}
