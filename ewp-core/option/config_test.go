package option

import (
	"encoding/json"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Test loading H3 config
	cfg, err := LoadConfig("../../example/config.example.json")
	if err != nil {
		t.Fatalf("Failed to load H3 config: %v", err)
	}

	if len(cfg.Outbounds) == 0 {
		t.Fatal("No outbounds in config")
	}

	outbound := cfg.Outbounds[0]
	if outbound.Type != "ewp" {
		t.Errorf("Expected outbound type 'ewp', got '%s'", outbound.Type)
	}

	if outbound.Transport == nil {
		t.Fatal("Transport is nil")
	}

	if outbound.Transport.Type != "h3grpc" {
		t.Errorf("Expected transport type 'h3grpc', got '%s'", outbound.Transport.Type)
	}

	if outbound.Transport.GRPCWeb == nil {
		t.Fatal("GRPCWeb config is nil")
	}

	if outbound.Transport.GRPCWeb.Mode != "binary" {
		t.Errorf("Expected GRPCWeb mode 'binary', got '%s'", outbound.Transport.GRPCWeb.Mode)
	}
}

func TestLoadWebSocketConfig(t *testing.T) {
	cfg, err := LoadConfig("../../example/config.ws.example.json")
	if err != nil {
		t.Fatalf("Failed to load WS config: %v", err)
	}

	outbound := cfg.Outbounds[0]
	if outbound.Transport.Type != "ws" {
		t.Errorf("Expected transport type 'ws', got '%s'", outbound.Transport.Type)
	}

	if outbound.Transport.Path != "/ws" {
		t.Errorf("Expected path '/ws', got '%s'", outbound.Transport.Path)
	}
}

func TestLoadTrojanConfig(t *testing.T) {
	cfg, err := LoadConfig("../../example/config.trojan.example.json")
	if err != nil {
		t.Fatalf("Failed to load Trojan config: %v", err)
	}

	if len(cfg.Outbounds) < 1 {
		t.Fatal("Expected at least 1 outbound")
	}

	trojan := cfg.Outbounds[0]
	if trojan.Type != "trojan" {
		t.Errorf("Expected outbound type 'trojan', got '%s'", trojan.Type)
	}

	if trojan.Multiplex == nil {
		t.Fatal("Multiplex config is nil")
	}

	if !trojan.Multiplex.Enabled {
		t.Error("Expected multiplex to be enabled")
	}
}

func TestLegacyFlagsConversion(t *testing.T) {
	flags := &LegacyFlags{
		ListenAddr: "127.0.0.1:1080",
		ServerAddr: "wss://example.com:443/ws",
		Token:      "test-uuid",
		Mode:       "ws",
		EnableFlow: true,
		EnablePQC:  false,
		Fallback:   false,
		DNSServer:  "dns.alidns.com/dns-query",
		ECHDomain:  "cloudflare-ech.com",
	}

	cfg, err := flags.ToRootConfig()
	if err != nil {
		t.Fatalf("Failed to convert legacy flags: %v", err)
	}

	if len(cfg.Inbounds) == 0 {
		t.Fatal("No inbounds created")
	}

	if cfg.Inbounds[0].Type != "mixed" {
		t.Errorf("Expected inbound type 'mixed', got '%s'", cfg.Inbounds[0].Type)
	}

	if len(cfg.Outbounds) == 0 {
		t.Fatal("No outbounds created")
	}

	outbound := cfg.Outbounds[0]
	if outbound.Type != "ewp" {
		t.Errorf("Expected outbound type 'ewp', got '%s'", outbound.Type)
	}

	if outbound.Server != "example.com" {
		t.Errorf("Expected server 'example.com', got '%s'", outbound.Server)
	}

	if outbound.ServerPort != 443 {
		t.Errorf("Expected port 443, got %d", outbound.ServerPort)
	}

	if outbound.UUID != "test-uuid" {
		t.Errorf("Expected UUID 'test-uuid', got '%s'", outbound.UUID)
	}

	if outbound.Transport.Type != "ws" {
		t.Errorf("Expected transport type 'ws', got '%s'", outbound.Transport.Type)
	}

	if outbound.Transport.Path != "/ws" {
		t.Errorf("Expected path '/ws', got '%s'", outbound.Transport.Path)
	}

	if !outbound.Flow.Enabled {
		t.Error("Expected flow to be enabled")
	}

	if !outbound.TLS.ECH.Enabled {
		t.Error("Expected ECH to be enabled")
	}
}

func TestH3GRPCFlagsConversion(t *testing.T) {
	flags := &LegacyFlags{
		ListenAddr: "127.0.0.1:1080",
		ServerAddr: "h3://cdn.example.com:443",
		Token:      "test-uuid",
		Mode:       "h3grpc",
		NumConns:   4,
		EnableFlow: true,
		EnablePQC:  true,
		Fallback:   false,
		DNSServer:  "dns.alidns.com/dns-query",
		ECHDomain:  "cloudflare-ech.com",
	}

	cfg, err := flags.ToRootConfig()
	if err != nil {
		t.Fatalf("Failed to convert H3 flags: %v", err)
	}

	outbound := cfg.Outbounds[0]
	if outbound.Transport.Type != "h3grpc" {
		t.Errorf("Expected transport type 'h3grpc', got '%s'", outbound.Transport.Type)
	}

	if outbound.Transport.GRPCWeb == nil {
		t.Fatal("GRPCWeb config is nil")
	}

	if outbound.Transport.GRPCWeb.Mode != "binary" {
		t.Errorf("Expected GRPCWeb mode 'binary', got '%s'", outbound.Transport.GRPCWeb.Mode)
	}

	if outbound.Transport.Concurrency != 4 {
		t.Errorf("Expected concurrency 4, got %d", outbound.Transport.Concurrency)
	}

	if !outbound.TLS.PQC {
		t.Error("Expected PQC to be enabled")
	}

	if len(outbound.TLS.ALPN) == 0 || outbound.TLS.ALPN[0] != "h3" {
		t.Errorf("Expected ALPN to contain 'h3', got %v", outbound.TLS.ALPN)
	}
}

func TestConfigValidation(t *testing.T) {
	// Test missing outbound
	cfg := DefaultRootConfig()
	cfg.Outbounds = []OutboundConfig{}
	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation error for missing outbound")
	}

	// Test duplicate tags
	cfg = DefaultRootConfig()
	cfg.Outbounds = []OutboundConfig{
		{Type: "direct", Tag: "test"},
		{Type: "block", Tag: "test"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation error for duplicate tags")
	}

	// Test invalid route.final
	cfg = DefaultRootConfig()
	cfg.Outbounds = []OutboundConfig{
		{Type: "direct", Tag: "direct"},
	}
	cfg.Route = &RouteConfig{
		Final: "nonexistent",
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation error for invalid route.final")
	}
}

func TestConfigJSONRoundtrip(t *testing.T) {
	original := DefaultRootConfig()
	original.Outbounds = []OutboundConfig{
		{
			Type:       "ewp",
			Tag:        "proxy",
			Server:     "example.com",
			ServerPort: 443,
			UUID:       "test-uuid",
			Transport: &TransportConfig{
				Type:        "h3grpc",
				ServiceName: "ProxyService",
				GRPCWeb: &GRPCWebConfig{
					Mode:           "binary",
					MaxMessageSize: 4194304,
				},
			},
			TLS: &TLSConfig{
				Enabled: true,
				ALPN:    []string{"h3"},
			},
		},
	}
	original.Route = &RouteConfig{
		Final: "proxy",
	}

	jsonStr, err := original.ToJSON(true)
	if err != nil {
		t.Fatalf("Failed to convert to JSON: %v", err)
	}

	var parsed RootConfig
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if err := parsed.Validate(); err != nil {
		t.Fatalf("Parsed config failed validation: %v", err)
	}

	if len(parsed.Outbounds) != 1 {
		t.Errorf("Expected 1 outbound, got %d", len(parsed.Outbounds))
	}

	if parsed.Outbounds[0].Transport.Type != "h3grpc" {
		t.Errorf("Expected transport type 'h3grpc', got '%s'", parsed.Outbounds[0].Transport.Type)
	}
}

func TestParseServerAddress(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort int
		wantPath string
		wantErr  bool
	}{
		{"wss://example.com:443/ws", "example.com", 443, "/ws", false},
		{"grpcs://example.com:443/ProxyService", "example.com", 443, "/ProxyService", false},
		{"h3://cdn.example.com:443", "cdn.example.com", 443, "/", false},
		{"example.com:443", "example.com", 443, "/", false},
		{"example.com", "", 0, "", true},
		{"invalid://", "", 0, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed, err := parseServerAddress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseServerAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if parsed.Host != tt.wantHost {
				t.Errorf("Host = %v, want %v", parsed.Host, tt.wantHost)
			}
			if parsed.Port != tt.wantPort {
				t.Errorf("Port = %v, want %v", parsed.Port, tt.wantPort)
			}
			if parsed.Path != tt.wantPath {
				t.Errorf("Path = %v, want %v", parsed.Path, tt.wantPath)
			}
		})
	}
}
