// Package cfg loads and validates the unified engine configuration
// and turns it into concrete inbound/outbound/router instances.
package cfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"ewp-core/engine"
	v2 "ewp-core/protocol/ewp/v2"
)

// File is the top-level config struct mapped from YAML/JSON.
type File struct {
	Inbounds  []InboundCfg   `yaml:"inbounds" json:"inbounds"`
	Outbounds []OutboundCfg  `yaml:"outbounds" json:"outbounds"`
	Router    RouterCfg      `yaml:"router" json:"router"`
	DNS       DNSCfg         `yaml:"dns" json:"dns"`
	ECH       ECHCfg         `yaml:"ech" json:"ech"`
	STUN      STUNCfg        `yaml:"stun" json:"stun"`
	ServerNameDNS ServerNameDNSCfg `yaml:"server_name_dns" json:"server_name_dns"`
}

// ServerNameDNSCfg configures how the client resolves the EWP server's
// own domain name to an IP at Dial time. Distinct from `dns.client`
// (TUN port-53 application traffic policy) and from `ech.bootstrap_doh`
// (one-shot HTTPS RR fetch).
//
// Threat-model rationale: every Dial of a v2 transport currently leaks
// the upstream server's domain to whoever the OS resolver talks to —
// usually the local ISP, sometimes worse. Configuring server_name_dns.doh
// routes that single A/AAAA query through DoH instead, so the wire only
// carries `dns.google` or `1.1.1.1` traffic from the user's perspective.
//
// Empty doh.servers ⇒ OS resolver is used.
type ServerNameDNSCfg struct {
	DoH        UpstreamDoHCfg `yaml:"doh" json:"doh"`
	PreferIPv6 bool           `yaml:"prefer_ipv6" json:"prefer_ipv6"`
}

// DNSCfg configures the project-wide DNS posture.
//
// The two upstream blocks (Client / Server) are independent because
// in a relay deployment the client side and server side need
// different policies — client typically wants fake-ip for the local
// applications, while the server (which the client's traffic
// eventually exits through) needs DoH for any inbound DOMAIN target.
type DNSCfg struct {
	Client ClientDNSCfg `yaml:"client" json:"client"`
	Server ServerDNSCfg `yaml:"server" json:"server"`
}

// ClientDNSCfg controls how the local TUN inbound responds to port-53
// queries from applications.
type ClientDNSCfg struct {
	Mode string `yaml:"mode" json:"mode"` // "fake-ip" (default) | "system"
}

// ServerDNSCfg controls how the server-side direct outbound resolves
// DOMAIN targets passed in by remote clients.
type ServerDNSCfg struct {
	Upstream UpstreamDoHCfg `yaml:"upstream" json:"upstream"`
}

// UpstreamDoHCfg configures an AsyncResolver instance.
type UpstreamDoHCfg struct {
	Servers    []string `yaml:"servers" json:"servers"`
	CacheSize  int      `yaml:"cache_size" json:"cache_size"`
	WorkerPool int      `yaml:"worker_pool" json:"worker_pool"`
	MinTTLSec  int      `yaml:"min_ttl_sec" json:"min_ttl_sec"`
	MaxTTLSec  int      `yaml:"max_ttl_sec" json:"max_ttl_sec"`
}

// ECHCfg configures the bootstrap DoH used to fetch HTTPS RRs at
// startup. Once we have an ECH config we never use OS DNS again.
type ECHCfg struct {
	BootstrapDoH UpstreamDoHCfg `yaml:"bootstrap_doh" json:"bootstrap_doh"`
}

// STUNCfg configures the optional reflexive-address discovery the
// server performs at startup. The result is reported in
// UDP_PROBE_RESP frames so clients can do NAT-type inference over
// the v2 tunnel without leaking STUN traffic outside it.
type STUNCfg struct {
	Servers []string `yaml:"servers" json:"servers"`
}

// RouterCfg is intentionally minimal in commit 7: a single default
// outbound tag. Rule-based routing is a follow-up.
type RouterCfg struct {
	Default string `yaml:"default" json:"default"`
}

type InboundCfg struct {
	Tag    string         `yaml:"tag" json:"tag"`
	Type   string         `yaml:"type" json:"type"`
	Listen string         `yaml:"listen" json:"listen"` // for socks5/http/ewpserver
	Users  map[string]string `yaml:"users" json:"users"` // socks5 only

	// EWP server inbound:
	UUIDs     []string  `yaml:"uuids" json:"uuids"`
	Transport TransportCfg `yaml:"transport" json:"transport"`

	// TUN inbound:
	TUN TUNCfg `yaml:"tun" json:"tun"`
}

type OutboundCfg struct {
	Tag       string       `yaml:"tag" json:"tag"`
	Type      string       `yaml:"type" json:"type"`
	UUID      string       `yaml:"uuid" json:"uuid"`         // ewpclient
	Server    string       `yaml:"server" json:"server"`     // ewpclient
	Transport TransportCfg `yaml:"transport" json:"transport"`
}

type TransportCfg struct {
	Kind string `yaml:"kind" json:"kind"` // "websocket" | "grpc" | "h3grpc" | "xhttp"
	URL  string `yaml:"url" json:"url"`
	SNI  string `yaml:"sni" json:"sni"`
	Host string `yaml:"host" json:"host"`
	Path string `yaml:"path" json:"path"`
	ECH  bool   `yaml:"ech" json:"ech"`

	// Server side TLS:
	CertFile string `yaml:"cert" json:"cert"`
	KeyFile  string `yaml:"key" json:"key"`
}

type TUNCfg struct {
	Name    string   `yaml:"name" json:"name"`
	Address string   `yaml:"address" json:"address"`
	MTU     int      `yaml:"mtu" json:"mtu"`
	DNS     []string `yaml:"dns" json:"dns"`
	FakeIP  bool     `yaml:"fake_ip" json:"fake_ip"`

	// BypassServer is the host (or host:port) of the upstream EWP
	// server. The TUN handler probes the routing table at startup
	// (via UDP-connect to this host) to learn which physical
	// interface to send proxy traffic out of, BEFORE it installs
	// its own default route. Without this set, the TUN can route-
	// loop: outbound traffic from the proxy itself gets pulled
	// back into the TUN. STRONGLY recommended; emit a loud warning
	// when missing.
	BypassServer string `yaml:"bypass_server" json:"bypass_server"`
}

// Load parses the file at path. Format is detected by extension.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f File
	switch {
	case strings.HasSuffix(path, ".json"):
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse json: %w", err)
		}
	default:
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse yaml: %w", err)
		}
	}
	if err := validate(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

func validate(f *File) error {
	if len(f.Inbounds) == 0 {
		return errors.New("at least one inbound is required")
	}
	if len(f.Outbounds) == 0 {
		return errors.New("at least one outbound is required")
	}
	if f.Router.Default == "" {
		// Default to the first outbound's tag.
		f.Router.Default = f.Outbounds[0].Tag
	}
	return nil
}

// BuildRouter returns the engine.Router instance.
func BuildRouter(rc RouterCfg) (engine.Router, error) {
	if rc.Default == "" {
		return nil, errors.New("router.default is required")
	}
	return &engine.StaticRouter{Tag: rc.Default}, nil
}

// parseUUID parses a hex-form UUID like "01020304-0506-0708-090a-0b0c0d0e0f10".
// It accepts both with and without hyphens.
func parseUUID(s string) ([16]byte, error) {
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return [16]byte{}, fmt.Errorf("uuid: want 32 hex chars, got %d", len(clean))
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		v, err := hexByte(clean[i*2 : i*2+2])
		if err != nil {
			return [16]byte{}, err
		}
		out[i] = v
	}
	return out, nil
}

func hexByte(s string) (byte, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("hex: bad len")
	}
	hi, err := hexNib(s[0])
	if err != nil {
		return 0, err
	}
	lo, err := hexNib(s[1])
	if err != nil {
		return 0, err
	}
	return hi<<4 | lo, nil
}

func hexNib(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("hex: bad char %q", c)
}

// parseUUIDs is a small helper used by ewpserver inbound.
func parseUUIDs(in []string) ([][v2.UUIDLen]byte, error) {
	if len(in) == 0 {
		return nil, errors.New("at least one UUID is required")
	}
	out := make([][v2.UUIDLen]byte, 0, len(in))
	for _, s := range in {
		u, err := parseUUID(s)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// silence unused-import for time when builds drop the helper.
var _ = time.Second
