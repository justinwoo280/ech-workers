//go:build android

// Package ewpmobile is the gomobile binding consumed by the Kotlin
// VpnService. Kotlin uses the symbols exposed in this file; vpn_manager.go
// provides the v2 implementation.
//
// The API has been re-cut for v2:
//
//   - There is one builder (VPNConfigBuilder) with v2-only fields.
//     The legacy v1 fields (EnableFlow, AppProtocol="trojan",
//     XhttpMode, EnableTLS, MinTLSVersion, ContentType, UserAgent,
//     ECHDomain, TunMask, TunGateway) have been removed; if you
//     were setting them on the Kotlin side you can now just delete
//     those lines.
//
//   - StartVPNTrojan / StartVPNAdvanced are gone. Trojan support is
//     a non-goal in v2 (EWP only). Advanced-mode is the default —
//     just call NewVPNConfig().Set...().Build() and pass it to
//     StartVPN.
//
//   - QuickStartVPN and StartVPNWithProtocol are kept as
//     convenience shims for the simplest call sites.
package ewpmobile

import (
	"fmt"

	"ewp-core/log"
)

// VPNConfigBuilder is a fluent builder around *VPNConfig.
//
// Kotlin usage:
//
//	val cfg = ewpmobile.NewVPNConfig("server.example:443", "01020304...")
//	    .SetProtocol("ws")
//	    .SetEnableECH(true)
//	    .SetSNI("server.example")
//	    .SetDoHServers("https://1.1.1.1/dns-query,https://dns.google/dns-query")
//	    .Build()
//	ewpmobile.StartVPN(tunFd, cfg)
type VPNConfigBuilder struct {
	cfg *VPNConfig
}

// NewVPNConfig returns a builder seeded with the upstream EWP server
// address and the hex-encoded UUID token issued by that server.
func NewVPNConfig(serverAddr, token string) *VPNConfigBuilder {
	return &VPNConfigBuilder{cfg: &VPNConfig{
		ServerAddr: serverAddr,
		Token:      token,
		Protocol:   "ws",
		Path:       "/ewp",
		EnableECH:  true,
		TUNMTU:     1420,
	}}
}

func (b *VPNConfigBuilder) SetProtocol(p string) *VPNConfigBuilder    { b.cfg.Protocol = p; return b }
func (b *VPNConfigBuilder) SetPath(p string) *VPNConfigBuilder        { b.cfg.Path = p; return b }
func (b *VPNConfigBuilder) SetSNI(s string) *VPNConfigBuilder         { b.cfg.SNI = s; return b }
func (b *VPNConfigBuilder) SetHost(h string) *VPNConfigBuilder        { b.cfg.Host = h; return b }
func (b *VPNConfigBuilder) SetEnableECH(en bool) *VPNConfigBuilder    { b.cfg.EnableECH = en; return b }
func (b *VPNConfigBuilder) SetTUNMTU(mtu int) *VPNConfigBuilder       { b.cfg.TUNMTU = mtu; return b }
func (b *VPNConfigBuilder) SetTUNIPv4(ip string) *VPNConfigBuilder    { b.cfg.TUNIPv4 = ip; return b }
func (b *VPNConfigBuilder) SetTUNIPv6(ip string) *VPNConfigBuilder    { b.cfg.TUNIPv6 = ip; return b }
func (b *VPNConfigBuilder) SetDNSv4(ip string) *VPNConfigBuilder      { b.cfg.DNSv4 = ip; return b }
func (b *VPNConfigBuilder) SetDNSv6(ip string) *VPNConfigBuilder      { b.cfg.DNSv6 = ip; return b }

// SetDoHServers takes a comma-separated list of DoH URLs (the wire
// format is comma-separated because gomobile cannot pass []string).
func (b *VPNConfigBuilder) SetDoHServers(commaSeparated string) *VPNConfigBuilder {
	b.cfg.DoHServers = splitCSV(commaSeparated)
	return b
}

// Build returns the immutable *VPNConfig. It performs no validation;
// errors surface from StartVPN.
func (b *VPNConfigBuilder) Build() *VPNConfig { return b.cfg }

// ---------------------------------------------------------------------
// Top-level entry points (the surface Kotlin actually calls)
// ---------------------------------------------------------------------

// StartVPN brings up the VPN with the supplied config, attaching to the
// TUN fd that VpnService.establish() returned.
func StartVPN(tunFD int, config *VPNConfig) error {
	if config == nil {
		return fmt.Errorf("nil config")
	}
	return vmInst.Start(tunFD, config)
}

// StopVPN tears the VPN down.
func StopVPN() error { return vmInst.Stop() }

// IsVPNRunning reports liveness.
func IsVPNRunning() bool { return vmInst.IsRunning() }

// GetVPNStats returns a JSON snapshot of runtime statistics. See
// vpn_manager.GetStats() for fields.
func GetVPNStats() string { return vmInst.GetStats() }

// QuickStartVPN is the smallest convenience entry: ws + ECH + 1.1.1.1
// DoH + standard MTU. Suitable for "I just want it to work" Kotlin
// code paths.
func QuickStartVPN(tunFD int, serverAddr, token string) error {
	cfg := NewVPNConfig(serverAddr, token).
		SetEnableECH(true).
		SetDoHServers("https://1.1.1.1/dns-query,https://dns.google/dns-query").
		Build()
	return StartVPN(tunFD, cfg)
}

// StartVPNWithProtocol lets the caller pick the outer transport while
// keeping every other v2 default.
func StartVPNWithProtocol(tunFD int, serverAddr, token, protocol string, enableECH bool) error {
	cfg := NewVPNConfig(serverAddr, token).
		SetProtocol(protocol).
		SetEnableECH(enableECH).
		SetDoHServers("https://1.1.1.1/dns-query,https://dns.google/dns-query").
		Build()
	return StartVPN(tunFD, cfg)
}

// TestLatency does a single UDP-handshake-style RTT to serverAddr and
// returns the result in milliseconds, or -1 on error.
//
// Implementation note: in v2 we no longer dial an EWP-aware probe —
// we just measure raw TCP connect time, which is the only signal that
// matters for "is the upstream reachable from this network".
func TestLatency(serverAddr string) int {
	if serverAddr == "" {
		return -1
	}
	ms, err := pingTCP(serverAddr)
	if err != nil {
		log.Printf("[ewpmobile] TestLatency(%q): %v", serverAddr, err)
		return -1
	}
	return ms
}
