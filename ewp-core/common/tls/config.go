package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"ewp-core/common/cabundle"
)

// GetMozillaCertPool returns a CertPool containing root CAs from
// Mozilla NSS. Backed by the shared common/cabundle leaf package
// (which also serves dns/, breaking what would otherwise be an
// import cycle: common/tls -> dns -> common/tls).
func GetMozillaCertPool() *x509.CertPool { return cabundle.MozillaPool() }

type STDConfig struct {
	config *tls.Config
}

func NewSTDConfig(serverName string, useMozillaCA bool, enablePQC bool) (*STDConfig, error) {
	var roots *x509.CertPool
	if useMozillaCA {
		roots = GetMozillaCertPool()
	} else {
		// P1-9: SystemCertPool() errors must be checked. On some restricted
		// systems (e.g. Android with user CAs disabled) it returns (nil, error).
		// Ignoring the error could lead to nil RootCAs which may silently trust
		// all certificates depending on Go version behavior.
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system CA pool: %w (consider enabling useMozillaCA)", err)
		}
		if roots == nil {
			return nil, fmt.Errorf("system CA pool is nil (consider enabling useMozillaCA)")
		}
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
	}

	if enablePQC {
		tlsCfg.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		}
	} else {
		tlsCfg.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		}
	}

	return &STDConfig{config: tlsCfg}, nil
}

func (c *STDConfig) ServerName() string {
	return c.config.ServerName
}

func (c *STDConfig) SetServerName(serverName string) {
	c.config.ServerName = serverName
}

func (c *STDConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *STDConfig) SetNextProtos(nextProtos []string) {
	c.config.NextProtos = nextProtos
}

func (c *STDConfig) TLSConfig() (*tls.Config, error) {
	// Clone ensures each Dial() gets its own *tls.Config so concurrent
	// handshakes cannot observe partial mutations (e.g. ECH retry updates).
	// Go docs explicitly state tls.Config must not be modified after first use.
	return c.config.Clone(), nil
}

func (c *STDConfig) Clone() Config {
	return &STDConfig{
		config: c.config.Clone(),
	}
}

func (c *STDConfig) Handshake(conn net.Conn) (net.Conn, error) {
	return tls.Client(conn, c.config), nil
}

type STDECHConfig struct {
	*STDConfig
}

func NewSTDECHConfig(serverName string, useMozillaCA bool, echList []byte, enablePQC bool) (*STDECHConfig, error) {
	cfg, err := NewSTDConfig(serverName, useMozillaCA, enablePQC)
	if err != nil {
		return nil, err
	}
	cfg.config.EncryptedClientHelloConfigList = echList
	cfg.config.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
		return errors.New("server rejected ECH")
	}
	return &STDECHConfig{cfg}, nil
}

func (c *STDECHConfig) ECHConfigList() []byte {
	return c.config.EncryptedClientHelloConfigList
}

func (c *STDECHConfig) SetECHConfigList(echList []byte) {
	c.config.EncryptedClientHelloConfigList = echList
}

func (c *STDECHConfig) Clone() Config {
	return &STDECHConfig{
		&STDConfig{
			config: c.config.Clone(),
		},
	}
}

// BuildWithECH is a convenience function for backward compatibility
// P1-9: now returns error to propagate CA loading failures
func BuildWithECH(serverName string, useMozillaCA bool, echList []byte, enablePQC bool) (*tls.Config, error) {
	cfg, err := NewSTDECHConfig(serverName, useMozillaCA, echList, enablePQC)
	if err != nil {
		return nil, err
	}
	return cfg.TLSConfig()
}

// GetConnectionInfo returns human-readable TLS connection info
func GetConnectionInfo(state tls.ConnectionState) string {
	info := fmt.Sprintf("TLS %s", versionName(state.Version))

	if state.DidResume {
		info += " (resumed)"
	}

	info += fmt.Sprintf(", Cipher: %s", tls.CipherSuiteName(state.CipherSuite))

	return info
}

func versionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
