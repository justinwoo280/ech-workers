package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
)

type STDConfig struct {
	config *tls.Config
}

func NewSTDConfig(serverName string, enablePQC bool) *STDConfig {
	roots, _ := x509.SystemCertPool()

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

	return &STDConfig{config: tlsCfg}
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
	return c.config, nil
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

func NewSTDECHConfig(serverName string, echList []byte, enablePQC bool) *STDECHConfig {
	cfg := NewSTDConfig(serverName, enablePQC)
	cfg.config.EncryptedClientHelloConfigList = echList
	cfg.config.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
		return errors.New("server rejected ECH")
	}
	return &STDECHConfig{cfg}
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
func BuildWithECH(serverName string, echList []byte, enablePQC bool) (*tls.Config, error) {
	cfg := NewSTDECHConfig(serverName, echList, enablePQC)
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
