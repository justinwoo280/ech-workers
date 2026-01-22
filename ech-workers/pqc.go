package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
)

// PQC (Post-Quantum Cryptography) Configuration
// Go 1.24+ natively supports X25519MLKEM768 (Kyber768)

// buildTLSConfigWithPQC creates a TLS config with post-quantum cryptography and ECH
func buildTLSConfigWithPQC(serverName string, echList []byte, enablePQC bool) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system cert pool: %w", err)
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
	}

	// Enable ECH if provided
	if len(echList) > 0 {
		cfg.EncryptedClientHelloConfigList = echList
		cfg.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
			return errors.New("server rejected ECH")
		}
	}

	// Enable Post-Quantum Key Exchange (X25519MLKEM768)
	if enablePQC {
		// Go 1.24+ enables X25519MLKEM768 by default
		// We explicitly set CurvePreferences to ensure PQC is prioritized
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768, // Post-Quantum Hybrid (X25519 + Kyber768)
			tls.X25519,         // Classical fallback
			tls.CurveP256,      // Additional fallback
		}
		log.Printf("[PQC] Enabled X25519MLKEM768 (Post-Quantum Hybrid Key Exchange)")
	} else {
		// Classical mode only
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		}
	}

	return cfg, nil
}

// buildTLSConfigWithECHAndPQC is a convenience wrapper that always enables PQC
func buildTLSConfigWithECHAndPQC(serverName string, echList []byte) (*tls.Config, error) {
	return buildTLSConfigWithPQC(serverName, echList, true)
}

// GetTLSConnectionInfo returns human-readable TLS connection info
func GetTLSConnectionInfo(state tls.ConnectionState) string {
	info := fmt.Sprintf("TLS %s", tlsVersionName(state.Version))

	if state.DidResume {
		info += " (resumed)"
	}

	info += fmt.Sprintf(", Cipher: %s", tls.CipherSuiteName(state.CipherSuite))

	return info
}

func tlsVersionName(version uint16) string {
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
