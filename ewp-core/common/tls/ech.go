package tls

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"ewp-core/dns"
	echlog "ewp-core/log"
)

// ECHManager manages ECH configuration
type ECHManager struct {
	domain    string
	dnsServer string
	echList   []byte
	mu        sync.RWMutex
	dnsClient *dns.Client
}

// NewECHManager creates a new ECH manager
func NewECHManager(domain, dnsServer string) *ECHManager {
	return &ECHManager{
		domain:    domain,
		dnsServer: dnsServer,
		dnsClient: dns.NewClient(dnsServer),
	}
}

// Refresh fetches and updates ECH configuration
func (m *ECHManager) Refresh() error {
	echlog.Printf("[ECH] Refreshing configuration...")

	// Query HTTPS record for ECH
	echBase64, err := m.dnsClient.QueryHTTPS(m.domain)
	if err != nil {
		return fmt.Errorf("DNS query failed: %w", err)
	}

	if echBase64 == "" {
		return errors.New("no ECH parameter found")
	}

	// Decode base64
	echList, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH decode failed: %w", err)
	}

	// Update ECH list
	m.mu.Lock()
	m.echList = echList
	m.mu.Unlock()

	echlog.Printf("[ECH] Configuration loaded, length: %d bytes", len(echList))
	return nil
}

// Get returns the current ECH configuration
func (m *ECHManager) Get() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.echList) == 0 {
		return nil, errors.New("ECH configuration not loaded")
	}

	return m.echList, nil
}

// GetDomain returns the ECH domain
func (m *ECHManager) GetDomain() string {
	return m.domain
}

// GetDNSServer returns the DNS server URL
func (m *ECHManager) GetDNSServer() string {
	return m.dnsServer
}
