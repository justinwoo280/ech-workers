package tls

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"ewp-core/dns"
	echlog "ewp-core/log"
)

// ECHManager manages ECH configuration with TTL-based caching
type ECHManager struct {
	domain     string
	dnsServer  string
	echList    []byte
	lastFetch  time.Time
	cacheTTL   time.Duration
	mu         sync.RWMutex
	dnsClient  *dns.Client
	stopClean  chan struct{}
	cleanOnce  sync.Once
}

// NewECHManager creates a new ECH manager with 1-hour cache TTL
func NewECHManager(domain, dnsServer string) *ECHManager {
	m := &ECHManager{
		domain:    domain,
		dnsServer: dnsServer,
		cacheTTL:  1 * time.Hour,
		dnsClient: dns.NewClient(dnsServer),
		stopClean: make(chan struct{}),
	}
	m.startCleanupRoutine()
	return m
}

// NewECHManagerWithTTL creates a new ECH manager with custom cache TTL
func NewECHManagerWithTTL(domain, dnsServer string, ttl time.Duration) *ECHManager {
	m := &ECHManager{
		domain:    domain,
		dnsServer: dnsServer,
		cacheTTL:  ttl,
		dnsClient: dns.NewClient(dnsServer),
		stopClean: make(chan struct{}),
	}
	m.startCleanupRoutine()
	return m
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

	// Decode base64 ECH data
	echList, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("failed to decode ECH config: %w", err)
	}

	// Update ECH list and fetch timestamp
	m.mu.Lock()
	m.echList = echList
	m.lastFetch = time.Now()
	m.mu.Unlock()

	echlog.Printf("[ECH] Configuration loaded, length: %d bytes, TTL: %v", len(echList), m.cacheTTL)
	return nil
}

// Get returns the current ECH configuration, auto-refreshing if expired
func (m *ECHManager) Get() ([]byte, error) {
	m.mu.RLock()
	needsRefresh := m.isExpired()
	m.mu.RUnlock()

	// Auto-refresh if cache expired
	if needsRefresh {
		echlog.Printf("[ECH] Cache expired, auto-refreshing...")
		if err := m.Refresh(); err != nil {
			echlog.Printf("[ECH] Auto-refresh failed: %v", err)
			// Return cached data even if expired (fallback)
			m.mu.RLock()
			defer m.mu.RUnlock()
			if len(m.echList) > 0 {
				echlog.Printf("[ECH] Using expired cache as fallback")
				return m.echList, nil
			}
			return nil, fmt.Errorf("refresh failed and no cache available: %w", err)
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.echList) == 0 {
		return nil, errors.New("ECH configuration not loaded")
	}

	return m.echList, nil
}

// UpdateFromRetry updates ECH configuration from server's retry config
// This is called when server returns ECHRejectionError with RetryConfigList
func (m *ECHManager) UpdateFromRetry(retryConfigList []byte) error {
	if len(retryConfigList) == 0 {
		return errors.New("empty retry config list")
	}

	m.mu.Lock()
	m.echList = retryConfigList
	m.lastFetch = time.Now()
	m.mu.Unlock()

	echlog.Printf("[ECH] Updated configuration from server retry, length: %d bytes", len(retryConfigList))
	return nil
}

// isExpired checks if the cache has expired (caller must hold at least RLock)
func (m *ECHManager) isExpired() bool {
	if m.lastFetch.IsZero() {
		return true
	}
	return time.Since(m.lastFetch) > m.cacheTTL
}

// GetDomain returns the ECH domain
func (m *ECHManager) GetDomain() string {
	return m.domain
}

// GetDNSServer returns the DNS server URL
func (m *ECHManager) GetDNSServer() string {
	return m.dnsServer
}

// startCleanupRoutine starts a background goroutine to periodically check and refresh expired cache
func (m *ECHManager) startCleanupRoutine() {
	m.cleanOnce.Do(func() {
		go m.cleanupLoop()
	})
}

// cleanupLoop runs periodically to check and refresh expired cache
func (m *ECHManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.RLock()
			expired := m.isExpired()
			m.mu.RUnlock()

			if expired {
				echlog.Printf("[ECH] Background cleanup: cache expired, refreshing...")
				if err := m.Refresh(); err != nil {
					echlog.Printf("[ECH] Background refresh failed: %v", err)
				}
			}
		case <-m.stopClean:
			echlog.Printf("[ECH] Cleanup routine stopped")
			return
		}
	}
}

// Stop stops the background cleanup routine
func (m *ECHManager) Stop() {
	close(m.stopClean)
}

// GetCacheAge returns the age of the current cache
func (m *ECHManager) GetCacheAge() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.lastFetch.IsZero() {
		return 0
	}
	return time.Since(m.lastFetch)
}

// GetCacheTTL returns the configured cache TTL
func (m *ECHManager) GetCacheTTL() time.Duration {
	return m.cacheTTL
}
