package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ewp-core/constant"
	"ewp-core/log"

	"golang.org/x/net/http2"
)

// Client represents a DoH (DNS over HTTPS) client
type Client struct {
	ServerURL  string
	Timeout    time.Duration
	httpClient *http.Client
}

// NewClient creates a new DoH client that works without DNS resolution
func NewClient(serverURL string) *Client {
	if !strings.HasPrefix(serverURL, "https://") && !strings.HasPrefix(serverURL, "http://") {
		serverURL = "https://" + serverURL
	}

	// Parse URL to get server name for SNI
	u, err := url.Parse(serverURL)
	if err != nil {
		log.Printf("[DoH Client] Invalid URL %s: %v", serverURL, err)
		// Fallback to simple client
		return &Client{
			ServerURL: serverURL,
			Timeout:   10 * time.Second,
			httpClient: &http.Client{
				Timeout: 10 * time.Second,
			},
		}
	}

	serverName := u.Hostname()

	// Create TLS config for HTTP/2
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
		ServerName: serverName,
	}

	// Create HTTP/2 transport with custom dialer (no DNS resolution needed)
	transport := &http2.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: false,
		AllowHTTP:          false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			log.V("[DoH Client] Dialing %s %s (SNI: %s)", network, addr, cfg.ServerName)

			dialer := &net.Dialer{
				Timeout: 5 * time.Second,
			}

			// Dial TCP connection
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				log.Printf("[DoH Client] TCP dial failed: %v", err)
				return nil, err
			}

			// Perform TLS handshake
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				log.Printf("[DoH Client] TLS handshake failed: %v", err)
				return nil, err
			}

			log.V("[DoH Client] TLS connection established to %s", addr)
			return tlsConn, nil
		},
	}

	return &Client{
		ServerURL: serverURL,
		Timeout:   10 * time.Second,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// QueryHTTPS queries HTTPS record for ECH configuration
func (c *Client) QueryHTTPS(domain string) (string, error) {
	return c.Query(domain, constant.TypeHTTPS)
}

// Query performs a DoH query using POST method (RFC 8484)
func (c *Client) Query(domain string, qtype uint16) (string, error) {
	log.Printf("[DoH Client] Querying %s (type %d) via %s", domain, qtype, c.ServerURL)

	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return "", fmt.Errorf("invalid DoH URL: %w", err)
	}

	// Build DNS query
	dnsQuery := BuildQuery(domain, qtype)

	// Create HTTP POST request with DNS query as body
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(dnsQuery))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// Send request using configured HTTP client
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH server returned error: %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Parse DNS response
	echBase64, err := ParseResponse(body)
	if err != nil {
		return "", fmt.Errorf("failed to parse DNS response: %w", err)
	}

	if echBase64 == "" {
		log.Printf("[DoH Client] No ECH parameter found for %s", domain)
		return "", fmt.Errorf("no ECH parameter found")
	}

	log.Printf("[DoH Client] Successfully retrieved ECH config for %s (%d bytes)", domain, len(echBase64))
	return echBase64, nil
}

// QueryRaw performs a raw DoH query using POST method (RFC 8484)
func (c *Client) QueryRaw(dnsQuery []byte) ([]byte, error) {
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}

	// Create HTTP POST request with raw DNS query as body
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// Send request using configured HTTP client
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned error: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
