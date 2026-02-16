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
	"time"

	"ewp-core/log"
	
	"golang.org/x/net/http2"
)

var _ BootstrapTransport = (*DoHTransport)(nil)

// DoHTransport implements DNS over HTTPS (RFC 8484)
type DoHTransport struct {
	serverURL  string
	httpClient *http.Client
}

// NewDoHTransport creates a new DoH transport
func NewDoHTransport(serverURL string) *DoHTransport {
	// Parse URL to get server name for SNI
	u, _ := url.Parse(serverURL)
	serverName := u.Hostname()
	
	// Create TLS config for HTTP/2
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
		ServerName: serverName, // Use hostname as SNI even when connecting to IP
		// InsecureSkipVerify: false means verify the cert against ServerName
	}
	
	// Create HTTP/2 transport with custom dialer (no DNS resolution needed)
	transport := &http2.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: false,
		AllowHTTP:          false,
		// DialTLSContext will use the IP address directly from URL
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			// addr is already "ip:port" from the URL, no DNS lookup needed
			log.V("[DoH Bootstrap] Dialing %s %s (SNI: %s)", network, addr, cfg.ServerName)
			
			dialer := &net.Dialer{
				Timeout: 5 * time.Second,
			}
			
			// Dial TCP connection
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				log.Printf("[DoH Bootstrap] TCP dial failed: %v", err)
				return nil, err
			}
			
			// Perform TLS handshake
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				log.Printf("[DoH Bootstrap] TLS handshake failed: %v", err)
				return nil, err
			}
			
			log.V("[DoH Bootstrap] TLS connection established to %s", addr)
			return tlsConn, nil
		},
	}

	return &DoHTransport{
		serverURL: serverURL,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// Query performs a DNS query via DoH using HTTP/2 POST method (RFC 8484)
func (t *DoHTransport) Query(ctx context.Context, domain string, qtype uint16) ([]net.IP, error) {
	log.Printf("[DoH Bootstrap] Querying %s (type %d) via %s", domain, qtype, t.serverURL)
	
	// Build DNS query
	dnsQuery := BuildQuery(domain, qtype)

	// Parse server URL
	u, err := url.Parse(t.serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}

	// Create HTTP POST request with DNS query as body
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// Send request via HTTP/2
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned error: %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Parse DNS response
	ips, err := parseDNSResponse(body, qtype)
	if err != nil {
		log.Printf("[DoH Bootstrap] Failed to parse response for %s: %v", domain, err)
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}
	
	log.Printf("[DoH Bootstrap] Resolved %s -> %v (%d IPs)", domain, ips, len(ips))

	return ips, nil
}

// Type returns the transport type
func (t *DoHTransport) Type() string {
	return "DoH"
}

// Server returns the server address
func (t *DoHTransport) Server() string {
	return t.serverURL
}

// Close closes the transport and releases resources
func (t *DoHTransport) Close() error {
	t.httpClient.CloseIdleConnections()
	return nil
}

// parseDNSResponse parses DNS response and extracts IP addresses
func parseDNSResponse(response []byte, qtype uint16) ([]net.IP, error) {
	if len(response) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// Parse DNS header
	answerCount := int(response[6])<<8 | int(response[7])
	if answerCount == 0 {
		return nil, fmt.Errorf("no answers in response")
	}

	var ips []net.IP
	offset := 12

	// Skip question section
	for offset < len(response) {
		if response[offset] == 0 {
			offset += 5 // null + qtype(2) + qclass(2)
			break
		}
		labelLen := int(response[offset])
		if labelLen&0xC0 == 0xC0 {
			offset += 2
			offset += 4
			break
		}
		offset += labelLen + 1
	}

	// Parse answer section
	for i := 0; i < answerCount && offset < len(response); i++ {
		// Skip name (usually compressed pointer)
		if offset+2 > len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				labelLen := int(response[offset])
				offset += labelLen + 1
			}
			offset++
		}

		if offset+10 > len(response) {
			break
		}

		recordType := uint16(response[offset])<<8 | uint16(response[offset+1])
		dataLen := int(response[offset+8])<<8 | int(response[offset+9])
		offset += 10

		if offset+dataLen > len(response) {
			break
		}

		// Extract IP based on record type
		if recordType == qtype {
			if qtype == 1 && dataLen == 4 { // Type A
				ip := net.IP(bytes.Clone(response[offset : offset+4]))
				ips = append(ips, ip)
			} else if qtype == 28 && dataLen == 16 { // Type AAAA
				ip := net.IP(bytes.Clone(response[offset : offset+16]))
				ips = append(ips, ip)
			}
		}

		offset += dataLen
	}

	return ips, nil
}
