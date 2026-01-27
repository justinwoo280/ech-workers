package constant

// Transport modes
const (
	TransportWebSocket = "ws"
	TransportGRPC      = "grpc"
	TransportXHTTP     = "xhttp"
)

// DNS record types
const (
	TypeHTTPS uint16 = 65
)

// Default values
const (
	DefaultListenAddr   = "127.0.0.1:30000"
	DefaultDNSServer    = "dns.alidns.com/dns-query"
	DefaultECHDomain    = "cloudflare-ech.com"
	DefaultNumConns     = 1
	DefaultXHTTPMode    = "auto"
	DefaultTunIP        = "10.0.85.2"
	DefaultTunGateway   = "10.0.85.1"
	DefaultTunMask      = "255.255.255.0"
	DefaultTunDNS       = "1.1.1.1"
	DefaultTunMTU       = 1380
)

// Buffer sizes
const (
	SmallBufferSize = 512
	LargeBufferSize = 32 * 1024
	UDPBufferSize   = 65536
)

// Timeouts
const (
	DefaultDialTimeout      = 10 // seconds
	DefaultHandshakeTimeout = 10 // seconds
)
