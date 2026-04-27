package protocol

// proxy.go held the v1 TunnelHandler that wired a per-flow proxy
// session directly onto a transport.TunnelConn via the deprecated
// Connect / Read / Write / StartPing methods, using a hot-reload
// atomic.Value transport.
//
// In v2 there is no standalone TunnelHandler. Inbounds push flows
// into the engine; the engine routes to an Outbound; the outbound
// (typically ewpclient) holds the v2 SecureStream and does all
// framing/encryption. See engine/, outbound/ewpclient/, inbound/.
//
// Kept as an empty stub for the same reason as server.go.
