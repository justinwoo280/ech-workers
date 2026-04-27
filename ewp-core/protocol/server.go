package protocol

// server.go held the v1 SOCKS5+HTTP listener glue that ran a per-flow
// proxy session against a transport.TunnelConn. In v2 this is split
// into engine inbound/socks5 and inbound/http feeding the unified
// engine; nothing in v2 imports this file.
//
// Kept as an empty stub so any straggling external import compiles
// to a no-op rather than a missing-package error.
