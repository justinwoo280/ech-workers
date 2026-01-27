package tls

import (
	"crypto/tls"
	"net"
)

type Config interface {
	ServerName() string
	SetServerName(serverName string)
	NextProtos() []string
	SetNextProtos(nextProtos []string)
	TLSConfig() (*tls.Config, error)
	Clone() Config
}

type ECHCapableConfig interface {
	Config
	ECHConfigList() []byte
	SetECHConfigList(echList []byte)
}

type ClientHandshaker interface {
	Config
	Handshake(conn net.Conn) (net.Conn, error)
}
