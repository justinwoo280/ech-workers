package server

import (
	"fmt"
	"io"

	"ewp-core/protocol/trojan"
)

type TrojanProtocolHandler struct {
	validKeys map[[trojan.KeyLength]byte]string
}

func NewTrojanProtocolHandler() *TrojanProtocolHandler {
	return &TrojanProtocolHandler{
		validKeys: GetTrojanValidKeys(),
	}
}

func (h *TrojanProtocolHandler) Handshake(data []byte, clientIP string) (*HandshakeResult, error) {
	if h.validKeys == nil {
		return nil, fmt.Errorf("no valid Trojan keys configured")
	}

	reader := &byteReader{data: data, pos: 0}
	pwd, command, addr, err := trojan.ReadHandshake(reader, h.validKeys)
	if err != nil {
		return nil, fmt.Errorf("Trojan handshake failed: %w", err)
	}

	result := &HandshakeResult{
		Target: addr.String(),
		IsUDP:  command == trojan.CommandUDP,
		UserID: maskPassword(pwd),
	}

	if reader.pos < len(reader.data) {
		result.InitialData = reader.data[reader.pos:]
	}

	return result, nil
}

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
