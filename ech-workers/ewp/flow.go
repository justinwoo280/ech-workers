package ewp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
)

// EWP Flow Protocol - Vision-based flow control
// Replaces Yamux with unified flow control across all transports

const (
	// === Padding Commands (from Vision) ===
	FlowCommandContinue byte = 0x00 // Continue padding (more packets coming)
	FlowCommandEnd      byte = 0x01 // End padding (switch to normal mode)
	FlowCommandDirect   byte = 0x02 // Switch to direct copy (zero-copy)

	// === Multiplexing Commands (WebSocket only) ===
	FlowCommandStreamNew   byte = 0x10 // New stream
	FlowCommandStreamData  byte = 0x11 // Stream data
	FlowCommandStreamClose byte = 0x12 // Close stream

	// === Control Commands ===
	FlowCommandPing  byte = 0x20 // Heartbeat
	FlowCommandPong  byte = 0x21 // Heartbeat response
	FlowCommandError byte = 0x22 // Error notification
)

const (
	// TLS handshake types
	TlsHandshakeTypeClientHello byte = 0x01
	TlsHandshakeTypeServerHello byte = 0x02
)

var (
	// TLS signatures (from Xray)
	Tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	TlsClientHandShakeStart = []byte{0x16, 0x03}
	TlsServerHandShakeStart = []byte{0x16, 0x03, 0x03}
	TlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

	// TLS 1.3 Cipher Suites
	Tls13CipherSuiteDic = map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
	}
)

// FlowFrame represents a single flow control frame
type FlowFrame struct {
	StreamID   uint16 // 0 for non-multiplexed transports (gRPC/XHTTP)
	Command    byte
	ContentLen uint16
	PaddingLen uint16
	Content    []byte
	Padding    []byte
}

// EncodeFlowFrame encodes a flow frame to wire format
func EncodeFlowFrame(streamID uint16, command byte, content []byte, paddingLen uint16) []byte {
	contentLen := uint16(len(content))
	totalLen := 7 + contentLen + paddingLen // 7 = StreamID(2) + Command(1) + ContentLen(2) + PaddingLen(2)

	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:2], streamID)
	buf[2] = command
	binary.BigEndian.PutUint16(buf[3:5], contentLen)
	binary.BigEndian.PutUint16(buf[5:7], paddingLen)

	if contentLen > 0 {
		copy(buf[7:7+contentLen], content)
	}

	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		rand.Read(padding)
		copy(buf[7+contentLen:], padding)
	}

	return buf
}

// DecodeFlowFrame decodes a flow frame from wire format
func DecodeFlowFrame(r io.Reader) (*FlowFrame, error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	frame := &FlowFrame{
		StreamID:   binary.BigEndian.Uint16(header[0:2]),
		Command:    header[2],
		ContentLen: binary.BigEndian.Uint16(header[3:5]),
		PaddingLen: binary.BigEndian.Uint16(header[5:7]),
	}

	if frame.ContentLen > 0 {
		frame.Content = make([]byte, frame.ContentLen)
		if _, err := io.ReadFull(r, frame.Content); err != nil {
			return nil, err
		}
	}

	if frame.PaddingLen > 0 {
		frame.Padding = make([]byte, frame.PaddingLen)
		if _, err := io.ReadFull(r, frame.Padding); err != nil {
			return nil, err
		}
	}

	return frame, nil
}

// PaddingConfig defines padding behavior (from Vision testseed)
type PaddingConfig struct {
	MinContentForLongPadding int // Default: 900
	MaxRandomPadding         int // Default: 500
	LongPaddingBase          int // Default: 900
	ShortPaddingMax          int // Default: 256
}

// DefaultPaddingConfig matches Xray Vision defaults: [900, 500, 900, 256]
var DefaultPaddingConfig = &PaddingConfig{
	MinContentForLongPadding: 900,
	MaxRandomPadding:         500,
	LongPaddingBase:          900,
	ShortPaddingMax:          256,
}

// CalculatePadding implements Vision's dynamic padding algorithm
func (cfg *PaddingConfig) CalculatePadding(contentLen int32, isTLS bool) int32 {
	if contentLen < int32(cfg.MinContentForLongPadding) && isTLS {
		// Long padding: rand(500) + 900 - contentLen
		l, err := rand.Int(rand.Reader, big.NewInt(int64(cfg.MaxRandomPadding)))
		if err != nil {
			return 0
		}
		paddingLen := int32(l.Int64()) + int32(cfg.LongPaddingBase) - contentLen
		if paddingLen < 0 {
			return 0
		}
		return paddingLen
	}

	// Short padding: rand(256)
	l, err := rand.Int(rand.Reader, big.NewInt(int64(cfg.ShortPaddingMax)))
	if err != nil {
		return 0
	}
	return int32(l.Int64())
}

// XtlsPadding adds Vision-style padding to eliminate length signature
// Ported directly from Xray-core proxy/proxy.go
func XtlsPadding(content []byte, command byte, userUUID *[]byte, longPadding bool, cfg *PaddingConfig) []byte {
	var contentLen int32 = 0
	if content != nil {
		contentLen = int32(len(content))
	}

	paddingLen := cfg.CalculatePadding(contentLen, longPadding)
	// Limit to avoid overflow: max 65535 - 21 (max header) - contentLen
	if paddingLen > 65535-21-contentLen {
		paddingLen = 65535 - 21 - contentLen
	}
	if paddingLen < 0 {
		paddingLen = 0
	}

	totalLen := 0
	if userUUID != nil && len(*userUUID) > 0 {
		totalLen += 16
	}
	totalLen += 5 + int(contentLen) + int(paddingLen)

	newbuffer := make([]byte, totalLen)
	pos := 0

	// Write UserUUID (once)
	if userUUID != nil && len(*userUUID) > 0 {
		copy(newbuffer[pos:pos+16], *userUUID)
		pos += 16
		*userUUID = nil // Clear after first use
	}

	// Write command header: [command(1) | contentLen(2) | paddingLen(2)]
	newbuffer[pos] = command
	pos++
	binary.BigEndian.PutUint16(newbuffer[pos:pos+2], uint16(contentLen))
	pos += 2
	binary.BigEndian.PutUint16(newbuffer[pos:pos+2], uint16(paddingLen))
	pos += 2

	// Write content
	if contentLen > 0 {
		copy(newbuffer[pos:pos+int(contentLen)], content)
		pos += int(contentLen)
	}

	// Write random padding
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		rand.Read(padding)
		copy(newbuffer[pos:], padding)
	}

	return newbuffer
}

// XtlsUnpadding removes padding and parses command
// Ported directly from Xray-core proxy/proxy.go
func XtlsUnpadding(data []byte, state *FlowState, isUplink bool) []byte {
	var remainingCommand *int32
	var remainingContent *int32
	var remainingPadding *int32
	var currentCommand *int

	if isUplink {
		remainingCommand = &state.Inbound.RemainingCommand
		remainingContent = &state.Inbound.RemainingContent
		remainingPadding = &state.Inbound.RemainingPadding
		currentCommand = &state.Inbound.CurrentCommand
	} else {
		remainingCommand = &state.Outbound.RemainingCommand
		remainingContent = &state.Outbound.RemainingContent
		remainingPadding = &state.Outbound.RemainingPadding
		currentCommand = &state.Outbound.CurrentCommand
	}

	// Initial state: check for UserUUID (16 bytes)
	if *remainingCommand == -1 && *remainingContent == -1 && *remainingPadding == -1 {
		if len(data) >= 21 && bytes.Equal(state.UserUUID, data[:16]) {
			data = data[16:] // Skip UserUUID
			*remainingCommand = 5
		} else {
			return data // Not padded data, return as-is
		}
	}

	newbuffer := &bytes.Buffer{}
	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		if *remainingCommand > 0 {
			// Parse command header: [command(1) | contentLen(2) | paddingLen(2)]
			b, err := reader.ReadByte()
			if err != nil {
				break
			}
			switch *remainingCommand {
			case 5:
				*currentCommand = int(b)
			case 4:
				*remainingContent = int32(b) << 8
			case 3:
				*remainingContent = *remainingContent | int32(b)
			case 2:
				*remainingPadding = int32(b) << 8
			case 1:
				*remainingPadding = *remainingPadding | int32(b)
			}
			*remainingCommand--
		} else if *remainingContent > 0 {
			// Read content
			length := *remainingContent
			if int32(reader.Len()) < length {
				length = int32(reader.Len())
			}
			buf := make([]byte, length)
			n, _ := reader.Read(buf)
			newbuffer.Write(buf[:n])
			*remainingContent -= int32(n)
		} else if *remainingPadding > 0 {
			// Skip padding
			length := *remainingPadding
			if int32(reader.Len()) < length {
				length = int32(reader.Len())
			}
			reader.Seek(int64(length), io.SeekCurrent)
			*remainingPadding -= length
		}

		// Check if current block is done
		if *remainingCommand <= 0 && *remainingContent <= 0 && *remainingPadding <= 0 {
			if *currentCommand == 0 { // CommandPaddingContinue
				*remainingCommand = 5 // Continue to next block
			} else { // CommandPaddingEnd (1) or CommandPaddingDirect (2)
				// End of padding, reset to initial state
				*remainingCommand = -1
				*remainingContent = -1
				*remainingPadding = -1
				// Append any remaining data (shouldn't happen in normal case)
				if reader.Len() > 0 {
					remaining := make([]byte, reader.Len())
					reader.Read(remaining)
					newbuffer.Write(remaining)
				}
				break
			}
		}
	}

	return newbuffer.Bytes()
}

// IsCompleteRecord checks if buffer contains complete TLS record(s)
// Ported from Xray-core proxy/proxy.go
func IsCompleteRecord(data []byte) bool {
	totalLen := len(data)
	if totalLen < 5 {
		return false
	}

	var headerLen int = 5
	var recordLen int
	i := 0

	for i < totalLen {
		if headerLen > 0 {
			b := data[i]
			i++
			switch headerLen {
			case 5:
				if b != 0x17 {
					return false
				}
			case 4:
				if b != 0x03 {
					return false
				}
			case 3:
				if b != 0x03 {
					return false
				}
			case 2:
				recordLen = int(b) << 8
			case 1:
				recordLen = recordLen | int(b)
			}
			headerLen--
		} else if recordLen > 0 {
			remaining := totalLen - i
			if remaining < recordLen {
				return false
			}
			i += recordLen
			recordLen = 0
			headerLen = 5
		} else {
			return false
		}
	}

	return headerLen == 5 && recordLen == 0
}
