package ewp

import (
	"bytes"
	"encoding/binary"
)

// FlowState tracks traffic state for Vision-style flow control
// Ported from Xray-core proxy/proxy.go TrafficState
type FlowState struct {
	UserUUID               []byte
	NumberOfPacketToFilter int
	EnableXtls             bool
	IsTLS12orAbove         bool
	IsTLS                  bool
	Cipher                 uint16
	RemainingServerHello   int32
	Inbound                InboundState
	Outbound               OutboundState
	PaddingConfig          *PaddingConfig
}

type InboundState struct {
	// Reader link state
	WithinPaddingBuffers   bool
	UplinkReaderDirectCopy bool
	RemainingCommand       int32
	RemainingContent       int32
	RemainingPadding       int32
	CurrentCommand         int
	// Writer link state
	IsPadding                bool
	DownlinkWriterDirectCopy bool
}

type OutboundState struct {
	// Reader link state
	WithinPaddingBuffers     bool
	DownlinkReaderDirectCopy bool
	RemainingCommand         int32
	RemainingContent         int32
	RemainingPadding         int32
	CurrentCommand           int
	// Writer link state
	IsPadding              bool
	UplinkWriterDirectCopy bool
}

// NewFlowState creates a new flow state with Vision defaults
func NewFlowState(userUUID []byte) *FlowState {
	return &FlowState{
		UserUUID:               userUUID,
		NumberOfPacketToFilter: 8, // Check first 8 packets
		EnableXtls:             false,
		IsTLS12orAbove:         false,
		IsTLS:                  false,
		Cipher:                 0,
		RemainingServerHello:   -1,
		Inbound: InboundState{
			WithinPaddingBuffers:     true,
			UplinkReaderDirectCopy:   false,
			RemainingCommand:         -1,
			RemainingContent:         -1,
			RemainingPadding:         -1,
			CurrentCommand:           0,
			IsPadding:                true,
			DownlinkWriterDirectCopy: false,
		},
		Outbound: OutboundState{
			WithinPaddingBuffers:     true,
			DownlinkReaderDirectCopy: false,
			RemainingCommand:         -1,
			RemainingContent:         -1,
			RemainingPadding:         -1,
			CurrentCommand:           0,
			IsPadding:                true,
			UplinkWriterDirectCopy:   false,
		},
		PaddingConfig: DefaultPaddingConfig,
	}
}

// XtlsFilterTls filters and recognizes TLS 1.3 traffic
// Ported from Xray-core proxy/proxy.go
func (s *FlowState) XtlsFilterTls(data []byte) {
	if s.NumberOfPacketToFilter <= 0 {
		return
	}

	s.NumberOfPacketToFilter--

	if len(data) < 6 {
		return
	}

	startsBytes := data[:6]

	// Detect TLS Server Hello
	if bytes.Equal(TlsServerHandShakeStart, startsBytes[:3]) && startsBytes[5] == TlsHandshakeTypeServerHello {
		s.RemainingServerHello = (int32(startsBytes[3])<<8 | int32(startsBytes[4])) + 5
		s.IsTLS12orAbove = true
		s.IsTLS = true

		// Extract cipher suite if possible
		if len(data) >= 79 && s.RemainingServerHello >= 79 {
			sessionIdLen := int32(data[43])
			if len(data) >= int(43+sessionIdLen+3) {
				cipherSuite := data[43+sessionIdLen+1 : 43+sessionIdLen+3]
				s.Cipher = binary.BigEndian.Uint16(cipherSuite)
			}
		}
	} else if bytes.Equal(TlsClientHandShakeStart, startsBytes[:2]) && startsBytes[5] == TlsHandshakeTypeClientHello {
		s.IsTLS = true
	}

	// Check for TLS 1.3 in Server Hello
	if s.RemainingServerHello > 0 {
		end := s.RemainingServerHello
		if end > int32(len(data)) {
			end = int32(len(data))
		}
		s.RemainingServerHello -= int32(len(data))

		if bytes.Contains(data[:end], Tls13SupportedVersions) {
			// Found TLS 1.3!
			if cipherName, ok := Tls13CipherSuiteDic[s.Cipher]; ok {
				// Enable XTLS for all ciphers except TLS_AES_128_CCM_8_SHA256
				if cipherName != "TLS_AES_128_CCM_8_SHA256" {
					s.EnableXtls = true
				}
			}
			s.NumberOfPacketToFilter = 0 // Stop filtering
			return
		} else if s.RemainingServerHello <= 0 {
			// Found TLS 1.2
			s.NumberOfPacketToFilter = 0
			return
		}
	}
}

// ShouldPad checks if current traffic should be padded
func (s *FlowState) ShouldPad(isUplink bool) bool {
	if isUplink {
		return s.Outbound.IsPadding
	}
	return s.Inbound.IsPadding
}

// ShouldDirectCopy checks if should switch to zero-copy mode
func (s *FlowState) ShouldDirectCopy(isUplink bool) bool {
	if isUplink {
		return s.Outbound.UplinkWriterDirectCopy
	}
	return s.Inbound.DownlinkWriterDirectCopy
}

// CheckDirectCopySwitch checks if should switch to direct copy based on TLS state
func (s *FlowState) CheckDirectCopySwitch(data []byte, isUplink bool) byte {
	// Check for TLS Application Data (0x17 0x03 0x03)
	if s.IsTLS && len(data) >= 3 && bytes.Equal(TlsApplicationDataStart, data[:3]) {
		if s.EnableXtls {
			if isUplink {
				s.Outbound.UplinkWriterDirectCopy = true
			} else {
				s.Inbound.DownlinkWriterDirectCopy = true
			}
			return FlowCommandDirect
		}
		// TLS detected but XTLS not enabled, end padding
		if isUplink {
			s.Outbound.IsPadding = false
		} else {
			s.Inbound.IsPadding = false
		}
		return FlowCommandEnd
	}

	// Check if still in padding phase
	if s.ShouldPad(isUplink) {
		return FlowCommandContinue
	}

	return FlowCommandEnd
}

// ProcessUplink processes uplink data (client -> server)
func (s *FlowState) ProcessUplink(data []byte) []byte {
	// Filter TLS if needed
	if s.NumberOfPacketToFilter > 0 {
		s.XtlsFilterTls(data)
	}

	// Unpad if within padding buffers
	if s.Inbound.WithinPaddingBuffers {
		unpaddedData := XtlsUnpadding(data, s, true)

		// Check if still in padding
		if s.Inbound.RemainingContent > 0 || s.Inbound.RemainingPadding > 0 || s.Inbound.CurrentCommand == 0 {
			s.Inbound.WithinPaddingBuffers = true
		} else if s.Inbound.CurrentCommand == 1 {
			s.Inbound.WithinPaddingBuffers = false
		} else if s.Inbound.CurrentCommand == 2 {
			s.Inbound.WithinPaddingBuffers = false
			s.Inbound.UplinkReaderDirectCopy = true
		}

		return unpaddedData
	}

	return data
}

// ProcessDownlink processes downlink data (server -> client)
func (s *FlowState) ProcessDownlink(data []byte) []byte {
	// Filter TLS if needed
	if s.NumberOfPacketToFilter > 0 {
		s.XtlsFilterTls(data)
	}

	// Unpad if within padding buffers
	if s.Outbound.WithinPaddingBuffers {
		unpaddedData := XtlsUnpadding(data, s, false)

		// Check if still in padding
		if s.Outbound.RemainingContent > 0 || s.Outbound.RemainingPadding > 0 || s.Outbound.CurrentCommand == 0 {
			s.Outbound.WithinPaddingBuffers = true
		} else if s.Outbound.CurrentCommand == 1 {
			s.Outbound.WithinPaddingBuffers = false
		} else if s.Outbound.CurrentCommand == 2 {
			s.Outbound.WithinPaddingBuffers = false
			s.Outbound.DownlinkReaderDirectCopy = true
		}

		return unpaddedData
	}

	return data
}

// PadUplink pads uplink data (client -> server)
func (s *FlowState) PadUplink(data []byte, userUUID *[]byte) []byte {
	if !s.Outbound.IsPadding {
		return data
	}

	command := s.CheckDirectCopySwitch(data, true)
	longPadding := s.IsTLS
	return XtlsPadding(data, command, userUUID, longPadding, s.PaddingConfig)
}

// PadDownlink pads downlink data (server -> client)
func (s *FlowState) PadDownlink(data []byte, userUUID *[]byte) []byte {
	if !s.Inbound.IsPadding {
		return data
	}

	command := s.CheckDirectCopySwitch(data, false)
	longPadding := s.IsTLS
	return XtlsPadding(data, command, userUUID, longPadding, s.PaddingConfig)
}
