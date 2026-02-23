package dns

import (
	"encoding/base64"
	"fmt"
)

// ParseResponse parses a DNS response and extracts ECH configuration from HTTPS record
// This is a simplified parser for ECH records
func ParseResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("response too short")
	}

	// Parse DNS header
	answerCount := int(response[6])<<8 | int(response[7])
	if answerCount == 0 {
		return "", fmt.Errorf("no answers in response")
	}

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

	// Parse answer section to find HTTPS record
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

		// Check if this is an HTTPS record (Type 65)
		if recordType == 65 {
			// HTTPS record data format:
			// Priority (2 bytes) + Target (variable) + SvcParams (variable)
			// ECH is in SvcParams with key 5

			if dataLen < 3 {
				offset += dataLen
				continue
			}

			// Skip priority (2 bytes)
			dataOffset := offset + 2

			// Skip target name
			for dataOffset < offset+dataLen && response[dataOffset] != 0 {
				labelLen := int(response[dataOffset])
				if labelLen&0xC0 == 0xC0 {
					dataOffset += 2
					break
				}
				dataOffset += labelLen + 1
			}
			if dataOffset < offset+dataLen {
				dataOffset++ // skip null terminator
			}

			// Parse SvcParams to find ECH (key 5)
			for dataOffset+4 <= offset+dataLen {
				paramKey := uint16(response[dataOffset])<<8 | uint16(response[dataOffset+1])
				paramLen := uint16(response[dataOffset+2])<<8 | uint16(response[dataOffset+3])
				dataOffset += 4

				if dataOffset+int(paramLen) > offset+dataLen {
					break
				}

				// ECH parameter key is 5
				if paramKey == 5 {
					echData := response[dataOffset : dataOffset+int(paramLen)]
					// Return base64 encoded ECH data
					return base64.StdEncoding.EncodeToString(echData), nil
				}

				dataOffset += int(paramLen)
			}
		}

		offset += dataLen
	}

	return "", fmt.Errorf("no ECH parameter found in HTTPS record")
}
