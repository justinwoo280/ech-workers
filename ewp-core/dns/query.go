package dns

import (
	"encoding/binary"
	"errors"
	"strings"

	"ewp-core/constant"
)

// BuildQuery builds a DNS query packet
func BuildQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	// DNS header: ID=0x0001, Flags=0x0100 (standard query), QDCOUNT=1
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Question section
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00) // End of domain name

	// QTYPE and QCLASS
	query = append(query, byte(qtype>>8), byte(qtype))
	query = append(query, 0x00, 0x01) // QCLASS = IN

	return query
}

// ParseResponse parses a DNS response and extracts HTTPS record ECH parameter
func ParseResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("response too short")
	}

	// Parse header
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("no answer records")
	}

	// Skip question section
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5 // Skip null terminator + QTYPE + QCLASS

	// Parse answer section
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}

		// Skip NAME (compressed or full)
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}

		if offset+10 > len(response) {
			break
		}

		// Parse TYPE, CLASS, TTL, RDLENGTH
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8 // Skip TYPE + CLASS + TTL
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		if offset+int(dataLen) > len(response) {
			break
		}

		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		// Check if this is an HTTPS record
		if rrType == constant.TypeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}

	return "", nil
}

// parseHTTPSRecord parses an HTTPS (SVCB) record and extracts ECH parameter (key=5)
func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Skip SvcPriority
	offset := 2

	// Skip TargetName
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}

	// Parse SvcParams
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(length) > len(data) {
			break
		}

		value := data[offset : offset+int(length)]
		offset += int(length)

		// ECH parameter key = 5
		if key == 5 {
			return string(value) // Return raw ECH config
		}
	}

	return ""
}
