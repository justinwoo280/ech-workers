package trojan

import (
	"fmt"
	"net/netip"
)

// DecodeUDPPayloadWithAddrAndDomain decodes a Trojan UDP frame and returns payload, address, and domain.
// This is needed because Trojan can carry domain addresses which should be preserved.
func DecodeUDPPayloadWithAddrAndDomain(data []byte) ([]byte, netip.AddrPort, string, error) {
	if len(data) < 1 {
		return nil, netip.AddrPort{}, "", fmt.Errorf("empty trojan udp payload")
	}

	var offset int
	var addr netip.AddrPort
	var domain string

	// Parse address type
	atyp := data[offset]
	offset++

	switch atyp {
	case AddressTypeIPv4:
		if len(data) < offset+6 {
			return nil, netip.AddrPort{}, "", fmt.Errorf("invalid ipv4 address in trojan udp frame")
		}
		ip := netip.AddrFrom4([4]byte(data[offset : offset+4]))
		offset += 4
		port := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2
		addr = netip.AddrPortFrom(ip, port)

	case AddressTypeIPv6:
		if len(data) < offset+18 {
			return nil, netip.AddrPort{}, "", fmt.Errorf("invalid ipv6 address in trojan udp frame")
		}
		ip := netip.AddrFrom16([16]byte(data[offset : offset+16]))
		offset += 16
		port := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2
		addr = netip.AddrPortFrom(ip, port)

	case AddressTypeDomain:
		if len(data) < offset+1 {
			return nil, netip.AddrPort{}, "", fmt.Errorf("invalid domain address in trojan udp frame")
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return nil, netip.AddrPort{}, "", fmt.Errorf("invalid domain address in trojan udp frame")
		}
		domain = string(data[offset : offset+domainLen])
		offset += domainLen
		port := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2
		// Return domain separately, addr is empty for domain type
		addr = netip.AddrPortFrom(netip.Addr{}, port)

	default:
		return nil, netip.AddrPort{}, "", fmt.Errorf("unknown address type: %d", atyp)
	}

	// Skip length (2 bytes) and CRLF (2 bytes)
	if len(data) < offset+4 {
		return nil, netip.AddrPort{}, "", fmt.Errorf("trojan udp frame missing length/crlf")
	}
	offset += 4

	if offset >= len(data) {
		return nil, netip.AddrPort{}, "", fmt.Errorf("invalid trojan udp frame: no payload")
	}

	// Return a copy of the payload
	payload := data[offset:]
	result := make([]byte, len(payload))
	copy(result, payload)
	return result, addr, domain, nil
}
