package ewp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

const (
	AddressTypeIPv4   byte = 0x01
	AddressTypeDomain byte = 0x02
	AddressTypeIPv6   byte = 0x03
)

type Address struct {
	Type byte
	Host string
	Port uint16
}

func ParseAddress(addr string) (Address, error) {
	// 预处理：检测未包裹方括号的 IPv6 地址
	// 例如 "2001:b28:f23f:f005::a:443" -> "[2001:b28:f23f:f005::a]:443"
	addr = normalizeIPv6Address(addr)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return Address{}, fmt.Errorf("invalid address format: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return Address{}, errors.New("invalid port")
	}

	a := Address{
		Host: host,
		Port: uint16(port),
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			a.Type = AddressTypeIPv4
		} else {
			a.Type = AddressTypeIPv6
		}
	} else {
		a.Type = AddressTypeDomain
	}

	return a, nil
}

// normalizeIPv6Address 规范化 IPv6 地址格式
// 将 "2001:db8::1:443" 转换为 "[2001:db8::1]:443"
func normalizeIPv6Address(addr string) string {
	// 已经是标准格式 [ipv6]:port
	if len(addr) > 0 && addr[0] == '[' {
		return addr
	}

	// 统计冒号数量，IPv6 地址至少有 2 个冒号
	colonCount := 0
	lastColonIdx := -1
	for i, c := range addr {
		if c == ':' {
			colonCount++
			lastColonIdx = i
		}
	}

	// 如果冒号数量 >= 2，可能是 IPv6 地址
	// 检查最后一个冒号后面是否是纯数字（端口号）
	if colonCount >= 2 && lastColonIdx > 0 && lastColonIdx < len(addr)-1 {
		portPart := addr[lastColonIdx+1:]
		isPort := true
		for _, c := range portPart {
			if c < '0' || c > '9' {
				isPort = false
				break
			}
		}

		if isPort {
			// 验证前面部分是否是有效的 IPv6 地址
			hostPart := addr[:lastColonIdx]
			if ip := net.ParseIP(hostPart); ip != nil && ip.To4() == nil {
				return "[" + hostPart + "]:" + portPart
			}
		}
	}

	return addr
}

func (a Address) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

func (a Address) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)

	buf.WriteByte(a.Type)

	switch a.Type {
	case AddressTypeIPv4:
		ip := net.ParseIP(a.Host).To4()
		if ip == nil {
			return nil, errors.New("invalid IPv4 address")
		}
		buf.WriteByte(4)
		buf.Write(ip)

	case AddressTypeDomain:
		if len(a.Host) > 255 {
			return nil, errors.New("domain name too long")
		}
		buf.WriteByte(byte(len(a.Host)))
		buf.WriteString(a.Host)

	case AddressTypeIPv6:
		ip := net.ParseIP(a.Host).To16()
		if ip == nil {
			return nil, errors.New("invalid IPv6 address")
		}
		buf.WriteByte(16)
		buf.Write(ip)

	default:
		return nil, errors.New("unknown address type")
	}

	binary.Write(buf, binary.BigEndian, a.Port)

	return buf.Bytes(), nil
}

func DecodeAddress(data []byte) (Address, int, error) {
	if len(data) < 1 {
		return Address{}, 0, errors.New("empty address data")
	}

	addr := Address{Type: data[0]}
	offset := 1

	if len(data) < offset+1 {
		return Address{}, 0, errors.New("truncated address length")
	}

	addrLen := int(data[offset])
	offset++

	switch addr.Type {
	case AddressTypeIPv4:
		if addrLen != 4 {
			return Address{}, 0, errors.New("invalid IPv4 length")
		}
		if len(data) < offset+4+2 {
			return Address{}, 0, errors.New("truncated IPv4 address")
		}
		ip := net.IP(data[offset : offset+4])
		addr.Host = ip.String()
		offset += 4

	case AddressTypeDomain:
		if len(data) < offset+addrLen+2 {
			return Address{}, 0, errors.New("truncated domain address")
		}
		addr.Host = string(data[offset : offset+addrLen])
		offset += addrLen

	case AddressTypeIPv6:
		if addrLen != 16 {
			return Address{}, 0, errors.New("invalid IPv6 length")
		}
		if len(data) < offset+16+2 {
			return Address{}, 0, errors.New("truncated IPv6 address")
		}
		ip := net.IP(data[offset : offset+16])
		addr.Host = ip.String()
		offset += 16

	default:
		return Address{}, 0, errors.New("unknown address type")
	}

	if len(data) < offset+2 {
		return Address{}, 0, errors.New("truncated port")
	}

	addr.Port = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	return addr, offset, nil
}
