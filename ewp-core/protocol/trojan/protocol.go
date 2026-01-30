package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
)

const (
	KeyLength = 56

	CommandTCP byte = 0x01
	CommandUDP byte = 0x03
	CommandMux byte = 0x7f  // Mux 多路复用命令

	AddressTypeIPv4   byte = 0x01
	AddressTypeIPv6   byte = 0x04
	AddressTypeDomain byte = 0x03

	// MaxSocksaddrLength 是 SOCKS 地址的最大长度 (1 + 1 + 255 + 2)
	MaxSocksaddrLength = 259
)

var CRLF = []byte{'\r', '\n'}

type Address struct {
	Type byte
	Host string
	Port uint16
}

func (a *Address) String() string {
	if a.Type == AddressTypeIPv6 {
		return fmt.Sprintf("[%s]:%d", a.Host, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

func (a *Address) Encode() ([]byte, error) {
	var buf []byte

	switch a.Type {
	case AddressTypeIPv4:
		ip := net.ParseIP(a.Host)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %s", a.Host)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("not an IPv4 address: %s", a.Host)
		}
		buf = append(buf, AddressTypeIPv4)
		buf = append(buf, ip4...)

	case AddressTypeIPv6:
		ip := net.ParseIP(a.Host)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", a.Host)
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("not an IPv6 address: %s", a.Host)
		}
		buf = append(buf, AddressTypeIPv6)
		buf = append(buf, ip16...)

	case AddressTypeDomain:
		if len(a.Host) > 255 {
			return nil, fmt.Errorf("domain name too long: %d bytes", len(a.Host))
		}
		buf = append(buf, AddressTypeDomain)
		buf = append(buf, byte(len(a.Host)))
		buf = append(buf, []byte(a.Host)...)

	default:
		return nil, fmt.Errorf("unknown address type: %d", a.Type)
	}

	buf = append(buf, byte(a.Port>>8), byte(a.Port))
	return buf, nil
}

func DecodeAddress(r io.Reader) (*Address, error) {
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		return nil, fmt.Errorf("read address type: %w", err)
	}

	addr := &Address{Type: typeBuf[0]}

	switch addr.Type {
	case AddressTypeIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return nil, fmt.Errorf("read IPv4 address: %w", err)
		}
		addr.Host = net.IP(ipBuf).String()

	case AddressTypeIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(r, ipBuf); err != nil {
			return nil, fmt.Errorf("read IPv6 address: %w", err)
		}
		addr.Host = net.IP(ipBuf).String()

	case AddressTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, fmt.Errorf("read domain length: %w", err)
		}
		domainLen := lenBuf[0]
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return nil, fmt.Errorf("read domain name: %w", err)
		}
		addr.Host = string(domainBuf)

	default:
		return nil, fmt.Errorf("unknown address type: %d", addr.Type)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}
	addr.Port = uint16(portBuf[0])<<8 | uint16(portBuf[1])

	return addr, nil
}

func ParseAddress(target string) (*Address, error) {
	// 规范化 IPv6 地址格式
	// 将 "2001:db8::1:443" 转换为 "[2001:db8::1]:443"
	target = normalizeIPv6Address(target)

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}

	addr := &Address{Port: uint16(port)}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			addr.Type = AddressTypeIPv4
			addr.Host = ip.To4().String()
		} else {
			addr.Type = AddressTypeIPv6
			addr.Host = ip.To16().String()
		}
	} else {
		addr.Type = AddressTypeDomain
		addr.Host = host
	}

	return addr, nil
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

func GenerateKey(password string) [KeyLength]byte {
	var key [KeyLength]byte
	hash := sha256.New224()
	hash.Write([]byte(password))
	hex.Encode(key[:], hash.Sum(nil))
	return key
}

func WriteHandshake(w io.Writer, key [KeyLength]byte, command byte, addr *Address, payload []byte) error {
	if _, err := w.Write(key[:]); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	if _, err := w.Write(CRLF); err != nil {
		return fmt.Errorf("write CRLF: %w", err)
	}

	if _, err := w.Write([]byte{command}); err != nil {
		return fmt.Errorf("write command: %w", err)
	}

	addrBytes, err := addr.Encode()
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	if _, err := w.Write(addrBytes); err != nil {
		return fmt.Errorf("write address: %w", err)
	}

	if _, err := w.Write(CRLF); err != nil {
		return fmt.Errorf("write CRLF: %w", err)
	}

	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	return nil
}

func ReadHandshake(r io.Reader, validKeys map[[KeyLength]byte]string) (string, byte, *Address, error) {
	keyBuf := make([]byte, KeyLength)
	if _, err := io.ReadFull(r, keyBuf); err != nil {
		return "", 0, nil, fmt.Errorf("read key: %w", err)
	}

	var key [KeyLength]byte
	copy(key[:], keyBuf)

	password, ok := validKeys[key]
	if !ok {
		return "", 0, nil, fmt.Errorf("invalid key")
	}

	crlfBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, crlfBuf); err != nil {
		return "", 0, nil, fmt.Errorf("read CRLF: %w", err)
	}

	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, cmdBuf); err != nil {
		return "", 0, nil, fmt.Errorf("read command: %w", err)
	}
	command := cmdBuf[0]

	addr, err := DecodeAddress(r)
	if err != nil {
		return "", 0, nil, fmt.Errorf("decode address: %w", err)
	}

	if _, err := io.ReadFull(r, crlfBuf); err != nil {
		return "", 0, nil, fmt.Errorf("read CRLF: %w", err)
	}

	return password, command, addr, nil
}
