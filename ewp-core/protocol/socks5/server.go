package socks5

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"time"

	"ewp-core/log"
)

const (
	Version5 = 0x05

	AuthMethodNone     = 0x00
	AuthMethodPassword = 0x02
	AuthMethodNoAccept = 0xFF

	CommandConnect      = 0x01
	CommandBind         = 0x02
	CommandUDPAssociate = 0x03

	AddressTypeIPv4   = 0x01
	AddressTypeDomain = 0x03
	AddressTypeIPv6   = 0x04

	ReplySuccess              = 0x00
	ReplyGeneralFailure       = 0x01
	ReplyConnectionNotAllowed = 0x02
	ReplyNetworkUnreachable   = 0x03
	ReplyHostUnreachable      = 0x04
	ReplyConnectionRefused    = 0x05
	ReplyTTLExpired           = 0x06
	ReplyCommandNotSupported  = 0x07
	ReplyAddressNotSupported  = 0x08
)

type Request struct {
	Version     byte
	Command     byte
	AddressType byte
	Address     string
	Port        int
	Target      string
}

func HandleConnection(conn net.Conn, reader *bufio.Reader, onConnect func(net.Conn, *Request, []byte) error, onUDPAssociate func(net.Conn, string) error) error {
	clientAddr := conn.RemoteAddr().String()

	if err := handshake(reader, conn); err != nil {
		log.V("[SOCKS] %s handshake failed: %v", clientAddr, err)
		return err
	}

	req, err := readRequest(reader)
	if err != nil {
		log.V("[SOCKS] %s read request failed: %v", clientAddr, err)
		return err
	}

	switch req.Command {
	case CommandConnect:
		log.V("[SOCKS%d] %s -> %s", req.Version, clientAddr, req.Target)
		initialData := tryReadInitialData(conn)
		return onConnect(conn, req, initialData)

	case CommandUDPAssociate:
		return onUDPAssociate(conn, clientAddr)

	default:
		sendReply(conn, ReplyCommandNotSupported, "0.0.0.0:0")
		return fmt.Errorf("unsupported command: 0x%02x", req.Command)
	}
}

func handshake(reader *bufio.Reader, conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}

	version := buf[0]
	nmethods := buf[1]

	if version != Version5 && version != 0x04 {
		return fmt.Errorf("invalid version: 0x%02x", version)
	}

	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}

	if _, err := conn.Write([]byte{Version5, AuthMethodNone}); err != nil {
		return err
	}

	return nil
}

func readRequest(reader *bufio.Reader) (*Request, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}

	if buf[0] != Version5 && buf[0] != 0x04 {
		return nil, fmt.Errorf("invalid version: 0x%02x", buf[0])
	}

	req := &Request{
		Version:     buf[0],
		Command:     buf[1],
		AddressType: buf[3],
	}

	var host string
	switch req.AddressType {
	case AddressTypeIPv4:
		buf = make([]byte, 4)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		host = net.IP(buf).String()

	case AddressTypeDomain:
		buf = make([]byte, 1)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		domainLen := buf[0]
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(reader, domainBuf); err != nil {
			return nil, err
		}
		host = string(domainBuf)

	case AddressTypeIPv6:
		buf = make([]byte, 16)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		host = net.IP(buf).String()

	default:
		return nil, fmt.Errorf("unsupported address type: 0x%02x", req.AddressType)
	}

	buf = make([]byte, 2)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}
	port := int(buf[0])<<8 | int(buf[1])

	req.Address = host
	req.Port = port

	if req.AddressType == AddressTypeIPv6 {
		req.Target = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		req.Target = fmt.Sprintf("%s:%d", host, port)
	}

	return req, nil
}

func tryReadInitialData(conn net.Conn) []byte {
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 32*1024)
	n, _ := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if n > 0 {
		return buf[:n]
	}
	return nil
}

func sendReply(conn net.Conn, reply byte, bindAddr string) error {
	resp := []byte{Version5, reply, 0x00, AddressTypeIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(resp)
	return err
}

func SendSuccessReply(conn net.Conn) error {
	return sendReply(conn, ReplySuccess, "0.0.0.0:0")
}

func SendErrorReply(conn net.Conn) error {
	return sendReply(conn, ReplyHostUnreachable, "0.0.0.0:0")
}
