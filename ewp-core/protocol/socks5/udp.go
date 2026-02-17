package socks5

import (
	"fmt"
	"net"
	"sync"
	"time"

	"ewp-core/log"
)

var udpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65536)
	},
}

func HandleUDPAssociate(tcpConn net.Conn, clientAddr string, dnsHandler func([]byte) ([]byte, error), udpHandler func(target string, data []byte) ([]byte, error)) error {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		log.Printf("[UDP] %s resolve address failed: %v", clientAddr, err)
		SendErrorReply(tcpConn)
		return err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("[UDP] %s listen failed: %v", clientAddr, err)
		SendErrorReply(tcpConn)
		return err
	}

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	port := localAddr.Port

	log.Printf("[UDP] %s UDP ASSOCIATE listening on port: %d", clientAddr, port)

	response := []byte{Version5, ReplySuccess, 0x00, AddressTypeIPv4}
	response = append(response, 127, 0, 0, 1)
	response = append(response, byte(port>>8), byte(port&0xff))

	if _, err := tcpConn.Write(response); err != nil {
		udpConn.Close()
		return err
	}

	stopChan := make(chan struct{})
	go handleUDPRelay(udpConn, clientAddr, stopChan, dnsHandler, udpHandler)

	buf := make([]byte, 1)
	tcpConn.Read(buf)

	close(stopChan)
	udpConn.Close()
	log.Printf("[UDP] %s UDP ASSOCIATE connection closed", clientAddr)
	return nil
}

func handleUDPRelay(udpConn *net.UDPConn, clientAddr string, stopChan chan struct{}, dnsHandler func([]byte) ([]byte, error), udpHandler func(target string, data []byte) ([]byte, error)) {
	buf := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(buf)

	for {
		select {
		case <-stopChan:
			return
		default:
		}

		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		if n < 10 {
			continue
		}

		data := buf[:n]

		if data[2] != 0x00 {
			continue
		}

		atyp := data[3]
		var headerLen int
		var dstHost string
		var dstPort int

		switch atyp {
		case AddressTypeIPv4:
			if n < 10 {
				continue
			}
			dstHost = net.IP(data[4:8]).String()
			dstPort = int(data[8])<<8 | int(data[9])
			headerLen = 10

		case AddressTypeDomain:
			if n < 5 {
				continue
			}
			domainLen := int(data[4])
			if n < 7+domainLen {
				continue
			}
			dstHost = string(data[5 : 5+domainLen])
			dstPort = int(data[5+domainLen])<<8 | int(data[6+domainLen])
			headerLen = 7 + domainLen

		case AddressTypeIPv6:
			if n < 22 {
				continue
			}
			dstHost = net.IP(data[4:20]).String()
			dstPort = int(data[20])<<8 | int(data[21])
			headerLen = 22

		default:
			continue
		}

		udpData := data[headerLen:]
		target := fmt.Sprintf("%s:%d", dstHost, dstPort)

		if dstPort == 53 && dnsHandler != nil {
			log.V("[UDP-DNS] %s -> %s (DoH query)", clientAddr, target)
			go handleDNSQuery(udpConn, addr, udpData, data[:headerLen], dnsHandler)
		} else if udpHandler != nil {
			// Handle non-DNS UDP (e.g., WebRTC STUN/TURN)
			if dstPort == 3478 || dstPort == 19302 {
				log.Printf("[UDP-STUN] %s -> %s (WebRTC STUN tunneled)", clientAddr, target)
			} else {
				log.V("[UDP] %s -> %s (tunneled)", clientAddr, target)
			}
			go handleGenericUDP(udpConn, addr, udpData, data[:headerLen], target, udpHandler)
		} else {
			log.V("[UDP] %s -> %s (non-DNS UDP not supported)", clientAddr, target)
		}
	}
}

func handleDNSQuery(udpConn *net.UDPConn, clientAddr *net.UDPAddr, dnsQuery []byte, socks5Header []byte, dnsHandler func([]byte) ([]byte, error)) {
	dnsResponse, err := dnsHandler(dnsQuery)
	if err != nil {
		log.Printf("[UDP-DNS] DoH query failed: %v", err)
		return
	}

	response := make([]byte, 0, len(socks5Header)+len(dnsResponse))
	response = append(response, socks5Header...)
	response = append(response, dnsResponse...)

	_, err = udpConn.WriteToUDP(response, clientAddr)
	if err != nil {
		log.Printf("[UDP-DNS] send response failed: %v", err)
		return
	}

	log.V("[UDP-DNS] DoH query successful, response %d bytes", len(dnsResponse))
}

func handleGenericUDP(udpConn *net.UDPConn, clientAddr *net.UDPAddr, udpData []byte, socks5Header []byte, target string, udpHandler func(target string, data []byte) ([]byte, error)) {
	response, err := udpHandler(target, udpData)
	if err != nil {
		log.V("[UDP] Generic UDP query failed for %s: %v", target, err)
		return
	}

	if len(response) == 0 {
		return
	}

	fullResponse := make([]byte, 0, len(socks5Header)+len(response))
	fullResponse = append(fullResponse, socks5Header...)
	fullResponse = append(fullResponse, response...)

	_, err = udpConn.WriteToUDP(fullResponse, clientAddr)
	if err != nil {
		log.V("[UDP] Send response failed for %s: %v", target, err)
		return
	}

	log.V("[UDP] Query successful for %s, response %d bytes", target, len(response))
}
