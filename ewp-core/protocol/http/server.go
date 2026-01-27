package http

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"

	"ewp-core/log"
)

type Request struct {
	Method      string
	URL         string
	Version     string
	Headers     map[string]string
	HeaderLines []string
	Target      string
	Path        string
	IsConnect   bool
}

func HandleConnection(conn net.Conn, reader *bufio.Reader, onConnect func(net.Conn, string) error, onProxy func(net.Conn, string, string) error) error {
	clientAddr := conn.RemoteAddr().String()

	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return fmt.Errorf("invalid HTTP request line")
	}

	req := &Request{
		Method:  parts[0],
		URL:     parts[1],
		Version: parts[2],
		Headers: make(map[string]string),
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		req.HeaderLines = append(req.HeaderLines, line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			req.Headers[strings.ToLower(key)] = value
		}
	}

	switch req.Method {
	case "CONNECT":
		log.V("[HTTP-CONNECT] %s -> %s", clientAddr, req.URL)
		return onConnect(conn, req.URL)

	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE":
		log.V("[HTTP-%s] %s -> %s", req.Method, clientAddr, req.URL)

		var target, path string

		if strings.HasPrefix(req.URL, "http://") {
			urlWithoutScheme := strings.TrimPrefix(req.URL, "http://")
			idx := strings.Index(urlWithoutScheme, "/")
			if idx > 0 {
				target = urlWithoutScheme[:idx]
				path = urlWithoutScheme[idx:]
			} else {
				target = urlWithoutScheme
				path = "/"
			}
		} else {
			target = req.Headers["host"]
			path = req.URL
		}

		if target == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return fmt.Errorf("missing target host")
		}

		if !strings.Contains(target, ":") {
			target += ":80"
		}

		var requestBuilder strings.Builder
		requestBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", req.Method, path, req.Version))

		for _, line := range req.HeaderLines {
			key := strings.Split(line, ":")[0]
			keyLower := strings.ToLower(strings.TrimSpace(key))
			if keyLower != "proxy-connection" && keyLower != "proxy-authorization" {
				requestBuilder.WriteString(line)
				requestBuilder.WriteString("\r\n")
			}
		}
		requestBuilder.WriteString("\r\n")

		if contentLength := req.Headers["content-length"]; contentLength != "" {
			var length int
			fmt.Sscanf(contentLength, "%d", &length)
			if length > 0 && length < 10*1024*1024 {
				body := make([]byte, length)
				if _, err := io.ReadFull(reader, body); err == nil {
					requestBuilder.Write(body)
				}
			}
		}

		firstFrame := requestBuilder.String()
		return onProxy(conn, target, firstFrame)

	default:
		log.Printf("[HTTP] %s unsupported method: %s", clientAddr, req.Method)
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return fmt.Errorf("unsupported method: %s", req.Method)
	}
}

func SendConnectSuccess(conn net.Conn) error {
	_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	return err
}

func SendConnectError(conn net.Conn) error {
	_, err := conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	return err
}
