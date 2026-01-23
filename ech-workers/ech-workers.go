package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wintun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ======================== 全局参数 ========================

var (
	listenAddr string
	serverAddr string
	serverIP   string
	token      string
	dnsServer  string
	echDomain  string
	fallback   bool
	numConns   int
	protoMode  string // 传输协议模式: ws/grpc/xhttp
	xhttpMode  string // XHTTP 模式: auto/stream-one/stream-down
	enableFlow bool   // 启用 Vision 流控协议
	enablePQC  bool   // 启用后量子密钥交换 (X25519MLKEM768)
	controlAddr string
	logFilePath string
	verbose     bool   // 详细日志模式

	echListMu sync.RWMutex
	echList   []byte

	// TUN 模式参数
	tunMode    bool
	tunIP      string
	tunGateway string
	tunMask    string
	tunDNS     string
	tunMTU     int

	// TUN 设备和网络栈
	tunAdapter   *wintun.Adapter
	tunSession   wintun.Session
	tunStack     *stack.Stack
	tunEndpoint  *channel.Endpoint
	tunConnCount int64

	// 流量统计
	totalUpload   int64
	totalDownload int64
	activeConns   int64

	// 系统代理模式
	sysProxyMode bool
)

// ======================== Buffer Pool (性能优化) ========================

var (
	udpBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65536)
		},
	}
)

func init() {
	flag.StringVar(&listenAddr, "l", "127.0.0.1:30000", "代理监听地址 (支持 SOCKS5 和 HTTP)")
	flag.StringVar(&serverAddr, "f", "", "服务端地址 (支持: wss://host:port/path, grpcs://host:port, https://host:port/xhttp)")
	flag.StringVar(&serverIP, "ip", "", "指定服务端 IP（绕过 DNS，TLS SNI 仍使用原 host）")
	flag.StringVar(&token, "token", "", "身份验证令牌 (WebSocket) 或 UUID (gRPC)")
	flag.StringVar(&dnsServer, "dns", "dns.alidns.com/dns-query", "ECH 查询 DoH 服务器")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH 查询域名")
	flag.BoolVar(&fallback, "fallback", false, "禁用 ECH (普通 TLS 模式)")
	flag.IntVar(&numConns, "n", 1, "并发连接数 (默认 1)")
	flag.StringVar(&protoMode, "mode", "ws", "传输协议模式: ws (WebSocket)、grpc 或 xhttp")
	flag.StringVar(&xhttpMode, "xhttp-mode", "auto", "XHTTP 模式: auto (自动选择)、stream-one (双向流) 或 stream-down (分离上下行)")
	flag.BoolVar(&enableFlow, "flow", true, "启用 Vision 流控协议（默认启用，提供流量混淆和零拷贝优化）")
	flag.BoolVar(&enablePQC, "pqc", false, "启用后量子密钥交换 X25519MLKEM768（需要 Go 1.24+，默认使用经典 X25519）")
	flag.StringVar(&controlAddr, "control", "", "本地控制接口监听地址（仅用于 GUI 控制退出），例如 127.0.0.1:0")
	flag.StringVar(&logFilePath, "logfile", "", "将日志追加写入到文件（用于 GUI 提权启动时仍能显示日志）")
	flag.BoolVar(&verbose, "verbose", false, "详细日志模式（记录每个连接详情，高并发时会产生大量日志）")
	flag.BoolVar(&tunMode, "tun", false, "启用 TUN 模式 (全局代理)")
	flag.StringVar(&tunIP, "tun-ip", "10.0.85.2", "TUN 设备 IP 地址")
	flag.StringVar(&tunGateway, "tun-gateway", "10.0.85.1", "TUN 网关地址")
	flag.StringVar(&tunMask, "tun-mask", "255.255.255.0", "TUN 子网掩码")
	flag.StringVar(&tunDNS, "tun-dns", "1.1.1.1", "TUN DNS 服务器")
	flag.IntVar(&tunMTU, "tun-mtu", 1380, "TUN MTU（建议约 1380，用于减少隧道封装导致的分片）")
	flag.BoolVar(&sysProxyMode, "sysproxy", false, "自动设置系统代理")
}

// logV 详细日志（仅在 verbose 模式下输出）
func logV(format string, v ...interface{}) {
	if verbose {
		log.Printf(format, v...)
	}
}

func main() {
	flag.Parse()

	if logFilePath != "" {
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("[日志] 打开日志文件失败: %v", err)
		}
		// 注意：这里不 defer f.Close()，因为日志需要持续写入直到进程退出
		// 进程退出时操作系统会自动关闭文件句柄
		log.SetOutput(io.MultiWriter(os.Stdout, f))
	}

	if serverAddr == "" {
		log.Fatal("必须指定服务端地址 -f\n\n示例:\n  ./client -l 127.0.0.1:1080 -f your-worker.workers.dev:443 -token your-token\n  ./client -l 127.0.0.1:1080 -f grpc://your-server:50051 -token your-uuid -mode grpc")
	}

	// 自动检测协议模式
	if strings.HasPrefix(serverAddr, "grpc://") || strings.HasPrefix(serverAddr, "grpcs://") {
		protoMode = TransportGRPC
	}

	// 设置信号处理，确保退出时清理资源
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 清理函数
	cleanup := func() {
		log.Printf("[清理] 正在清理资源...")
		if sysProxyMode {
			disableSystemProxy()
		}
		if tunMode && tunAdapter != nil {
			cleanupTUN()
		}
		log.Printf("[清理] 资源清理完成")
	}

	quit := func() {
		cleanup()
		os.Exit(0)
	}

	// 启动信号监听协程
	go func() {
		<-sigChan
		log.Printf("[信号] 收到退出信号")
		quit()
	}()

	if controlAddr != "" {
		actualAddr, err := startControlServer(controlAddr, func() {
			log.Printf("[控制] 收到退出请求")
			quit()
		})
		if err != nil {
			log.Fatalf("[控制] 启动失败: %v", err)
		}
		log.Printf("CONTROL_ADDR=%s", actualAddr)
	}

	// 根据协议模式初始化
	useECH := !fallback
	if !fallback {
		// 获取 ECH 配置（WebSocket 和 gRPC 都可以使用）
		log.Printf("[启动] 正在获取 ECH 配置...")
		if err := prepareECH(); err != nil {
			log.Fatalf("[启动] 获取 ECH 配置失败: %v\n提示: 如需禁用 ECH，请使用 -fallback 参数", err)
		}
	} else {
		log.Printf("[启动] 已启用 Fallback 模式 (普通 TLS)")
	}

	if protoMode == TransportGRPC {
		log.Printf("[启动] 使用 gRPC 传输模式 (ECH: %v)", useECH)
	}

	// 初始化传输层
	InitTransport(protoMode, serverAddr, serverIP, token, useECH, enableFlow, xhttpMode)
	log.Printf("[启动] 传输层: %s", GetTransport().Name())

	if tunMode {
		log.Printf("[启动] 正在初始化 TUN 设备...")
		if !isAdmin() {
			log.Fatal("[错误] TUN 模式需要管理员权限，请以管理员身份运行")
		}

		// TUN 模式下忽略系统代理设置（TUN 已经捕获全部流量）
		if sysProxyMode {
			log.Printf("[提示] TUN 模式已启用，系统代理设置将被忽略（TUN 已捕获全部流量）")
		}

		if err := startTUNMode(); err != nil {
			log.Fatalf("[启动] TUN 模式初始化失败: %v", err)
		}
	} else {
		// 非 TUN 模式：启动本地代理服务器
		// 如果启用系统代理模式，自动配置
		if sysProxyMode {
			if err := enableSystemProxy(listenAddr); err != nil {
				log.Printf("[警告] 设置系统代理失败: %v", err)
			} else {
				log.Printf("[系统代理] 已启用，代理地址: %s", listenAddr)
			}
		}
		runProxyServer(listenAddr)
	}
}

func startControlServer(addr string, quit func()) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" {
		return "", fmt.Errorf("control 只能监听 127.0.0.1 或 localhost")
	}
	if host != "127.0.0.1" && host != "localhost" {
		return "", fmt.Errorf("control 只能监听 127.0.0.1 或 localhost")
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		go func() {
			time.Sleep(100 * time.Millisecond)
			quit()
		}()
	})

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(ln)
	}()

	return ln.Addr().String(), nil
}

// ======================== 工具函数 ========================

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

// ======================== ECH 支持 ========================

const typeHTTPS = 65

func prepareECH() error {
	echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
	if err != nil {
		return fmt.Errorf("DNS 查询失败: %w", err)
	}
	if echBase64 == "" {
		return errors.New("未找到 ECH 参数")
	}
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH 解码失败: %w", err)
	}
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw))
	return nil
}

func refreshECH() error {
	log.Printf("[ECH] 刷新配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置未加载")
	}
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH")
		},
		RootCAs: roots,
	}

	// 设置密钥交换算法
	if enablePQC {
		// 启用后量子密钥交换 (X25519MLKEM768 = X25519 + Kyber768)
		// Go 1.24+ 原生支持
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768, // 后量子混合模式 (X25519 + Kyber768)
			tls.X25519,         // 经典回退
			tls.CurveP256,      // 额外回退
		}
		log.Printf("[🔒 PQC] 启用后量子密钥交换 X25519MLKEM768")
	} else {
		// 默认使用经典 X25519
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519,    // 经典模式
			tls.CurveP256, // 回退
		}
	}

	return cfg, nil
}

// queryHTTPSRecord 通过 DoH 查询 HTTPS 记录
func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(domain, dohURL)
}

// queryDoH 执行 DoH 查询（用于获取 ECH 配置）
func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效的 DoH URL: %v", err)
	}

	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 DoH 响应失败: %v", err)
	}

	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("无应答记录")
	}

	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
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
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== DoH 代理支持 ========================

// queryDoHForProxy 通过 ECH 转发 DNS 查询到 Cloudflare DoH
func queryDoHForProxy(dnsQuery []byte) ([]byte, error) {
	_, port, _, err := parseServerAddr(serverAddr)
	if err != nil {
		return nil, err
	}

	// 构建 DoH URL
	dohURL := fmt.Sprintf("https://cloudflare-dns.com:%s/dns-query", port)

	echBytes, err := getECHList()
	if err != nil {
		return nil, fmt.Errorf("获取 ECH 配置失败: %w", err)
	}

	tlsCfg, err := buildTLSConfigWithECH("cloudflare-dns.com", echBytes)
	if err != nil {
		return nil, fmt.Errorf("构建 TLS 配置失败: %w", err)
	}

	// 创建 HTTP 客户端
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	// 如果指定了 IP，使用自定义 Dialer
	if serverIP != "" {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{
				Timeout: 10 * time.Second,
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(serverIP, port))
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// 发送 DoH 请求
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 响应错误: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// ======================== WebSocket 客户端 ========================



// ======================== 统一代理服务器 ========================

func runProxyServer(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[代理] 监听失败: %v", err)
	}
	defer listener.Close()

	log.Printf("[代理] 服务器启动: %s (支持 SOCKS5 和 HTTP)", addr)
	log.Printf("[代理] 后端服务器: %s", serverAddr)
	if serverIP != "" {
		log.Printf("[代理] 使用固定 IP: %s", serverIP)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[代理] 接受连接失败: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 读取第一个字节判断协议
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	firstByte := buf[0]

	// 使用 switch 判断协议类型
	switch firstByte {
	case 0x05:
		// SOCKS5 协议
		handleSOCKS5(conn, clientAddr, firstByte)
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		// HTTP 协议 (CONNECT, GET, POST, HEAD, DELETE, OPTIONS, TRACE, PUT, PATCH)
		handleHTTP(conn, clientAddr, firstByte)
	default:
		log.Printf("[代理] %s 未知协议: 0x%02x", clientAddr, firstByte)
	}
}

// ======================== SOCKS5 处理 ========================

func handleSOCKS5(conn net.Conn, clientAddr string, firstByte byte) {
	// 验证版本
	if firstByte != 0x05 {
		log.Printf("[SOCKS5] %s 版本错误: 0x%02x", clientAddr, firstByte)
		return
	}

	// 读取认证方法数量
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	nmethods := buf[0]
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// 响应无需认证
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 读取请求
	buf = make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	if buf[0] != 5 {
		return
	}

	command := buf[1]
	atyp := buf[3]

	var host string
	switch atyp {
	case 0x01: // IPv4
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()

	case 0x03: // 域名
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		domainBuf := make([]byte, buf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)

	case 0x04: // IPv6
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 读取端口
	buf = make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])

	switch command {
	case 0x01: // CONNECT
		var target string
		if atyp == 0x04 {
			target = fmt.Sprintf("[%s]:%d", host, port)
		} else {
			target = fmt.Sprintf("%s:%d", host, port)
		}

		logV("[SOCKS5] %s -> %s", clientAddr, target)

		if err := handleTunnel(conn, target, clientAddr, modeSOCKS5, ""); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[SOCKS5] %s 代理失败: %v", clientAddr, err)
			}
		}

	case 0x03: // UDP ASSOCIATE
		handleUDPAssociate(conn, clientAddr)

	default:
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
}

func handleUDPAssociate(tcpConn net.Conn, clientAddr string) {
	// 创建 UDP 监听器
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		log.Printf("[UDP] %s 解析地址失败: %v", clientAddr, err)
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("[UDP] %s 监听失败: %v", clientAddr, err)
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 获取实际监听的端口
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	port := localAddr.Port

	log.Printf("[UDP] %s UDP ASSOCIATE 监听端口: %d", clientAddr, port)

	// 发送成功响应
	response := []byte{0x05, 0x00, 0x00, 0x01}
	response = append(response, 127, 0, 0, 1) // 127.0.0.1
	response = append(response, byte(port>>8), byte(port&0xff))

	if _, err := tcpConn.Write(response); err != nil {
		udpConn.Close()
		return
	}

	// 启动 UDP 处理
	stopChan := make(chan struct{})
	go handleUDPRelay(udpConn, clientAddr, stopChan)

	// 保持 TCP 连接，直到客户端关闭
	buf := make([]byte, 1)
	tcpConn.Read(buf)

	close(stopChan)
	udpConn.Close()
	log.Printf("[UDP] %s UDP ASSOCIATE 连接关闭", clientAddr)
}

func handleUDPRelay(udpConn *net.UDPConn, clientAddr string, stopChan chan struct{}) {
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

		// 解析 SOCKS5 UDP 请求头
		if n < 10 {
			continue
		}

		// SOCKS5 UDP 请求格式:
		// +----+------+------+----------+----------+----------+
		// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
		// +----+------+------+----------+----------+----------+
		// | 2  |  1   |  1   | Variable |    2     | Variable |
		// +----+------+------+----------+----------+----------+

		data := buf[:n]

		if data[2] != 0x00 { // FRAG 必须为 0
			continue
		}

		atyp := data[3]
		var headerLen int
		var dstHost string
		var dstPort int

		switch atyp {
		case 0x01: // IPv4
			if n < 10 {
				continue
			}
			dstHost = net.IP(data[4:8]).String()
			dstPort = int(data[8])<<8 | int(data[9])
			headerLen = 10

		case 0x03: // 域名
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

		case 0x04: // IPv6
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

		// 检查是否是 DNS 查询（端口 53）
		if dstPort == 53 {
			logV("[UDP-DNS] %s -> %s (DoH 查询)", clientAddr, target)
			go handleDNSQuery(udpConn, addr, udpData, data[:headerLen])
		} else {
			logV("[UDP] %s -> %s (暂不支持非 DNS UDP)", clientAddr, target)
			// 这里可以扩展支持其他 UDP 流量
		}
	}
}

func handleDNSQuery(udpConn *net.UDPConn, clientAddr *net.UDPAddr, dnsQuery []byte, socks5Header []byte) {
	// 通过 DoH 查询（使用重命名后的函数）
	dnsResponse, err := queryDoHForProxy(dnsQuery)
	if err != nil {
		log.Printf("[UDP-DNS] DoH 查询失败: %v", err)
		return
	}

	// 构建 SOCKS5 UDP 响应
	response := make([]byte, 0, len(socks5Header)+len(dnsResponse))
	response = append(response, socks5Header...)
	response = append(response, dnsResponse...)

	// 发送响应
	_, err = udpConn.WriteToUDP(response, clientAddr)
	if err != nil {
		log.Printf("[UDP-DNS] 发送响应失败: %v", err)
		return
	}

	logV("[UDP-DNS] DoH 查询成功，响应 %d 字节", len(dnsResponse))
}

// ======================== HTTP 处理 ========================

func handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
	// 将第一个字节放回缓冲区
	reader := bufio.NewReader(io.MultiReader(
		strings.NewReader(string(firstByte)),
		conn,
	))

	// 读取 HTTP 请求行
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return
	}

	method := parts[0]
	requestURL := parts[1]
	httpVersion := parts[2]

	// 读取所有 headers
	headers := make(map[string]string)
	var headerLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		headerLines = append(headerLines, line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[strings.ToLower(key)] = value
		}
	}

	switch method {
	case "CONNECT":
		// HTTPS 隧道代理 - 需要发送 200 响应
		logV("[HTTP-CONNECT] %s -> %s", clientAddr, requestURL)
		if err := handleTunnel(conn, requestURL, clientAddr, modeHTTPConnect, ""); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTP-CONNECT] %s 代理失败: %v", clientAddr, err)
			}
		}

	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE":
		// HTTP 代理 - 直接转发，不发送 200 响应
		logV("[HTTP-%s] %s -> %s", method, clientAddr, requestURL)

		var target string
		var path string

		if strings.HasPrefix(requestURL, "http://") {
			// 解析完整 URL
			urlWithoutScheme := strings.TrimPrefix(requestURL, "http://")
			idx := strings.Index(urlWithoutScheme, "/")
			if idx > 0 {
				target = urlWithoutScheme[:idx]
				path = urlWithoutScheme[idx:]
			} else {
				target = urlWithoutScheme
				path = "/"
			}
		} else {
			// 相对路径，从 Host header 获取
			target = headers["host"]
			path = requestURL
		}

		if target == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}

		// 添加默认端口
		if !strings.Contains(target, ":") {
			target += ":80"
		}

		// 重构 HTTP 请求（去掉完整 URL，使用相对路径）
		var requestBuilder strings.Builder
		requestBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVersion))

		// 写入 headers（过滤掉 Proxy-Connection）
		for _, line := range headerLines {
			key := strings.Split(line, ":")[0]
			keyLower := strings.ToLower(strings.TrimSpace(key))
			if keyLower != "proxy-connection" && keyLower != "proxy-authorization" {
				requestBuilder.WriteString(line)
				requestBuilder.WriteString("\r\n")
			}
		}
		requestBuilder.WriteString("\r\n")

		// 如果有请求体，需要读取并附加
		if contentLength := headers["content-length"]; contentLength != "" {
			var length int
			fmt.Sscanf(contentLength, "%d", &length)
			if length > 0 && length < 10*1024*1024 { // 限制 10MB
				body := make([]byte, length)
				if _, err := io.ReadFull(reader, body); err == nil {
					requestBuilder.Write(body)
				}
			}
		}

		firstFrame := requestBuilder.String()

		// 使用 modeHTTPProxy 模式（不发送 200 响应）
		if err := handleTunnel(conn, target, clientAddr, modeHTTPProxy, firstFrame); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTP-%s] %s 代理失败: %v", method, clientAddr, err)
			}
		}

	default:
		log.Printf("[HTTP] %s 不支持的方法: %s", clientAddr, method)
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
	}
}

// ======================== 通用隧道处理 ========================

// 代理模式常量
const (
	modeSOCKS5      = 1 // SOCKS5 代理
	modeHTTPConnect = 2 // HTTP CONNECT 隧道
	modeHTTPProxy   = 3 // HTTP 普通代理（GET/POST等）
)

func handleTunnel(conn net.Conn, target, clientAddr string, mode int, firstFrame string) error {
	// 统计活跃连接
	atomic.AddInt64(&activeConns, 1)
	defer atomic.AddInt64(&activeConns, -1)

	// 使用统一的 Transport 抽象层建立隧道连接
	tunnelConn, err := DialTunnel()
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}
	defer tunnelConn.Close()

	// 启动心跳
	stopPing := tunnelConn.StartPing(30 * time.Second)
	defer close(stopPing)

	conn.SetDeadline(time.Time{})

	// 如果没有预设的 firstFrame，尝试读取第一帧数据（仅 SOCKS5）
	if firstFrame == "" && mode == modeSOCKS5 {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buffer := largeBufferPool.Get().([]byte)
		n, _ := conn.Read(buffer)
		_ = conn.SetReadDeadline(time.Time{})
		if n > 0 {
			firstFrame = string(buffer[:n])
		}
		largeBufferPool.Put(buffer)
	}

	// 发送连接请求（使用 Transport 抽象）
	if err := tunnelConn.Connect(target, []byte(firstFrame)); err != nil {
		sendErrorResponse(conn, mode)
		return err
	}

	// 发送成功响应（根据模式不同而不同）
	if err := sendSuccessResponse(conn, mode); err != nil {
		return err
	}

	logV("[代理] %s 已连接: %s", clientAddr, target)

	// 双向转发
	done := make(chan bool, 2)

	// Client -> Server (上传)
	go func() {
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if err := tunnelConn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
			atomic.AddInt64(&totalUpload, int64(n))
		}
	}()

	// Server -> Client (下载) - 零拷贝优化
	go func() {
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		
		for {
			n, err := tunnelConn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if _, err := conn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
			atomic.AddInt64(&totalDownload, int64(n))
		}
	}()

	<-done
	logV("[代理] %s 已断开: %s", clientAddr, target)
	return nil
}

// ======================== 响应辅助函数 ========================

func sendErrorResponse(conn net.Conn, mode int) {
	switch mode {
	case modeSOCKS5:
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case modeHTTPConnect, modeHTTPProxy:
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

func sendSuccessResponse(conn net.Conn, mode int) error {
	switch mode {
	case modeSOCKS5:
		// SOCKS5 成功响应
		_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return err
	case modeHTTPConnect:
		// HTTP CONNECT 需要发送 200 响应
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		return err
	case modeHTTPProxy:
		// HTTP GET/POST 等不需要发送响应，直接转发目标服务器的响应
		return nil
	}
	return nil
}

// ======================== 系统代理设置 ========================

const (
	internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
)

// enableSystemProxy 启用 Windows 系统代理
func enableSystemProxy(proxyAddr string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开注册表失败: %w", err)
	}
	defer key.Close()

	// 启用代理
	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return fmt.Errorf("设置 ProxyEnable 失败: %w", err)
	}

	// 设置代理服务器地址
	if err := key.SetStringValue("ProxyServer", proxyAddr); err != nil {
		return fmt.Errorf("设置 ProxyServer 失败: %w", err)
	}

	// 设置不使用代理的地址（本地地址）
	bypass := "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"
	if err := key.SetStringValue("ProxyOverride", bypass); err != nil {
		return fmt.Errorf("设置 ProxyOverride 失败: %w", err)
	}

	// 通知系统代理设置已更改
	notifyProxyChange()

	return nil
}

// disableSystemProxy 禁用 Windows 系统代理
func disableSystemProxy() {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		log.Printf("[系统代理] 关闭时打开注册表失败: %v", err)
		return
	}
	defer key.Close()

	// 禁用代理
	if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
		log.Printf("[系统代理] 禁用失败: %v", err)
		return
	}

	// 通知系统代理设置已更改
	notifyProxyChange()

	log.Printf("[系统代理] 已禁用")
}

// notifyProxyChange 通知系统代理设置已更改
func notifyProxyChange() {
	// 调用 InternetSetOption 通知系统刷新代理设置
	// 这需要调用 wininet.dll
	wininet := windows.NewLazySystemDLL("wininet.dll")
	internetSetOption := wininet.NewProc("InternetSetOptionW")

	const (
		INTERNET_OPTION_SETTINGS_CHANGED = 39
		INTERNET_OPTION_REFRESH          = 37
	)

	internetSetOption.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	internetSetOption.Call(0, INTERNET_OPTION_REFRESH, 0, 0)
}

// ======================== TUN 模式实现 ========================

// cleanupTUN 清理 TUN 资源
func cleanupTUN() {
	log.Printf("[TUN] 正在清理 TUN 资源...")

	// 删除添加的路由
	cmd := exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", tunGateway)
	cmd.Run()

	// 关闭会话
	if tunSession != (wintun.Session{}) {
		tunSession.End()
		log.Printf("[TUN] 会话已关闭")
	}

	// 关闭适配器
	if tunAdapter != nil {
		tunAdapter.Close()
		tunAdapter = nil
		log.Printf("[TUN] 适配器已关闭")
	}

	log.Printf("[TUN] TUN 资源清理完成")
}

func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

func startTUNMode() error {
	var err error

	tunAdapter, err = wintun.CreateAdapter("ECH-TUN", "WireGuard", nil)
	if err != nil {
		return fmt.Errorf("创建 TUN 适配器失败: %w", err)
	}
	log.Printf("[TUN] 适配器已创建")

	tunSession, err = tunAdapter.StartSession(0x800000)
	if err != nil {
		return fmt.Errorf("启动会话失败: %w", err)
	}
	log.Printf("[TUN] 会话已启动")

	if err := configureTUNInterface(); err != nil {
		return fmt.Errorf("配置网络接口失败: %w", err)
	}

	if err := initNetworkStack(); err != nil {
		return fmt.Errorf("初始化网络栈失败: %w", err)
	}

	if err := configureRouting(); err != nil {
		return fmt.Errorf("配置路由失败: %w", err)
	}

	go tunReadLoop()
	go tunWriteLoop()

	log.Printf("[TUN] TUN 模式已启动，IP: %s", tunIP)

	select {}
}

func configureTUNInterface() error {
	// 使用接口名称 "ECH-TUN" 而不是 LUID
	interfaceName := "ECH-TUN"

	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", interfaceName),
		"source=static",
		fmt.Sprintf("addr=%s", tunIP),
		fmt.Sprintf("mask=%s", tunMask),
		fmt.Sprintf("gateway=%s", tunGateway))

	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[TUN] netsh 配置失败: %s (需要管理员权限)", output)
		return fmt.Errorf("配置网络接口失败，请确保以管理员身份运行: %w", err)
	}

	log.Printf("[TUN] 接口配置: IP=%s, Gateway=%s, Mask=%s", tunIP, tunGateway, tunMask)

	cmd = exec.Command("netsh", "interface", "ip", "set", "dns",
		fmt.Sprintf("name=%s", interfaceName),
		"source=static",
		fmt.Sprintf("addr=%s", tunDNS))
	cmd.Run()

	log.Printf("[TUN] DNS 设置: %s", tunDNS)

	// 尝试设置接口 MTU（失败不致命）
	if tunMTU > 0 {
		cmd = exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
			interfaceName,
			fmt.Sprintf("mtu=%d", tunMTU),
			"store=persistent")
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[TUN] 设置 IPv4 MTU 失败: %v (%s)", err, output)
		} else {
			log.Printf("[TUN] MTU 已设置: %d", tunMTU)
		}
		cmd = exec.Command("netsh", "interface", "ipv6", "set", "subinterface",
			interfaceName,
			fmt.Sprintf("mtu=%d", tunMTU),
			"store=persistent")
		_, _ = cmd.CombinedOutput()
	}

	return nil
}

func initNetworkStack() error {
	mtu := tunMTU
	if mtu <= 0 {
		mtu = 1500
	}
	tunEndpoint = channel.New(512, uint32(mtu), "")

	tunStack = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	if err := tunStack.CreateNIC(1, tunEndpoint); err != nil {
		return fmt.Errorf("创建 NIC 失败: %v", err)
	}

	gatewayIP := parseIPv4(tunGateway)
	tunStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{gatewayIP[0], gatewayIP[1], gatewayIP[2], gatewayIP[3]}),
			PrefixLen: 24,
		},
	}, stack.AddressProperties{})

	subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	tunStack.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})

	tunStack.SetPromiscuousMode(1, true)
	tunStack.SetSpoofing(1, true)

	go handleTCPConnections()
	go handleUDPPackets()

	log.Printf("[TUN] 网络栈已初始化")
	return nil
}

func configureRouting() error {
	// 获取接口索引用于 route 命令
	iface, err := net.InterfaceByName("ECH-TUN")
	if err != nil {
		log.Printf("[TUN] 获取接口索引失败: %v，尝试使用网关直接添加路由", err)
		// 备用方案：不指定接口，让系统自动选择
		cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", tunGateway, "metric", "1")
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[TUN] 路由设置警告: %s (可能已存在)", output)
		}
	} else {
		cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", tunGateway,
			"metric", "1", "if", strconv.Itoa(iface.Index))
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[TUN] 路由设置警告: %s (可能已存在)", output)
		}
	}

	log.Printf("[TUN] 路由表已配置 (全局代理)")
	return nil
}

func tunReadLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUN] 读取协程崩溃: %v", r)
		}
	}()

	mtu := tunMTU
	if mtu <= 0 {
		mtu = 1500
	}
	packetBuf := make([]byte, mtu)

	for {
		packet, err := tunSession.ReceivePacket()
		if err != nil {
			log.Printf("[TUN] 读取数据包失败: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n := copy(packetBuf, packet)

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packetBuf[:n]),
		})

		tunEndpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
}

func tunWriteLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUN] 写入协程崩溃: %v", r)
		}
	}()

	for {
		pkt := tunEndpoint.ReadContext(context.Background())
		if pkt == nil {
			continue
		}

		data := pkt.ToView().AsSlice()

		packet, err := tunSession.AllocateSendPacket(len(data))
		if err != nil {
			pkt.DecRef()
			log.Printf("[TUN] 分配发送缓冲区失败: %v", err)
			continue
		}

		copy(packet, data)
		tunSession.SendPacket(packet)
		pkt.DecRef()
	}
}

func handleTCPConnections() {
	var wq waiter.Queue
	ep, err := tunStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		log.Fatalf("[TCP] 创建端点失败: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{
		Port: 0,
	}); err != nil {
		log.Fatalf("[TCP] 绑定失败: %v", err)
	}

	if err := ep.Listen(128); err != nil {
		log.Fatalf("[TCP] 监听失败: %v", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	for {
		n, wq, err := ep.Accept(nil)
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}
			log.Printf("[TCP] 接受连接失败: %v", err)
			continue
		}

		go handleTCPConnection(n, wq)
	}
}

func handleTCPConnection(ep tcpip.Endpoint, wq *waiter.Queue) {
	defer ep.Close()

	atomic.AddInt64(&tunConnCount, 1)
	connID := atomic.LoadInt64(&tunConnCount)

	remoteAddr, _ := ep.GetRemoteAddress()
	localAddr, _ := ep.GetLocalAddress()

	target := fmt.Sprintf("%s:%d", net.IP(remoteAddr.Addr.AsSlice()).String(), remoteAddr.Port)
	log.Printf("[TCP:%d] 新连接: %s:%d -> %s", connID,
		net.IP(localAddr.Addr.AsSlice()).String(), localAddr.Port, target)

	conn := gonet.NewTCPConn(wq, ep)
	defer conn.Close()

	// 使用统一的 Transport 抽象层
	tunnelConn, err := DialTunnel()
	if err != nil {
		log.Printf("[TCP:%d] 隧道连接失败: %v", connID, err)
		return
	}
	defer tunnelConn.Close()

	// 启动心跳
	stopPing := tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	// 发送连接请求
	if err := tunnelConn.Connect(target, nil); err != nil {
		log.Printf("[TCP:%d] CONNECT 失败: %v", connID, err)
		return
	}

	log.Printf("[TCP:%d] 已连接: %s", connID, target)

	done := make(chan bool, 2)

	// Client -> Server
	go func() {
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if err := tunnelConn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
		}
	}()

	// Server -> Client
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := tunnelConn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if _, err := conn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
		}
	}()

	<-done
	log.Printf("[TCP:%d] 已断开: %s", connID, target)
}

// 全局 UDP 处理器
var tunUDPHandler *UDPConnectionHandler

func handleUDPPackets() {
	// 启动 IPv4 和 IPv6 UDP 处理
	go handleUDPPacketsV4()
	go handleUDPPacketsV6()

	// 阻塞等待
	select {}
}

// writeUDPResponse 将 UDP 响应写回 TUN (支持 IPv4/IPv6)
func writeUDPResponse(src, dst *net.UDPAddr, payload []byte) {
	// 判断是 IPv4 还是 IPv6
	isIPv6 := src.IP.To4() == nil

	var srcIP, dstIP []byte
	var networkProto tcpip.NetworkProtocolNumber

	if isIPv6 {
		srcIP = src.IP.To16()
		dstIP = dst.IP.To16()
		networkProto = ipv6.ProtocolNumber
	} else {
		srcIP = src.IP.To4()
		dstIP = dst.IP.To4()
		networkProto = ipv4.ProtocolNumber
	}

	srcAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(srcIP),
		Port: uint16(src.Port),
	}
	dstAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(dstIP),
		Port: uint16(dst.Port),
	}

	// 创建新的 UDP endpoint 发送响应
	var respWq waiter.Queue
	respEp, err := tunStack.NewEndpoint(udp.ProtocolNumber, networkProto, &respWq)
	if err != nil {
		logV("[UDP] 创建响应端点失败: %v", err)
		return
	}
	defer respEp.Close()

	// 绑定到源地址（模拟远程服务器）
	if err := respEp.Bind(srcAddr); err != nil {
		logV("[UDP] 绑定源地址失败: %v", err)
		return
	}

	// 发送响应到客户端
	var buf bytes.Buffer
	buf.Write(payload)
	_, tcpipErr := respEp.Write(&buf, tcpip.WriteOptions{
		To: &dstAddr,
	})
	if tcpipErr != nil {
		logV("[UDP] 发送响应失败: %v", tcpipErr)
	}
}

func handleUDPPacketsV4() {
	var wq waiter.Queue
	ep, err := tunStack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		log.Fatalf("[UDP4] 创建端点失败: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{}); err != nil {
		log.Fatalf("[UDP4] 绑定失败: %v", err)
	}

	// 初始化 UDP 处理器（使用当前传输层）
	transport := GetTransport()
	if transport != nil && tunUDPHandler == nil {
		tunUDPHandler = NewUDPConnectionHandler(transport, writeUDPResponse)
		log.Printf("[UDP] Full-Cone NAT 处理器已启动 (IPv4/IPv6)")
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	handleUDPLoop(ep, notifyCh, false)
}

func handleUDPPacketsV6() {
	var wq waiter.Queue
	ep, err := tunStack.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if err != nil {
		log.Printf("[UDP6] 创建端点失败: %v (IPv6 可能未启用)", err)
		return
	}

	if err := ep.Bind(tcpip.FullAddress{}); err != nil {
		log.Printf("[UDP6] 绑定失败: %v", err)
		return
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	handleUDPLoop(ep, notifyCh, true)
}

func handleUDPLoop(ep tcpip.Endpoint, notifyCh chan struct{}, isIPv6 bool) {
	protoName := "UDP4"
	if isIPv6 {
		protoName = "UDP6"
	}

	for {
		var buf bytes.Buffer
		res, err := ep.Read(&buf, tcpip.ReadOptions{
			NeedRemoteAddr: true,
		})
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}
			continue
		}
		addr := res.RemoteAddr

		data := buf.Bytes()
		if len(data) > 0 {
			// DNS 查询优先使用 DoH（更快）
			if addr.Port == 53 {
				go handleTUNDNSQuery(ep, &addr, data)
				continue
			}

			// 其他 UDP 流量通过代理
			// 注意：gvisor 旧版本不支持 LocalAddr，使用 TUN 虚拟 IP 作为源地址
			if tunUDPHandler != nil {
				var srcIP net.IP
				if isIPv6 {
					srcIP = net.ParseIP("fd00::1") // TUN IPv6 地址
				} else {
					srcIP = net.ParseIP("10.0.0.1") // TUN IPv4 地址
				}
				srcAddr := &net.UDPAddr{
					IP:   srcIP,
					Port: 12345, // 使用固定端口，Full-Cone NAT 会基于目标地址映射
				}
				dstAddr := &net.UDPAddr{
					IP:   net.IP(addr.Addr.AsSlice()),
					Port: int(addr.Port),
				}

				if err := tunUDPHandler.HandlePacket(srcAddr, dstAddr, data); err != nil {
					logV("[%s] 处理失败: %v", protoName, err)
				}
			} else {
				target := fmt.Sprintf("%s:%d", net.IP(addr.Addr.AsSlice()).String(), addr.Port)
				logV("[%s] 收到数据包 -> %s (UDP 处理器未初始化)", protoName, target)
			}
		}
	}
}

func handleTUNDNSQuery(ep tcpip.Endpoint, clientAddr *tcpip.FullAddress, query []byte) {
	dnsResponse, err := queryDoHForProxy(query)
	if err != nil {
		log.Printf("[DNS] DoH 查询失败: %v", err)
		return
	}

	var buf bytes.Buffer
	buf.Write(dnsResponse)
	_, tcpipErr := ep.Write(&buf, tcpip.WriteOptions{
		To: clientAddr,
	})
	if tcpipErr != nil {
		log.Printf("[DNS] 发送响应失败: %v", tcpipErr)
		return
	}

	log.Printf("[DNS] 查询成功: %d 字节", len(dnsResponse))
}

func parseIPv4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPv4(0, 0, 0, 0)
	}
	return ip.To4()
}
