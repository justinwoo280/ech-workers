package xhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	commonnet "ewp-core/common/net"
	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"

	"golang.org/x/net/http2"
)

type Transport struct {
	serverAddr        string
	serverIP          string
	token             string
	password          string // Trojan password
	uuid              [16]byte
	uuidStr           string
	useECH            bool
	enableFlow        bool
	enablePQC         bool
	useTrojan         bool // Use Trojan protocol
	path              string
	mode              string
	echManager        *commontls.ECHManager

	// Xray-core 风格的随机化配置
	paddingBytes     RangeConfig  // Referer padding 大小
	postSizeRange    RangeConfig  // POST 请求体大小随机化
	requestInterval  RangeConfig  // 请求间隔随机化
	maxConcurrent    RangeConfig  // 最大并发数随机化
	connectionTimeout RangeConfig  // 连接超时随机化

	// HTTP 头部配置
	customHeaders    map[string]string
	enablePadding    bool  // 是否启用 padding（ECH 环境下建议关闭路径 padding）
	paddingInReferer bool  // 仅在 Referer 中添加 padding

	// Browser Dialer 配置
	useBrowserDialer bool  // 是否使用 Browser Dialer

	// SSE 伪装配置
	useSSEHeaders bool  // 伪装成 Server-Sent Events 流
	noSSEHeader   bool  // 禁用 SSE Content-Type（某些 CDN 场景）

	// Xmux 连接池管理
	xmuxConfig XmuxConfig
	xmuxManager *XmuxManager
}

func New(serverAddr, serverIP, token string, useECH, enableFlow bool, path string, echManager *commontls.ECHManager) (*Transport, error) {
	return NewWithProtocol(serverAddr, serverIP, token, "", useECH, enableFlow, false, false, path, echManager)
}

func NewWithProtocol(serverAddr, serverIP, token, password string, useECH, enableFlow, enablePQC, useTrojan bool, path string, echManager *commontls.ECHManager) (*Transport, error) {
	var uuid [16]byte
	if !useTrojan {
		var err error
		uuid, err = transport.ParseUUID(token)
		if err != nil {
			return nil, fmt.Errorf("invalid UUID: %w", err)
		}
	}

	if path == "" {
		path = "/xhttp"
	}

	// 默认配置 - 针对 ECH 环境优化
	paddingInReferer := useECH // ECH 环境下默认只在 Referer 中 padding

	// 初始化 Xmux 配置
	xmuxConfig := XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 2, To: 5},      // 每个连接最大并发 2-5
		MaxConnections: &RangeConfig{From: 1, To: 3},      // 总共 1-3 个连接
		CMaxReuseTimes: &RangeConfig{From: 0, To: 0},     // 连接复用次数无限制
		HMaxRequestTimes: &RangeConfig{From: 50, To: 100}, // 每个连接处理 50-100 个请求
		HMaxReusableSecs: &RangeConfig{From: 300, To: 600}, // 连接可重用 5-10 分钟
		HKeepAlivePeriod: 30, // Keep-Alive 30 秒
	}

	return &Transport{
		serverAddr:        serverAddr,
		serverIP:          serverIP,
		token:             token,
		password:          password,
		uuid:              uuid,
		uuidStr:           token,
		useECH:            useECH,
		enableFlow:        enableFlow,
		enablePQC:         enablePQC,
		useTrojan:         useTrojan,
		path:              path,
		mode:              "stream-one",
		echManager:        echManager,

		// 随机化配置 - 基于 Xray-core
		paddingBytes:     RangeConfig{From: 50, To: 200},   // Referer padding
		postSizeRange:    RangeConfig{From: 1024, To: 4096}, // POST 大小
		requestInterval:  RangeConfig{From: 10, To: 100},   // 请求间隔 ms
		maxConcurrent:    RangeConfig{From: 2, To: 5},      // 并发数
		connectionTimeout: RangeConfig{From: 5000, To: 10000}, // 连接超时 ms

		// HTTP 配置
		customHeaders:    make(map[string]string),
		enablePadding:    true,
		paddingInReferer: paddingInReferer,
		
		// SSE 伪装配置（默认启用）
		useSSEHeaders:    true,  // 伪装成 SSE 流，对抗 CDN/Nginx 缓冲
		noSSEHeader:      false, // 某些 CDN 可能需要禁用 Content-Type

		// Xmux 连接池配置
		xmuxConfig: xmuxConfig,
		xmuxManager: nil, // 延迟初始化
	}, nil
}

func (t *Transport) SetMode(mode string) *Transport {
	t.mode = mode
	return t
}

// SetCustomHeader 设置自定义头部
func (t *Transport) SetCustomHeader(key, value string) *Transport {
	t.customHeaders[key] = value
	return t
}

// SetPaddingConfig 设置 padding 配置
func (t *Transport) SetPaddingConfig(enable bool, onlyReferer bool) *Transport {
	t.enablePadding = enable
	t.paddingInReferer = onlyReferer
	return t
}

// SetXmuxConfig 设置 Xmux 连接池配置
func (t *Transport) SetXmuxConfig(config XmuxConfig) *Transport {
	t.xmuxConfig = config
	// 重新初始化连接池管理器
	if t.xmuxManager != nil {
		t.xmuxManager.Close()
		t.xmuxManager = nil
	}
	return t
}

// SetSSEHeaders 设置是否使用 SSE 伪装头
func (t *Transport) SetSSEHeaders(enabled bool) *Transport {
	t.useSSEHeaders = enabled
	return t
}

// SetNoSSEHeader 设置是否禁用 SSE Content-Type（某些 CDN 场景）
func (t *Transport) SetNoSSEHeader(disabled bool) *Transport {
	t.noSSEHeader = disabled
	return t
}

// SetBrowserDialer 设置是否使用 Browser Dialer
func (t *Transport) SetBrowserDialer(enable bool) *Transport {
	t.useBrowserDialer = enable
	return t
}

// getXmuxManager 获取或创建 Xmux 管理器
func (t *Transport) getXmuxManager() *XmuxManager {
	if t.xmuxManager == nil {
		t.xmuxManager = NewXmuxManager(t.xmuxConfig, func() XmuxConn {
			// 创建新的 HTTP 客户端连接
			httpClient, _ := t.createHTTPClient(t.parseHost(), t.parsePort())
			return NewXmuxHTTPClient(httpClient)
		})
	}
	return t.xmuxManager
}

// parseHost 解析主机名
func (t *Transport) parseHost() string {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return "unknown"
	}
	return parsed.Host
}

// parsePort 解析端口
func (t *Transport) parsePort() string {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return "443"
	}
	return parsed.Port
}

// GetRequestHeader 统一的请求头生成 - 基于 Xray-core 设计
func (t *Transport) GetRequestHeader(rawURL string) http.Header {
	header := http.Header{}

	// 添加自定义头部
	for k, v := range t.customHeaders {
		header.Add(k, v)
	}

	// ECH 环境下仅在 Referer 中添加 padding
	if t.enablePadding && t.paddingInReferer {
		paddingLength := t.paddingBytes.Rand()
		if paddingLength > 0 {
			// 构造带 padding 的 Referer
			refererURL := rawURL + "?x_padding=" + strings.Repeat("X", int(paddingLength))
			header.Set("Referer", refererURL)
		}
	}

	// 添加其他标准头部
	header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	// SSE 伪装：Accept text/event-stream 让中间件认为这是 SSE 长连接
	if t.useSSEHeaders {
		header.Set("Accept", "text/event-stream")
	} else {
		header.Set("Accept", "*/*")
	}
	
	header.Set("Accept-Language", "en-US,en;q=0.9")
	header.Set("Cache-Control", "no-cache")
	header.Set("Pragma", "no-cache")

	return header
}

func (t *Transport) Name() string {
	name := "XHTTP"
	if t.useTrojan {
		name += "+Trojan"
	} else if t.enableFlow {
		name += "+Vision"
	} else {
		name += "+EWP"
	}
	if t.useECH {
		name += "+ECH"
	} else {
		name += "+TLS"
	}
	return name
}

func (t *Transport) Dial() (transport.TunnelConn, error) {
	if t.mode == "stream-down" {
		return t.dialStreamDown()
	}
	return t.dialStreamOne()
}

func (t *Transport) createHTTPClient(host, port string) (*http.Client, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := commontls.NewClient(commontls.ClientOptions{
		ServerName: parsed.Host,
		EnableECH:  t.useECH,
		EnablePQC:  t.enablePQC,
		ECHManager: t.echManager,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	stdConfig, err := tlsConfig.TLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS config: %w", err)
	}

	stdConfig.NextProtos = []string{"h2"}

	// Resolve serverIP if it's a domain name using system DNS
	resolvedIP := t.serverIP
	if resolvedIP != "" && !isIPAddress(resolvedIP) {
		ips, err := net.LookupIP(resolvedIP)
		if err != nil {
			log.Printf("[XHTTP] System DNS resolution failed for serverIP %s: %v", resolvedIP, err)
			return nil, fmt.Errorf("DNS resolution failed for serverIP: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
			log.V("[XHTTP] Resolved serverIP %s -> %s", t.serverIP, resolvedIP)
		} else {
			return nil, fmt.Errorf("no IPs returned for serverIP %s", t.serverIP)
		}
	}

	// If no serverIP, resolve serverAddr using system DNS
	if resolvedIP == "" && !isIPAddress(host) {
		ips, err := net.LookupIP(host)
		if err != nil {
			log.Printf("[XHTTP] System DNS resolution failed for %s: %v", host, err)
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
		}
	}

	target := net.JoinHostPort(host, port)
	if resolvedIP != "" {
		target = net.JoinHostPort(resolvedIP, port)
		log.Printf("[XHTTP] Connecting to: %s (SNI: %s)", target, host)
	}

	// HTTP/2 Transport 配置 - 参考 Xray-core ChromeH2KeepAlivePeriod
	h2Transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			// 使用 TCP Fast Open 减少延迟
			rawConn, err := commonnet.DialTFOContext(ctx, "tcp", target, 10*time.Second)
			if err != nil {
				return nil, err
			}
			return tls.Client(rawConn, stdConfig), nil
		},
		IdleConnTimeout:            90 * time.Second,  // 连接空闲超时
		ReadIdleTimeout:            15 * time.Second,  // 读空闲超时（参考 Chrome）→ 触发 HTTP/2 PING
		StrictMaxConcurrentStreams: true,             // 严格限制并发流数
	}

	return &http.Client{
		Transport: h2Transport,
		Timeout:   0,
	}, nil
}

// createRequestWithContext 创建带 httptrace 和 WithoutCancel 的请求
func (t *Transport) createRequestWithContext(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	// 使用 WithoutCancel 防止上层 context 取消中断请求
	ctx = context.WithoutCancel(ctx)

	// 添加 httptrace 获取真实地址信息
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			log.V("[XHTTP] GotConn: Remote=%s, Local=%s, Reused=%v, WasIdle=%v",
				connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr(),
				connInfo.Reused, connInfo.WasIdle)
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			log.V("[XHTTP] DNS Start: %s", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			log.V("[XHTTP] DNS Done: %v", info.Addrs)
		},
		TLSHandshakeStart: func() {
			log.V("[XHTTP] TLS Handshake Start")
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil {
				log.V("[XHTTP] TLS Handshake Done: Version=%s, Cipher=%s, ServerName=%s",
					tlsVersionToString(state.Version),
					tls.CipherSuiteName(state.CipherSuite),
					state.ServerName)
			} else {
				log.V("[XHTTP] TLS Handshake Error: %v", err)
			}
		},
	})

	return http.NewRequestWithContext(ctx, method, url, body)
}

// tlsVersionToString 转换 TLS 版本号为字符串
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown %x", version)
	}
}

func (t *Transport) dialStreamOne() (transport.TunnelConn, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	// 使用 Xmux 连接池获取 HTTP 客户端
	xmuxManager := t.getXmuxManager()
	xmuxClient := xmuxManager.GetXmuxClient(context.Background())
	xmuxHTTPClient := xmuxClient.XmuxConn.(*XmuxHTTPClient)
	httpClient := xmuxHTTPClient.GetClient()

	log.V("[XHTTP] HTTP/2 transport ready for %s (pooled)", parsed.Host)

	return NewStreamOneConn(
		httpClient,
		parsed.Host,
		parsed.Port,
		t.path,
		t.uuid,
		t.uuidStr,
		t.password,
		t.enableFlow,
		t.useTrojan,
		t, // 传递 Transport 以获取新功能
	), nil
}

func (t *Transport) dialStreamDown() (transport.TunnelConn, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	// 使用 Xmux 连接池获取 HTTP 客户端
	xmuxManager := t.getXmuxManager()
	xmuxClient := xmuxManager.GetXmuxClient(context.Background())
	xmuxHTTPClient := xmuxClient.XmuxConn.(*XmuxHTTPClient)
	httpClient := xmuxHTTPClient.GetClient()

	return NewStreamDownConn(
		httpClient,
		parsed.Host,
		parsed.Port,
		t.path,
		t.uuid,
		t.uuidStr,
		t.password,
		t.enableFlow,
		t.useTrojan,
		t, // 传递 Transport 以获取新功能
	), nil
}
  
// isIPAddress checks if a string is an IP address  
func isIPAddress(s string) bool {  
	return net.ParseIP(s) != nil  
} 
