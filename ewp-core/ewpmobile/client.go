package ewpmobile

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/option"
	"ewp-core/protocol"
	"ewp-core/protocol/socks5"
	"ewp-core/transport"
	"ewp-core/transport/grpc"
	"ewp-core/transport/websocket"
	"ewp-core/transport/xhttp"
)

// EWPClient GoMobile 接口
type EWPClient struct {
	mu           sync.RWMutex
	connected    bool
	socks5Server *socks5.Server
	transport    transport.Transport
	cancel       context.CancelFunc
	ctx          context.Context
}

// NewEWPClient 创建新的 EWP 客户端
func NewEWPClient() *EWPClient {
	return &EWPClient{}
}

// Connect 连接到远程服务器
func (c *EWPClient) Connect(serverAddr, token, password string, useECH, enableFlow bool, protocol, transportMode string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		log.Printf("[Mobile] Already connected")
		return true
	}

	log.Printf("[Mobile] Connecting to server: %s", serverAddr)

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	c.cancel = cancel

	// 创建配置
	cfg := &option.Config{
		ServerAddr:  serverAddr,
		Token:       token,
		Password:    password,
		ProtoMode:   protocol,
		AppProtocol: transportMode,
		UseECH:      useECH,
		EnableFlow:  enableFlow,
		ListenAddr:  "127.0.0.1:1080",
	}

	// 初始化 ECH 管理器
	if !cfg.Fallback {
		log.Printf("[Mobile] Initializing ECH configuration...")
		echMgr, err := tls.NewECHManager(cfg.ServerAddr, cfg.ECHConfig)
		if err != nil {
			log.Printf("[Mobile] Failed to initialize ECH: %v", err)
			cancel()
			return false
		}
		cfg.ECHManager = echMgr
	}

	// 创建传输层
	var err error
	switch cfg.AppProtocol {
	case "grpc":
		c.transport, err = grpc.NewWithProtocol(cfg.ServerAddr, cfg.ServerIP, cfg.Token, cfg.Password,
			cfg.UseECH, cfg.EnableFlow, cfg.EnablePQC, cfg.UseTrojan, cfg.Path, cfg.ECHManager)
	case "websocket":
		c.transport, err = websocket.NewWithProtocol(cfg.ServerAddr, cfg.ServerIP, cfg.Token, cfg.Password,
			cfg.UseECH, cfg.EnableFlow, cfg.EnablePQC, cfg.UseTrojan, cfg.Path, cfg.ECHManager)
	case "xhttp":
		c.transport, err = xhttp.NewWithProtocol(cfg.ServerAddr, cfg.ServerIP, cfg.Token, cfg.Password,
			cfg.UseECH, cfg.EnableFlow, cfg.EnablePQC, cfg.UseTrojan, cfg.Path, cfg.ECHManager)
	default:
		err = fmt.Errorf("unsupported protocol: %s", cfg.AppProtocol)
	}

	if err != nil {
		log.Printf("[Mobile] Failed to create transport: %v", err)
		cancel()
		return false
	}

	// 测试连接
	conn, err := c.transport.Dial()
	if err != nil {
		log.Printf("[Mobile] Failed to dial server: %v", err)
		cancel()
		return false
	}
	conn.Close()

	c.connected = true
	log.Printf("[Mobile] Connected successfully")
	return true
}

// Disconnect 断开连接
func (c *EWPClient) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		log.Printf("[Mobile] Already disconnected")
		return
	}

	log.Printf("[Mobile] Disconnecting")

	// 停止 SOCKS5 代理
	if c.socks5Server != nil {
		c.socks5Server.Stop()
		c.socks5Server = nil
	}

	// 取消上下文
	if c.cancel != nil {
		c.cancel()
	}

	// 关闭传输层
	if c.transport != nil {
		c.transport.Close()
		c.transport = nil
	}

	c.connected = false
	log.Printf("[Mobile] Disconnected")
}

// IsConnected 检查连接状态
func (c *EWPClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// StartSocks5Proxy 启动 SOCKS5 代理
func (c *EWPClient) StartSocks5Proxy(port int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		log.Printf("[Mobile] Not connected, cannot start SOCKS5 proxy")
		return false
	}

	if c.socks5Server != nil {
		log.Printf("[Mobile] SOCKS5 proxy already running")
		return true
	}

	log.Printf("[Mobile] Starting SOCKS5 proxy on port %d", port)

	// 创建 SOCKS5 服务器配置
	config := &socks5.Config{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", port),
		EnableUDP:  true,
		EnableDNS:  true,
	}

	// 创建处理函数
	onConnect := func(conn net.Conn, req *socks5.Request, initialData []byte) error {
		return c.handleSOCKS5Connect(conn, req, initialData)
	}

	onUDPAssociate := func(conn net.Conn, clientAddr string) error {
		return c.handleSOCKS5UDP(conn, clientAddr)
	}

	// 创建 SOCKS5 服务器
	server, err := socks5.NewServer(config, onConnect, onUDPAssociate)
	if err != nil {
		log.Printf("[Mobile] Failed to create SOCKS5 server: %v", err)
		return false
	}

	// 启动服务器
	go func() {
		if err := server.Start(); err != nil {
			log.Printf("[Mobile] SOCKS5 server error: %v", err)
		}
	}()

	c.socks5Server = server
	log.Printf("[Mobile] SOCKS5 proxy started on port %d", port)
	return true
}

// StopSocks5Proxy 停止 SOCKS5 代理
func (c *EWPClient) StopSocks5Proxy() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.socks5Server == nil {
		log.Printf("[Mobile] SOCKS5 proxy not running")
		return
	}

	log.Printf("[Mobile] Stopping SOCKS5 proxy")
	c.socks5Server.Stop()
	c.socks5Server = nil
	log.Printf("[Mobile] SOCKS5 proxy stopped")
}

// GetStats 获取统计信息
func (c *EWPClient) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := map[string]interface{}{
		"connected":      c.connected,
		"socks5_running": c.socks5Server != nil,
	}

	// 添加传输层统计
	if c.transport != nil {
		if xhttpTransport, ok := c.transport.(*xhttp.Transport); ok {
			if xmuxStats := xhttpTransport.GetXmuxStats(); xmuxStats != nil {
				stats["xmux"] = xmuxStats
			}
		}
	}

	return stats
}

// handleSOCKS5Connect 处理 SOCKS5 TCP 连接
func (c *EWPClient) handleSOCKS5Connect(conn net.Conn, req *socks5.Request, initialData []byte) error {
	if c.transport == nil {
		return fmt.Errorf("transport not available")
	}

	// 建立到目标服务器的连接
	targetConn, err := c.transport.Dial()
	if err != nil {
		return fmt.Errorf("failed to dial target: %v", err)
	}
	defer targetConn.Close()

	// 发送初始数据（如果有）
	if len(initialData) > 0 {
		if _, err := targetConn.Write(initialData); err != nil {
			return fmt.Errorf("failed to write initial data: %v", err)
		}
	}

	// 双向数据转发
	errChan := make(chan error, 2)

	// 客户端 -> 服务器
	go func() {
		_, err := copyData(targetConn, conn)
		errChan <- err
	}()

	// 服务器 -> 客户端
	go func() {
		_, err := copyData(conn, targetConn)
		errChan <- err
	}()

	// 等待任一方向完成
	return <-errChan
}

// handleSOCKS5UDP 处理 SOCKS5 UDP 关联
func (c *EWPClient) handleSOCKS5UDP(conn net.Conn, clientAddr string) error {
	// DNS 处理函数
	dnsHandler := func(query []byte) ([]byte, error) {
		// 这里可以实现 DoH 查询
		// 暂时返回空响应
		return nil, fmt.Errorf("DNS not implemented")
	}

	return socks5.HandleUDPAssociate(conn, clientAddr, dnsHandler)
}

// copyData 复制数据
func copyData(dst net.Conn, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024) // 32KB 缓冲区
	var written int64
	var err error

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = fmt.Errorf("short write")
				break
			}
		}
		if er != nil {
			if er.Error() != "EOF" {
				err = er
			}
			break
		}
	}

	return written, err
}

// Cleanup 清理资源
func (c *EWPClient) Cleanup() {
	c.Disconnect()
}
