package ewpmobile

import "sync"

// GoMobile 导出的接口
// 这些方法将被编译成 Java/Kotlin 可调用的接口

// 全局客户端实例管理
var (
	clients = make(map[int64]*EWPClient)
	nextID  int64 = 1
	clientMu sync.RWMutex
)

// CreateClient 创建客户端并返回 ID
func CreateClient() int64 {
	clientMu.Lock()
	defer clientMu.Unlock()

	id := nextID
	nextID++
	clients[id] = NewEWPClient()
	return id
}

// GetClient 根据 ID 获取客户端
func GetClient(id int64) *EWPClient {
	clientMu.RLock()
	defer clientMu.RUnlock()
	return clients[id]
}

// DestroyClient 销毁客户端
func DestroyClient(id int64) {
	clientMu.Lock()
	defer clientMu.Unlock()

	if client, exists := clients[id]; exists {
		client.Cleanup()
		delete(clients, id)
	}
}

// 全局方法 - 简化版本
var globalClient *EWPClient

// InitGlobalClient 初始化全局客户端
func InitGlobalClient() {
	if globalClient == nil {
		globalClient = NewEWPClient()
	}
}

// GlobalConnect 全局客户端连接
func GlobalConnect(serverAddr, token, password string, useECH, enableFlow bool, protocol, transportMode string) bool {
	InitGlobalClient()
	return globalClient.Connect(serverAddr, token, password, useECH, enableFlow, protocol, transportMode)
}

// GlobalDisconnect 全局客户端断开
func GlobalDisconnect() {
	if globalClient != nil {
		globalClient.Disconnect()
	}
}

// GlobalIsConnected 全局客户端连接状态
func GlobalIsConnected() bool {
	if globalClient == nil {
		return false
	}
	return globalClient.IsConnected()
}

// GlobalStartSocks5Proxy 全局启动 SOCKS5 代理
func GlobalStartSocks5Proxy(port int) bool {
	if globalClient == nil {
		return false
	}
	return globalClient.StartSocks5Proxy(port)
}

// GlobalStopSocks5Proxy 全局停止 SOCKS5 代理
func GlobalStopSocks5Proxy() {
	if globalClient != nil {
		globalClient.StopSocks5Proxy()
	}
}

// GlobalGetStats 全局获取统计信息
func GlobalGetStats() map[string]interface{} {
	if globalClient == nil {
		return map[string]interface{}{
			"connected": false,
		}
	}
	return globalClient.GetStats()
}

// GlobalCleanup 全局清理
func GlobalCleanup() {
	if globalClient != nil {
		globalClient.Cleanup()
		globalClient = nil
	}
}
