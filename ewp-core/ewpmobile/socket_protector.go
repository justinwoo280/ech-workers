package ewpmobile

import (
	"log"
	"sync"
)

// SocketProtector Socket 保护接口（由 Android VpnService 实现）
// 用于防止 VPN 流量循环回到自己
type SocketProtector interface {
	// Protect 保护 socket 文件描述符，使其流量不经过 VPN
	// 返回 true 表示保护成功
	Protect(fd int) bool
}

var (
	socketProtector SocketProtector
	protectorMu     sync.RWMutex
)

// SetSocketProtector 设置 Socket 保护器（由 Android 端调用）
func SetSocketProtector(protector SocketProtector) {
	protectorMu.Lock()
	defer protectorMu.Unlock()
	socketProtector = protector
	log.Printf("[SocketProtector] Socket protector has been set")
}

// GetSocketProtector 获取当前的 Socket 保护器
func GetSocketProtector() SocketProtector {
	protectorMu.RLock()
	defer protectorMu.RUnlock()
	return socketProtector
}

// ProtectSocket 保护 socket（内部调用）
func ProtectSocket(fd int) bool {
	protectorMu.RLock()
	protector := socketProtector
	protectorMu.RUnlock()

	if protector == nil {
		log.Printf("[SocketProtector] Warning: No socket protector set, fd=%d may cause VPN loop", fd)
		return false
	}

	result := protector.Protect(fd)
	if !result {
		log.Printf("[SocketProtector] Failed to protect socket fd=%d", fd)
	}
	return result
}

// IsSocketProtectorSet 检查是否已设置保护器
func IsSocketProtectorSet() bool {
	protectorMu.RLock()
	defer protectorMu.RUnlock()
	return socketProtector != nil
}
