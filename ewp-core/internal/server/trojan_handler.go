package server

import (
	"log"
	"strings"

	"ewp-core/protocol/trojan"
)

var (
	TrojanService *trojan.Service
)

// InitTrojanHandler 初始化 Trojan 服务
func InitTrojanHandler(passwordStr string) error {
	TrojanService = trojan.NewService(nil)

	passwords := strings.Split(passwordStr, ",")
	count := 0
	for _, p := range passwords {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		TrojanService.AddUserByPassword(p)
		log.Printf("[Trojan] Registered user: %s", maskPassword(p))
		count++
	}

	log.Printf("[Trojan] Service initialized with %d users", count)
	return nil
}

// SetFallbackHandler 设置 fallback 处理器
func SetTrojanFallback(handler trojan.FallbackHandler) {
	if TrojanService != nil {
		TrojanService.SetFallbackHandler(handler)
	}
}

func maskPassword(p string) string {
	if len(p) <= 4 {
		return "****"
	}
	return p[:2] + "****" + p[len(p)-2:]
}

// GetTrojanValidKeys 获取有效密钥映射
func GetTrojanValidKeys() map[[trojan.KeyLength]byte]string {
	if TrojanService == nil {
		return nil
	}
	return TrojanService.GetValidKeys()
}

// GetTrojanUserCount 获取用户数量
func GetTrojanUserCount() int {
	if TrojanService == nil {
		return 0
	}
	return TrojanService.UserCount()
}
