package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"proxy-server/ewp"
)

var (
	validUUIDs  [][16]byte
	nonceCache  *ewp.NonceCache
	rateLimiter *ewp.RateLimiter
)

func initEWPHandler(uuidStr string) error {
	validUUIDs = make([][16]byte, 0)
	
	uuids := strings.Split(uuidStr, ",")
	for _, u := range uuids {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		
		uuid, err := parseUUID(u)
		if err != nil {
			return fmt.Errorf("invalid UUID %s: %w", u, err)
		}
		
		validUUIDs = append(validUUIDs, uuid)
		log.Printf("[EWP] Registered UUID: %s", u)
	}
	
	if len(validUUIDs) == 0 {
		return fmt.Errorf("no valid UUIDs configured")
	}
	
	// 初始化安全组件
	nonceCache = ewp.NewNonceCache()
	rateLimiter = ewp.NewRateLimiter(20, 30*time.Second) // 每秒最多 20 次握手，超限封禁 30 秒
	
	log.Printf("[EWP] Security: Nonce cache and rate limiter initialized")
	
	return nil
}

func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")
	
	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d", len(s))
	}
	
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return uuid, fmt.Errorf("invalid UUID hex: %w", err)
	}
	
	copy(uuid[:], decoded)
	return uuid, nil
}

func handleEWPHandshake(reader io.Reader, clientIP string) (*ewp.HandshakeRequest, []byte, error) {
	// === 1. 速率限制检查（防 DoS） ===
	if !rateLimiter.Allow(clientIP) {
		log.Printf("🚫 EWP: Rate limit exceeded for IP %s", clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("rate limit exceeded")
	}
	
	handshakeData, err := ewp.ReadHandshake(reader)
	if err != nil {
		log.Printf("❌ EWP: Failed to read handshake from %s: %v", clientIP, err)
		rateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), err
	}

	// === 2. 解码和验证握手请求 ===
	req, err := ewp.DecodeHandshakeRequest(handshakeData, validUUIDs)
	if err != nil {
		log.Printf("❌ EWP: Handshake validation failed from %s: %v", clientIP, err)
		rateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), err
	}

	// === 3. Nonce 去重检查（防重放攻击） ===
	if nonceCache.Check(req.Nonce) {
		log.Printf("🚫 EWP: Replay attack detected from %s (duplicate nonce)", clientIP)
		rateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("replay attack detected")
	}
	
	// === 4. 添加 Nonce 到缓存 ===
	nonceCache.Add(req.Nonce)

	resp := ewp.NewSuccessResponse(req.Version, req.Nonce)
	respData, err := resp.Encode(req.UUID)
	if err != nil {
		log.Printf("❌ EWP: Failed to encode response: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	log.Printf("✅ EWP: Handshake successful from %s, target: %s", clientIP, req.TargetAddr.String())
	return req, respData, nil
}

func handleEWPHandshakeBinary(data []byte, clientIP string) (*ewp.HandshakeRequest, []byte, error) {
	// === 1. 速率限制检查（防 DoS） ===
	if !rateLimiter.Allow(clientIP) {
		log.Printf("🚫 EWP: Rate limit exceeded for IP %s", clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("rate limit exceeded")
	}
	
	// === 2. 解码和验证握手请求 ===
	req, err := ewp.DecodeHandshakeRequest(data, validUUIDs)
	if err != nil {
		log.Printf("❌ EWP: Handshake validation failed from %s: %v", clientIP, err)
		rateLimiter.RecordFailure(clientIP) // 记录失败，延长封禁
		return nil, ewp.GenerateFakeResponse(), err
	}
	
	// === 3. Nonce 去重检查（防重放攻击） ===
	if nonceCache.Check(req.Nonce) {
		log.Printf("🚫 EWP: Replay attack detected from %s (duplicate nonce)", clientIP)
		rateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("replay attack detected")
	}
	
	// === 4. 添加 Nonce 到缓存 ===
	nonceCache.Add(req.Nonce)

	resp := ewp.NewSuccessResponse(req.Version, req.Nonce)
	respData, err := resp.Encode(req.UUID)
	if err != nil {
		log.Printf("❌ EWP: Failed to encode response: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	log.Printf("✅ EWP: Handshake successful from %s, target: %s", clientIP, req.TargetAddr.String())
	return req, respData, nil
}
