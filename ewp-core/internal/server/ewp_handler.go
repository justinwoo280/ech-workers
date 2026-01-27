package server

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"ewp-core/protocol/ewp"
)

var (
	ValidUUIDs  [][16]byte
	NonceCache  *ewp.NonceCache
	RateLimiter *ewp.RateLimiter
)

func InitEWPHandler(uuidStr string) error {
	ValidUUIDs = make([][16]byte, 0)
	
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
		
		ValidUUIDs = append(ValidUUIDs, uuid)
		log.Printf("[EWP] Registered UUID: %s", u)
	}
	
	if len(ValidUUIDs) == 0 {
		return fmt.Errorf("no valid UUIDs configured")
	}
	
	NonceCache = ewp.NewNonceCache()
	RateLimiter = ewp.NewRateLimiter(300, 5*time.Second)
	
	log.Printf("[EWP] Security: Nonce cache and rate limiter initialized (maxRate=300/s, banTime=5s)")
	
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

func HandleEWPHandshake(reader io.Reader, clientIP string) (*ewp.HandshakeRequest, []byte, error) {
	if !RateLimiter.Allow(clientIP) {
		log.Printf("🚫 EWP: Rate limit exceeded for IP %s", clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("rate limit exceeded")
	}
	
	handshakeData, err := ewp.ReadHandshake(reader)
	if err != nil {
		log.Printf("❌ EWP: Failed to read handshake from %s: %v", clientIP, err)
		RateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), err
	}

	req, err := ewp.DecodeHandshakeRequest(handshakeData, ValidUUIDs)
	if err != nil {
		log.Printf("❌ EWP: Handshake validation failed from %s: %v", clientIP, err)
		RateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), err
	}

	if NonceCache.Check(req.Nonce) {
		log.Printf("🚫 EWP: Replay attack detected from %s (duplicate nonce)", clientIP)
		RateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("replay attack detected")
	}
	
	NonceCache.Add(req.Nonce)

	resp := ewp.NewSuccessResponse(req.Version, req.Nonce)
	respData, err := resp.Encode(req.UUID)
	if err != nil {
		log.Printf("❌ EWP: Failed to encode response: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	log.Printf("✅ EWP: Handshake successful from %s, target: %s", clientIP, req.TargetAddr.String())
	return req, respData, nil
}

func HandleEWPHandshakeBinary(data []byte, clientIP string) (*ewp.HandshakeRequest, []byte, error) {
	if !RateLimiter.Allow(clientIP) {
		log.Printf("🚫 EWP: Rate limit exceeded for IP %s", clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("rate limit exceeded")
	}
	
	req, err := ewp.DecodeHandshakeRequest(data, ValidUUIDs)
	if err != nil {
		log.Printf("❌ EWP: Handshake validation failed from %s: %v", clientIP, err)
		RateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), err
	}
	
	if NonceCache.Check(req.Nonce) {
		log.Printf("🚫 EWP: Replay attack detected from %s (duplicate nonce)", clientIP)
		RateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("replay attack detected")
	}
	
	NonceCache.Add(req.Nonce)

	resp := ewp.NewSuccessResponse(req.Version, req.Nonce)
	respData, err := resp.Encode(req.UUID)
	if err != nil {
		log.Printf("❌ EWP: Failed to encode response: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	log.Printf("✅ EWP: Handshake successful from %s, target: %s", clientIP, req.TargetAddr.String())
	return req, respData, nil
}
