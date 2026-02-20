package server

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"ewp-core/protocol/ewp"
	log "ewp-core/log"
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
		log.Info("[EWP] Registered UUID: %s", u)
	}

	if len(ValidUUIDs) == 0 {
		return fmt.Errorf("no valid UUIDs configured")
	}

	NonceCache = ewp.NewNonceCache()
	RateLimiter = ewp.NewRateLimiter(300, 5*time.Second)

	log.Info("[EWP] Nonce cache and rate limiter initialized (maxRate=300/s, banTime=5s)")

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

func HandleEWPHandshakeBinary(data []byte, clientIP string) (*ewp.HandshakeRequest, []byte, error) {
	if !RateLimiter.Allow(clientIP) {
		log.Warn("[EWP] Rate limit exceeded for %s", clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("rate limit exceeded")
	}

	req, err := ewp.DecodeHandshakeRequest(data, ValidUUIDs)
	if err != nil {
		log.Warn("[EWP] Handshake failed from %s: %v", clientIP, err)
		RateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), err
	}

	if NonceCache.CheckAndAdd(req.Nonce) {
		log.Warn("[EWP] Replay attack (duplicate nonce) from %s", clientIP)
		RateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("replay attack detected")
	}

	resp := ewp.NewSuccessResponse(req.Version, req.Nonce)
	respData, err := resp.Encode(req.UUID)
	if err != nil {
		log.Error("[EWP] Failed to encode response: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	log.Info("[EWP] Handshake from %s -> %s", clientIP, req.TargetAddr.String())
	return req, respData, nil
}
