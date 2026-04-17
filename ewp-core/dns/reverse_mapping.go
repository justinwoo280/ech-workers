package dns

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// ReverseMapping stores IP→domain mappings from real DNS responses.
// This enables domain-based routing even when FakeIP is not used.
// Thread-safe with LRU eviction and TTL-based expiration.
type ReverseMapping struct {
	mu         sync.RWMutex
	entries    map[netip.Addr]*reverseEntry
	order      []*netip.Addr // LRU order: oldest first
	maxEntries int
}

type reverseEntry struct {
	domain    string
	expiresAt time.Time
}

// NewReverseMapping creates a new reverse mapping cache.
// maxEntries limits the cache size (recommended: 4096).
func NewReverseMapping(maxEntries int) *ReverseMapping {
	return &ReverseMapping{
		entries:    make(map[netip.Addr]*reverseEntry, maxEntries),
		order:      make([]*netip.Addr, 0, maxEntries),
		maxEntries: maxEntries,
	}
}

// Store saves an IP→domain mapping with the given TTL.
func (rm *ReverseMapping) Store(ip netip.Addr, domain string, ttl time.Duration) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Remove existing entry if present (will be re-added at end)
	if _, exists := rm.entries[ip]; exists {
		rm.removeOrder(ip)
	}

	// Evict oldest if at capacity
	if len(rm.entries) >= rm.maxEntries {
		rm.evictOldest()
	}

	rm.entries[ip] = &reverseEntry{
		domain:    domain,
		expiresAt: time.Now().Add(ttl),
	}
	rm.order = append(rm.order, &ip)
}

// Lookup returns the domain for the given IP.
// Returns ("", false) if not found or expired.
func (rm *ReverseMapping) Lookup(ip netip.Addr) (string, bool) {
	rm.mu.RLock()
	entry, exists := rm.entries[ip]
	rm.mu.RUnlock()

	if !exists {
		return "", false
	}

	if time.Now().After(entry.expiresAt) {
		rm.mu.Lock()
		delete(rm.entries, ip)
		rm.removeOrder(ip)
		rm.mu.Unlock()
		return "", false
	}

	return entry.domain, true
}

// StoreDNSResponse extracts A/AAAA records from a DNS response and stores mappings.
// This is called after a successful DNS query to enable reverse lookups.
func (rm *ReverseMapping) StoreDNSResponse(response []byte) {
	if len(response) < 12 {
		return
	}

	// Parse header
	ancount := int(binary.BigEndian.Uint16(response[6:8]))
	if ancount == 0 {
		return
	}

	// Skip header and question section
	off := 12
	// Skip QNAME
	for off < len(response) {
		if response[off] == 0 {
			off++ // skip null terminator
			break
		}
		labelLen := int(response[off])
		off += 1 + labelLen
	}
	if off+4 > len(response) {
		return
	}
	off += 4 // skip QTYPE(2) + QCLASS(2)

	// Parse answer records
	domain := ParseDNSName(response)
	if domain == "" {
		return
	}

	for i := 0; i < ancount && off < len(response); i++ {
		// Check if name is a pointer or inline
		if off >= len(response) {
			break
		}

		var rrStart int
		if response[off]&0xc0 == 0xc0 {
			// Name pointer (2 bytes)
			if off+2 > len(response) {
				break
			}
			off += 2
			rrStart = off
		} else {
			// Inline name - skip it
			for off < len(response) && response[off] != 0 {
				labelLen := int(response[off])
				off += 1 + labelLen
			}
			if off >= len(response) {
				break
			}
			off++ // skip null terminator
			rrStart = off
		}

		// Now at: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
		if rrStart+10 > len(response) {
			break
		}

		rrType := binary.BigEndian.Uint16(response[rrStart : rrStart+2])
		// Skip CLASS(2)
		ttl := time.Duration(binary.BigEndian.Uint32(response[rrStart+4:rrStart+8])) * time.Second
		if ttl <= 0 {
			ttl = 5 * time.Minute // default TTL
		}
		rdlength := int(binary.BigEndian.Uint16(response[rrStart+8 : rrStart+10]))

		rdataStart := rrStart + 10
		rdataEnd := rdataStart + rdlength
		if rdataEnd > len(response) {
			break
		}

		// Store A or AAAA record
		switch rrType {
		case 1: // A record (IPv4)
			if rdlength == 4 {
				ip := netip.AddrFrom4([4]byte(response[rdataStart : rdataStart+4]))
				rm.Store(ip, domain, ttl)
			}
		case 28: // AAAA record (IPv6)
			if rdlength == 16 {
				ip := netip.AddrFrom16([16]byte(response[rdataStart : rdataStart+16]))
				rm.Store(ip, domain, ttl)
			}
		}

		off = rdataEnd
	}
}

// removeOrder removes an IP from the LRU order slice (caller must hold lock).
func (rm *ReverseMapping) removeOrder(ip netip.Addr) {
	for i, v := range rm.order {
		if v != nil && *v == ip {
			rm.order = append(rm.order[:i], rm.order[i+1:]...)
			return
		}
	}
}

// evictOldest removes the oldest entry (caller must hold lock).
func (rm *ReverseMapping) evictOldest() {
	if len(rm.order) == 0 {
		return
	}
	oldest := rm.order[0]
	if oldest != nil {
		delete(rm.entries, *oldest)
	}
	rm.order = rm.order[1:]
}

// Clear removes all entries.
func (rm *ReverseMapping) Clear() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.entries = make(map[netip.Addr]*reverseEntry, rm.maxEntries)
	rm.order = rm.order[:0]
}

// Size returns the current number of entries.
func (rm *ReverseMapping) Size() int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return len(rm.entries)
}
