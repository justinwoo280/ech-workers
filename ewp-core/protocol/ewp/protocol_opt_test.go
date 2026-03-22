package ewp

import (
	"bytes"
	"io"
	"testing"
)

var testUUID = [16]byte{
	0xd3, 0x42, 0xd1, 0x1e, 0xd4, 0x24, 0x45, 0x83,
	0xb3, 0x6e, 0x52, 0x4a, 0xb1, 0xf0, 0xaf, 0xa4,
}

func testAddr() Address {
	return Address{Type: AddressTypeDomain, Host: "example.com", Port: 443}
}

// ─── T1: ReadHandshake 单次分配 ───────────────────────────────────────────────

func TestReadHandshake_SingleAlloc(t *testing.T) {
	req := NewHandshakeRequest(testUUID, CommandTCP, testAddr())
	frame, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := ReadHandshake(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadHandshake: %v", err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("frame mismatch: got %d bytes want %d bytes", len(got), len(frame))
	}

	allocs := testing.AllocsPerRun(1000, func() {
		r := bytes.NewReader(frame)
		_, _ = ReadHandshake(r)
	})
	if allocs > 1 {
		t.Errorf("ReadHandshake allocates %.0f heap objects, want ≤1", allocs)
	}
}

func TestReadHandshake_TruncatedHeader(t *testing.T) {
	_, err := ReadHandshake(bytes.NewReader([]byte{0x01, 0x02}))
	if err == nil {
		t.Fatal("expected error for truncated header, got nil")
	}
}

func TestReadHandshake_InvalidPayloadLen(t *testing.T) {
	header := make([]byte, 15)
	header[0] = 0x01
	header[13] = 0x00
	header[14] = 0x01 // payloadLen = 1 < MinPayloadLength
	_, err := ReadHandshake(bytes.NewReader(header))
	if err == nil {
		t.Fatal("expected ErrInvalidLength for tiny payload, got nil")
	}
}

func TestReadHandshake_TruncatedPayload(t *testing.T) {
	req := NewHandshakeRequest(testUUID, CommandTCP, testAddr())
	frame, _ := req.Encode()
	_, err := ReadHandshake(bytes.NewReader(frame[:19]))
	if err != io.ErrUnexpectedEOF && err != io.EOF {
		t.Fatalf("expected EOF error for truncated payload, got %v", err)
	}
}

// ─── T2: UUIDKeyCache — 预计算 HMAC key，热路径零 SHA256 ─────────────────────

func TestUUIDKeyCache_HitPath(t *testing.T) {
	req := NewHandshakeRequest(testUUID, CommandTCP, testAddr())
	frame, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	cache := NewUUIDKeyCache([][16]byte{testUUID})
	decoded, err := DecodeHandshakeRequestCached(frame, cache)
	if err != nil {
		t.Fatalf("DecodeHandshakeRequestCached: %v", err)
	}
	if decoded.UUID != testUUID {
		t.Errorf("UUID mismatch: got %x want %x", decoded.UUID, testUUID)
	}
	if decoded.Command != CommandTCP {
		t.Errorf("Command mismatch: got %x want %x", decoded.Command, CommandTCP)
	}
}

func TestUUIDKeyCache_WrongUUID(t *testing.T) {
	wrongUUID := [16]byte{0xFF, 0xFE, 0xFD}
	req := NewHandshakeRequest(wrongUUID, CommandTCP, testAddr())
	frame, _ := req.Encode()

	cache := NewUUIDKeyCache([][16]byte{testUUID})
	_, err := DecodeHandshakeRequestCached(frame, cache)
	if err == nil {
		t.Fatal("expected auth error for unknown UUID, got nil")
	}
}

func TestUUIDKeyCache_MultiUUID(t *testing.T) {
	uuid2 := [16]byte{0xAA, 0xBB, 0xCC}
	uuids := [][16]byte{testUUID, uuid2}
	cache := NewUUIDKeyCache(uuids)

	for _, u := range uuids {
		req := NewHandshakeRequest(u, CommandTCP, testAddr())
		frame, _ := req.Encode()

		decoded, err := DecodeHandshakeRequestCached(frame, cache)
		if err != nil {
			t.Errorf("UUID %x: unexpected error: %v", u, err)
			continue
		}
		if decoded.UUID != u {
			t.Errorf("UUID %x: got decoded UUID %x", u, decoded.UUID)
		}
	}
}

// DecodeHandshakeRequestCached 允许最多 2 次 alloc（AEAD Open 输出 + chacha20 内部状态）
func TestUUIDKeyCache_ZeroAllocsHotPath(t *testing.T) {
	req := NewHandshakeRequest(testUUID, CommandTCP, testAddr())
	frame, _ := req.Encode()
	cache := NewUUIDKeyCache([][16]byte{testUUID})

	allocs := testing.AllocsPerRun(500, func() {
		_, _ = DecodeHandshakeRequestCached(frame, cache)
	})
	if allocs > 2 {
		t.Errorf("DecodeHandshakeRequestCached allocates %.0f heap objects, want ≤2", allocs)
	}
}
