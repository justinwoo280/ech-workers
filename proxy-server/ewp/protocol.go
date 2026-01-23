package ewp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version1 = 0x01

	CommandTCP byte = 0x01
	CommandUDP byte = 0x02

	OptionMux           byte = 0x01
	OptionDataEncryption byte = 0x02

	MinPaddingLength = 64
	MaxPaddingLength = 255
	TimeWindow       = 120

	MinPayloadLength = 64
	MaxPayloadLength = 512
)

var (
	ErrInvalidVersion   = errors.New("ewp: invalid version")
	ErrInvalidLength    = errors.New("ewp: invalid payload length")
	ErrInvalidTimestamp = errors.New("ewp: timestamp out of window")
	ErrInvalidAuth      = errors.New("ewp: authentication failed")
	ErrInvalidAddress   = errors.New("ewp: invalid address")
	ErrDecryptFailed    = errors.New("ewp: decryption failed")
)

type HandshakeRequest struct {
	Version       byte
	Nonce         [12]byte
	Timestamp     uint32
	UUID          [16]byte
	Command       byte
	TargetAddr    Address
	Options       byte
	PaddingLength byte
}

type HandshakeResponse struct {
	VersionEcho byte
	Status      byte
	ServerTime  uint32
	NonceEcho   [12]byte
	AuthTag     [8]byte
}

const (
	StatusOK    byte = 0x00
	StatusError byte = 0x01
)

func NewHandshakeRequest(uuid [16]byte, command byte, addr Address) *HandshakeRequest {
	// 使用 crypto/rand 生成随机 Version (1-255)
	versionBig, _ := rand.Int(rand.Reader, big.NewInt(255))
	version := byte(versionBig.Int64() + 1)
	
	// 使用 crypto/rand 生成随机 Padding 长度
	paddingRange := MaxPaddingLength - MinPaddingLength + 1
	paddingBig, _ := rand.Int(rand.Reader, big.NewInt(int64(paddingRange)))
	paddingLen := byte(paddingBig.Int64() + MinPaddingLength)
	
	req := &HandshakeRequest{
		Version:       version,
		Timestamp:     uint32(time.Now().Unix()),
		UUID:          uuid,
		Command:       command,
		TargetAddr:    addr,
		Options:       0,
		PaddingLength: paddingLen,
	}
	rand.Read(req.Nonce[:])
	return req
}

func (r *HandshakeRequest) Encode() ([]byte, error) {
	// 编码地址
	addrBytes, err := r.TargetAddr.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode address: %w", err)
	}
	
	// 计算 Plaintext 长度: Timestamp(4) + UUID(16) + Command(1) + Addr + Options(1) + PadLen(1) + Padding
	plaintextLen := 4 + 16 + 1 + len(addrBytes) + 1 + 1 + int(r.PaddingLength)
	
	// 预分配完整缓冲区: AD(15) + Ciphertext(plaintext + 16-byte Poly1305 tag) + HMAC(16)
	totalLen := 15 + plaintextLen + 16 + 16
	buf := make([]byte, totalLen)
	
	// === 1. 构建 AD (Authenticated Data) ===
	buf[0] = r.Version
	copy(buf[1:13], r.Nonce[:])
	binary.BigEndian.PutUint16(buf[13:15], uint16(plaintextLen))
	ad := buf[:15]
	
	// === 2. 构建 Plaintext (先临时写入，后续原地加密) ===
	offset := 15
	binary.BigEndian.PutUint32(buf[offset:], r.Timestamp)
	offset += 4
	copy(buf[offset:], r.UUID[:])
	offset += 16
	buf[offset] = r.Command
	offset++
	copy(buf[offset:], addrBytes)
	offset += len(addrBytes)
	buf[offset] = r.Options
	offset++
	buf[offset] = r.PaddingLength
	offset++
	
	// 填充随机 Padding
	rand.Read(buf[offset : offset+int(r.PaddingLength)])
	offset += int(r.PaddingLength)
	
	// === 3. 加密 (ChaCha20-Poly1305) ===
	key := deriveEncryptionKey(r.UUID, r.Nonce)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	
	// Seal 会追加 16 字节 Poly1305 tag
	plaintext := buf[15 : 15+plaintextLen]
	ciphertext := aead.Seal(buf[15:15], r.Nonce[:], plaintext, ad)
	
	// === 4. 计算外层 HMAC (快速熔断器) ===
	authTag := computeHMAC(r.UUID, ad, ciphertext)
	copy(buf[15+len(ciphertext):], authTag)
	
	return buf, nil
}

func DecodeHandshakeRequest(data []byte, validUUIDs [][16]byte) (*HandshakeRequest, error) {
	if len(data) < 15+MinPayloadLength+16 {
		return nil, fmt.Errorf("%w: got %d bytes, need at least %d", ErrInvalidLength, len(data), 15+MinPayloadLength+16)
	}

	version := data[0]
	if version == 0 {
		return nil, ErrInvalidVersion
	}

	var nonce [12]byte
	copy(nonce[:], data[1:13])

	payloadLen := binary.BigEndian.Uint16(data[13:15])
	if payloadLen < MinPayloadLength || payloadLen > MaxPayloadLength {
		return nil, fmt.Errorf("%w: payloadLen=%d (min=%d, max=%d)", ErrInvalidLength, payloadLen, MinPayloadLength, MaxPayloadLength)
	}

	// ciphertextLen = plaintextLen + 16 (Poly1305 tag)
	ciphertextLen := int(payloadLen) + 16
	if len(data) < 15+ciphertextLen+16 {
		return nil, fmt.Errorf("%w: data too short for payload", ErrInvalidLength)
	}

	ad := data[0:15]
	ciphertext := data[15 : 15+ciphertextLen]
	authTag := data[15+ciphertextLen : 15+ciphertextLen+16]

	// 调试：打印收到的数据摘要
	fmt.Printf("[DEBUG] DecodeHandshakeRequest: dataLen=%d, version=%d, payloadLen=%d\n", len(data), version, payloadLen)
	fmt.Printf("[DEBUG] authTag (received): %x\n", authTag)

	for i, uuid := range validUUIDs {
		expectedTag := computeHMAC(uuid, ad, ciphertext)
		fmt.Printf("[DEBUG] UUID[%d] expectedTag: %x\n", i, expectedTag)
		if !hmac.Equal(authTag, expectedTag) {
			continue
		}

		key := deriveEncryptionKey(uuid, nonce)
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			continue
		}

		plaintext, err := aead.Open(nil, nonce[:], ciphertext, ad)
		if err != nil {
			continue
		}

		req := &HandshakeRequest{
			Version: version,
			Nonce:   nonce,
		}

		if len(plaintext) < 4+16+1+1+1+1 {
			continue
		}

		req.Timestamp = binary.BigEndian.Uint32(plaintext[0:4])
		copy(req.UUID[:], plaintext[4:20])
		req.Command = plaintext[20]

		now := time.Now().Unix()
		if math.Abs(float64(int64(req.Timestamp)-now)) > TimeWindow {
			return nil, ErrInvalidTimestamp
		}

		addr, addrLen, err := DecodeAddress(plaintext[21:])
		if err != nil {
			continue
		}
		req.TargetAddr = addr

		offset := 21 + addrLen
		if len(plaintext) < offset+2 {
			continue
		}

		req.Options = plaintext[offset]
		req.PaddingLength = plaintext[offset+1]

		return req, nil
	}

	return nil, ErrInvalidAuth
}

func (r *HandshakeResponse) Encode(uuid [16]byte) ([]byte, error) {
	// 预分配: VersionEcho(1) + Status(1) + ServerTime(4) + NonceEcho(12) + AuthTag(8) = 26 bytes
	buf := make([]byte, 26)
	
	buf[0] = r.VersionEcho
	buf[1] = r.Status
	binary.BigEndian.PutUint32(buf[2:6], r.ServerTime)
	copy(buf[6:18], r.NonceEcho[:])
	
	// 计算 HMAC (前 17 字节)
	tag := computeResponseHMAC(uuid, buf[:17])
	copy(r.AuthTag[:], tag[:8])
	copy(buf[18:26], r.AuthTag[:])
	
	return buf, nil
}

func DecodeHandshakeResponse(data []byte, expectedVersion byte, expectedNonce [12]byte, uuid [16]byte) (*HandshakeResponse, error) {
	if len(data) < 26 {
		return nil, ErrInvalidLength
	}

	resp := &HandshakeResponse{}
	resp.VersionEcho = data[0]
	resp.Status = data[1]
	resp.ServerTime = binary.BigEndian.Uint32(data[2:6])
	copy(resp.NonceEcho[:], data[6:18])
	copy(resp.AuthTag[:], data[18:26])

	if resp.VersionEcho != expectedVersion {
		return nil, ErrInvalidVersion
	}

	if !bytes.Equal(resp.NonceEcho[:], expectedNonce[:]) {
		return nil, ErrInvalidAuth
	}

	expectedTag := computeResponseHMAC(uuid, data[:17])
	if !bytes.Equal(resp.AuthTag[:], expectedTag[:8]) {
		return nil, ErrInvalidAuth
	}

	return resp, nil
}

func NewSuccessResponse(version byte, nonce [12]byte) *HandshakeResponse {
	return &HandshakeResponse{
		VersionEcho: version,
		Status:      StatusOK,
		ServerTime:  uint32(time.Now().Unix()),
		NonceEcho:   nonce,
	}
}

func GenerateFakeResponse() []byte {
	fake := make([]byte, 26)
	rand.Read(fake)
	return fake
}

func deriveEncryptionKey(uuid [16]byte, nonce [12]byte) []byte {
	h := sha256.New()
	h.Write(uuid[:])
	h.Write(nonce[:])
	h.Write([]byte("EWP-ENC-v1"))
	return h.Sum(nil)
}

func computeHMAC(uuid [16]byte, ad, ciphertext []byte) []byte {
	keyHash := sha256.Sum256(uuid[:])
	h := hmac.New(sha256.New, keyHash[:])
	h.Write(ad)
	h.Write(ciphertext)
	sum := h.Sum(nil)
	return sum[:16]
}

func computeResponseHMAC(uuid [16]byte, msg []byte) []byte {
	keyHash := sha256.Sum256(uuid[:])
	h := hmac.New(sha256.New, keyHash[:])
	h.Write(msg)
	return h.Sum(nil)
}

func ReadHandshake(r io.Reader) ([]byte, error) {
	header := make([]byte, 15)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	payloadLen := binary.BigEndian.Uint16(header[13:15])
	if payloadLen < MinPayloadLength || payloadLen > MaxPayloadLength {
		return nil, ErrInvalidLength
	}

	rest := make([]byte, int(payloadLen)+16)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}

	fullData := append(header, rest...)
	return fullData, nil
}
