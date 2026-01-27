package bufferpool

import (
	"sync"

	"ewp-core/constant"
)

var (
	// SmallPool for small buffers (512 bytes)
	SmallPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, constant.SmallBufferSize)
			return &buf
		},
	}

	// LargePool for large buffers (32KB)
	LargePool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, constant.LargeBufferSize)
			return &buf
		},
	}

	// UDPPool for UDP buffers (64KB)
	UDPPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, constant.UDPBufferSize)
			return &buf
		},
	}
)

// GetSmall returns a small buffer from the pool
func GetSmall() []byte {
	return *SmallPool.Get().(*[]byte)
}

// PutSmall returns a small buffer to the pool
func PutSmall(buf []byte) {
	if cap(buf) >= constant.SmallBufferSize {
		buf = buf[:constant.SmallBufferSize]
		SmallPool.Put(&buf)
	}
}

// GetLarge returns a large buffer from the pool
func GetLarge() []byte {
	return *LargePool.Get().(*[]byte)
}

// PutLarge returns a large buffer to the pool
func PutLarge(buf []byte) {
	if cap(buf) >= constant.LargeBufferSize {
		buf = buf[:constant.LargeBufferSize]
		LargePool.Put(&buf)
	}
}

// GetUDP returns a UDP buffer from the pool
func GetUDP() []byte {
	return *UDPPool.Get().(*[]byte)
}

// PutUDP returns a UDP buffer to the pool
func PutUDP(buf []byte) {
	if cap(buf) >= constant.UDPBufferSize {
		buf = buf[:constant.UDPBufferSize]
		UDPPool.Put(&buf)
	}
}
