package xhttp

import (
	"crypto/rand"
	"math/big"
	"time"
)

// RangeConfig 随机化配置 - 基于 Xray-core 设计
type RangeConfig struct {
	From int32
	To   int32
}

// Rand 生成随机值
func (c RangeConfig) Rand() int32 {
	if c.From == c.To {
		return c.From
	}
	if c.From > c.To {
		c.From, c.To = c.To, c.From
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(c.To-c.From+1)))
	return c.From + int32(n.Int64())
}

// RandDuration 生成随机时间间隔
func (c RangeConfig) RandDuration() time.Duration {
	return time.Duration(c.Rand()) * time.Millisecond
}

// RandBytes 生成随机字节长度
func (c RangeConfig) RandBytes() []byte {
	length := c.Rand()
	if length <= 0 {
		return nil
	}
	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}
