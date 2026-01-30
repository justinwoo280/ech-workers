package xhttp

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"ewp-core/log"
)

// XmuxConfig 连接池配置 - 基于 Xray-core 设计
type XmuxConfig struct {
	// 连接池配置
	MaxConcurrency *RangeConfig `json:"maxConcurrency"` // 最大并发数
	MaxConnections *RangeConfig `json:"maxConnections"`  // 最大连接数
	
	// 连接生命周期配置
	CMaxReuseTimes *RangeConfig `json:"cMaxReuseTimes"` // 连接最大复用次数
	HMaxRequestTimes *RangeConfig `json:"hMaxRequestTimes"` // HTTP 连接最大请求次数
	HMaxReusableSecs *RangeConfig `json:"hMaxReusableSecs"` // HTTP 连接最大可重用时间(秒)
	
	// Keep-Alive 配置
	HKeepAlivePeriod int64 `json:"hKeepAlivePeriod"` // Keep-Alive 周期(秒)
}

// XmuxConn 连接接口
type XmuxConn interface {
	IsClosed() bool
	Close() error
	GetLastActiveTime() time.Time
	GetRequestCount() int64
	IncrementRequestCount()
}

// XmuxClient 连接池客户端
type XmuxClient struct {
	XmuxConn     XmuxConn
	OpenUsage    atomic.Int32  // 当前并发使用数
	leftUsage    int32         // 剩余使用次数
	LeftRequests atomic.Int32 // 剩余请求次数
	UnreusableAt time.Time     // 过期时间
	CreatedAt    time.Time     // 创建时间
}

// XmuxManager 连接池管理器 - 基于 Xray-core 设计
type XmuxManager struct {
	xmuxConfig  XmuxConfig
	concurrency int32  // 随机并发数
	connections int32  // 随机连接数
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
	mu          sync.RWMutex
	
	// 统计信息
	totalCreated   int64
	totalReused    int64
	totalExpired   int64
	totalClosed    int64
}

// NewXmuxManager 创建连接池管理器
func NewXmuxManager(xmuxConfig XmuxConfig, newConnFunc func() XmuxConn) *XmuxManager {
	return &XmuxManager{
		xmuxConfig:  xmuxConfig,
		concurrency: xmuxConfig.GetNormalizedMaxConcurrency().Rand(),
		connections: xmuxConfig.GetNormalizedMaxConnections().Rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
	}
}

// newXmuxClient 创建新的连接池客户端
func (m *XmuxManager) newXmuxClient() *XmuxClient {
	xmuxClient := &XmuxClient{
		XmuxConn:  m.newConnFunc(),
		leftUsage: -1, // -1 表示无限制
		CreatedAt: time.Now(),
	}
	
	// 设置连接复用次数限制
	if x := m.xmuxConfig.GetNormalizedCMaxReuseTimes().Rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	
	// 设置请求次数限制
	xmuxClient.LeftRequests.Store(math.MaxInt32)
	if x := m.xmuxConfig.GetNormalizedHMaxRequestTimes().Rand(); x > 0 {
		xmuxClient.LeftRequests.Store(x)
	}
	
	// 设置过期时间
	if x := m.xmuxConfig.GetNormalizedHMaxReusableSecs().Rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	
	m.mu.Lock()
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	atomic.AddInt64(&m.totalCreated, 1)
	m.mu.Unlock()
	
	log.V("[XHTTP] XMUX: created new client, total: %d", len(m.xmuxClients))
	return xmuxClient
}

// GetXmuxClient 获取可用的连接池客户端
func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// 清理过期/已关闭的连接
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		
		if xmuxClient.XmuxConn.IsClosed() ||
			xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(xmuxClient.UnreusableAt != time.Time{} && time.Now().After(xmuxClient.UnreusableAt)) {
			
			log.V("[XHTTP] XMUX: removing client - closed=%v, usage=%d, requests=%d, expired=%v",
				xmuxClient.XmuxConn.IsClosed(),
				xmuxClient.leftUsage,
				xmuxClient.LeftRequests.Load(),
				time.Now().After(xmuxClient.UnreusableAt))
			
			// 关闭连接
			xmuxClient.XmuxConn.Close()
			atomic.AddInt64(&m.totalClosed, 1)
			
			// 从切片中移除
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
		} else {
			i++
		}
	}
	
	// 如果没有可用连接，创建新连接
	if len(m.xmuxClients) == 0 {
		log.V("[XHTTP] XMUX: creating client - pool empty")
		return m.newXmuxClient()
	}
	
	// 如果连接数未达到上限，创建新连接
	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		log.V("[XHTTP] XMUX: creating client - connections: %d/%d", len(m.xmuxClients), m.connections)
		return m.newXmuxClient()
	}
	
	// 筛选可用连接（并发数限制）
	availableClients := make([]*XmuxClient, 0)
	if m.concurrency > 0 {
		for _, xmuxClient := range m.xmuxClients {
			if xmuxClient.OpenUsage.Load() < m.concurrency {
				availableClients = append(availableClients, xmuxClient)
			}
		}
	} else {
		availableClients = m.xmuxClients
	}
	
	// 如果没有可用连接（达到并发限制），创建新连接
	if len(availableClients) == 0 {
		log.V("[XHTTP] XMUX: creating client - concurrency limit hit: %d", m.concurrency)
		return m.newXmuxClient()
	}
	
	// 随机选择一个连接
	i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(availableClients))))
	xmuxClient := availableClients[i.Int64()]
	
	// 更新使用统计
	if xmuxClient.leftUsage > 0 {
		xmuxClient.leftUsage--
	}
	xmuxClient.LeftRequests.Add(-1)
	
	atomic.AddInt64(&m.totalReused, 1)
	log.V("[XHTTP] XMUX: reused client, usage left: %d, requests left: %d",
		xmuxClient.leftUsage, xmuxClient.LeftRequests.Load())
	
	return xmuxClient
}

// GetStats 获取连接池统计信息
func (m *XmuxManager) GetStats() map[string]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	return map[string]int64{
		"total_created":  atomic.LoadInt64(&m.totalCreated),
		"total_reused":   atomic.LoadInt64(&m.totalReused),
		"total_expired":  atomic.LoadInt64(&m.totalExpired),
		"total_closed":   atomic.LoadInt64(&m.totalClosed),
		"active_clients": int64(len(m.xmuxClients)),
		"max_concurrency": int64(m.concurrency),
		"max_connections": int64(m.connections),
	}
}

// Close 关闭连接池管理器
func (m *XmuxManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for _, xmuxClient := range m.xmuxClients {
		xmuxClient.XmuxConn.Close()
	}
	
	m.xmuxClients = make([]*XmuxClient, 0)
	log.V("[XHTTP] XMUX: manager closed")
	return nil
}

// 配置标准化方法
func (c *XmuxConfig) GetNormalizedMaxConcurrency() RangeConfig {
	if c.MaxConcurrency == nil || c.MaxConcurrency.To == 0 {
		return RangeConfig{From: 0, To: 0} // 0 表示无限制
	}
	return *c.MaxConcurrency
}

func (c *XmuxConfig) GetNormalizedMaxConnections() RangeConfig {
	if c.MaxConnections == nil || c.MaxConnections.To == 0 {
		return RangeConfig{From: 1, To: 3} // 默认 1-3 个连接
	}
	return *c.MaxConnections
}

func (c *XmuxConfig) GetNormalizedCMaxReuseTimes() RangeConfig {
	if c.CMaxReuseTimes == nil || c.CMaxReuseTimes.To == 0 {
		return RangeConfig{From: 0, To: 0} // 0 表示无限制
	}
	return *c.CMaxReuseTimes
}

func (c *XmuxConfig) GetNormalizedHMaxRequestTimes() RangeConfig {
	if c.HMaxRequestTimes == nil || c.HMaxRequestTimes.To == 0 {
		return RangeConfig{From: 100, To: 200} // 默认每个连接处理 100-200 个请求
	}
	return *c.HMaxRequestTimes
}

func (c *XmuxConfig) GetNormalizedHMaxReusableSecs() RangeConfig {
	if c.HMaxReusableSecs == nil || c.HMaxReusableSecs.To == 0 {
		return RangeConfig{From: 300, To: 600} // 默认 5-10 分钟
	}
	return *c.HMaxReusableSecs
}
