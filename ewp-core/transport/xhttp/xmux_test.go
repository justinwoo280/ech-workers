package xhttp

import (
	"testing"
	"time"
)

// TestXmuxManager 测试 XmuxManager 基本功能
func TestXmuxManager(t *testing.T) {
	// 创建测试配置
	config := XmuxConfig{
		MaxConcurrency:  &RangeConfig{From: 2, To: 3},
		MaxConnections:  &RangeConfig{From: 1, To: 2},
		CMaxReuseTimes:  &RangeConfig{From: 5, To: 10},
		HMaxRequestTimes: &RangeConfig{From: 10, To: 20},
		HMaxReusableSecs: &RangeConfig{From: 60, To: 120},
		HKeepAlivePeriod: 30,
	}

	// 创建连接池管理器
	manager := NewXmuxManager(config, func() XmuxConn {
		return &mockXmuxConn{}
	})

	defer manager.Close()

	// 测试获取连接
	client1 := manager.GetXmuxClient(nil)
	if client1 == nil {
		t.Error("Failed to get xmux client")
	}

	client2 := manager.GetXmuxClient(nil)
	if client2 == nil {
		t.Error("Failed to get xmux client")
	}

	// 检查统计信息
	stats := manager.GetStats()
	if stats["total_created"] < 1 {
		t.Error("Expected at least 1 created client")
	}

	t.Logf("Xmux Stats: %+v", stats)
}

// TestXmuxConfigNormalization 测试配置标准化
func TestXmuxConfigNormalization(t *testing.T) {
	config := XmuxConfig{}

	// 测试默认值
	if config.GetNormalizedMaxConcurrency().To != 0 {
		t.Error("Expected default max concurrency to be 0 (unlimited)")
	}

	if config.GetNormalizedMaxConnections().From != 1 || config.GetNormalizedMaxConnections().To != 3 {
		t.Error("Expected default max connections to be 1-3")
	}

	if config.GetNormalizedCMaxReuseTimes().To != 0 {
		t.Error("Expected default reuse times to be 0 (unlimited)")
	}

	if config.GetNormalizedHMaxRequestTimes().From != 100 || config.GetNormalizedHMaxRequestTimes().To != 200 {
		t.Error("Expected default request times to be 100-200")
	}

	if config.GetNormalizedHMaxReusableSecs().From != 300 || config.GetNormalizedHMaxReusableSecs().To != 600 {
		t.Error("Expected default reusable seconds to be 300-600")
	}
}

// mockXmuxConn 模拟连接实现
type mockXmuxConn struct {
	closed      bool
	lastActive  time.Time
	requestCount int64
}

func (m *mockXmuxConn) IsClosed() bool {
	return m.closed
}

func (m *mockXmuxConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockXmuxConn) GetLastActiveTime() time.Time {
	return m.lastActive
}

func (m *mockXmuxConn) GetRequestCount() int64 {
	return m.requestCount
}

func (m *mockXmuxConn) IncrementRequestCount() {
	m.requestCount++
	m.lastActive = time.Now()
}

// TestRangeConfigRand 测试随机化配置
func TestRangeConfigRand(t *testing.T) {
	config := RangeConfig{From: 10, To: 20}
	
	// 测试多次随机生成
	for i := 0; i < 100; i++ {
		val := config.Rand()
		if val < 10 || val > 20 {
			t.Errorf("Random value %d out of range [10, 20]", val)
		}
	}

	// 测试相同值
	sameConfig := RangeConfig{From: 15, To: 15}
	for i := 0; i < 10; i++ {
		val := sameConfig.Rand()
		if val != 15 {
			t.Errorf("Expected 15, got %d", val)
		}
	}
}
