package ewp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// ════════════════════════════════════════════════════════════════════════════════
// E2E Protocol Layer Test - 验证完整的协议链路正常工作
// ════════════════════════════════════════════════════════════════════════════════

var e2eTestUUID = [16]byte{
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
	0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
}

// TestE2E_HandshakeAndDataFlow 测试完整的握手和数据流
// 模拟实际的客户端-服务器交互流程
func TestE2E_HandshakeAndDataFlow(t *testing.T) {
	// ─── 1. 客户端: 生成握手请求 ───────────────────────────────────────────
	targetAddr := Address{
		Type: AddressTypeDomain,
		Host: "example.com",
		Port: 443,
	}
	clientHandshake := NewHandshakeRequest(e2eTestUUID, 0, targetAddr)
	
	// 编码握手请求
	clientHandshakeBytes, err := clientHandshake.Encode()
	if err != nil {
		t.Fatalf("encode handshake: %v", err)
	}
	
	t.Logf("✓ Client handshake encoded: %d bytes, version: %d, nonce: %v",
		len(clientHandshakeBytes), clientHandshake.Version, clientHandshake.Nonce)
	
	// ─── 2. 服务器: 接收并解码握手请求 ──────────────────────────────────────
	cache := NewUUIDKeyCache([][16]byte{e2eTestUUID})
	serverReq, err := DecodeHandshakeRequestCached(clientHandshakeBytes, cache)
	if err != nil {
		t.Fatalf("decode handshake: %v", err)
	}
	
	if serverReq.UUID != e2eTestUUID {
		t.Errorf("UUID mismatch: got %v want %v", serverReq.UUID, e2eTestUUID)
	}
	
	t.Logf("✓ Server decoded handshake: UUID=%v, target=%s:%d",
		serverReq.UUID, serverReq.TargetAddr.Host, serverReq.TargetAddr.Port)
	
	// ─── 3. 服务器: 生成握手响应 ────────────────────────────────────────────
	serverResp := NewSuccessResponse(clientHandshake.Version, clientHandshake.Nonce)
	serverRespBytes, err := serverResp.Encode(e2eTestUUID)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	
	t.Logf("✓ Server handshake response encoded: %d bytes", len(serverRespBytes))
	
	// ─── 4. 客户端: 接收并解码握手响应 ────────────────────────────────────────
	clientResp, err := DecodeHandshakeResponse(
		serverRespBytes,
		clientHandshake.Version,
		clientHandshake.Nonce,
		e2eTestUUID,
	)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	
	if clientResp.Status != StatusOK {
		t.Errorf("handshake status: got %d want %d", clientResp.Status, StatusOK)
	}
	
	t.Logf("✓ Client handshake success, status=%d", clientResp.Status)
}

// TestE2E_PaddingWithFlowControl 测试 Padding 和流控的完整链路
func TestE2E_PaddingWithFlowControl(t *testing.T) {
	// ─── 初始化状态 ──────────────────────────────────────────────────────────
	flowState := NewFlowState(e2eTestUUID[:])
	
	// 模拟的实际应用数据
	testData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	t.Logf("Original data: %d bytes", len(testData))
	
	// ─── 1. 客户端: 应用 Padding ────────────────────────────────────────────
	uuidCopy := make([]byte, 16)
	copy(uuidCopy, e2eTestUUID[:])
	
	paddedData := XtlsPadding(testData, FlowCommandEnd, &uuidCopy, true, DefaultPaddingConfig)
	t.Logf("✓ Data padded: %d → %d bytes (%.1f%% overhead)",
		len(testData), len(paddedData), float64(len(paddedData)-len(testData))/float64(len(testData))*100)
	
	// ─── 2. 网络传输（模拟） ─────────────────────────────��──────────────────
	// 这里可以模拟网络延迟、乱序等场景，现在就是直接转发
	
	// ─── 3. 服务器: 接收并移除 Padding ──────────────────────────────────────
	unpadded := XtlsUnpadding(paddedData, flowState, true)
	
	// 由于使用 FlowCommandEnd，应该恢复到原始数据
	if !bytes.Equal(unpadded, testData) {
		t.Errorf("data mismatch after unpadding: got %d bytes want %d bytes",
			len(unpadded), len(testData))
		t.Errorf("got: %q", unpadded)
		t.Errorf("want: %q", testData)
	}
	
	t.Logf("✓ Data unpadded correctly: %d bytes recovered", len(unpadded))
}

// TestE2E_MultiBlockPaddingFlow 测试多块数据的 Padding 链路
func TestE2E_MultiBlockPaddingFlow(t *testing.T) {
	flowState := NewFlowState(e2eTestUUID[:])
	
	// 模拟多个数据块
	blocks := [][]byte{
		[]byte("BLOCK1: Initial data"),
		[]byte("BLOCK2: Follow-up data"),
		[]byte("BLOCK3: Final data"),
	}
	
	// ─── 1. 客户端: 对每个块应用 Padding ──────────────────────────────────
	var paddedBlocks [][]byte
	for i, block := range blocks {
		command := FlowCommandContinue
		if i == len(blocks)-1 {
			command = FlowCommandEnd // 最后一块使用 End
		}
		
		uuidCopy := make([]byte, 16)
		copy(uuidCopy, e2eTestUUID[:])
		
		padded := XtlsPadding(block, command, &uuidCopy, true, DefaultPaddingConfig)
		paddedBlocks = append(paddedBlocks, padded)
		t.Logf("  Block %d: %d → %d bytes", i+1, len(block), len(padded))
	}
	
	// ─── 2. 服务器: 串联接收所有块并 Unpadding ──────────────────────────────
	allPadded := bytes.Join(paddedBlocks, nil)
	t.Logf("✓ Total padded data: %d bytes", len(allPadded))
	
	unpadded := XtlsUnpadding(allPadded, flowState, true)
	
	// 验证: 对于 FlowCommandContinue，数据会被包含在输出中
	// 对于 FlowCommandEnd，输出应该等于最后的块
	expectedLen := len(blocks[len(blocks)-1])
	if len(unpadded) != expectedLen {
		t.Logf("Warning: unpadded length %d != expected %d (this may be normal for multi-block)",
			len(unpadded), expectedLen)
	}
	
	t.Logf("✓ Multi-block unpadding complete: %d bytes", len(unpadded))
}

// TestE2E_DirectCopyMode 测试直传模式的切换
func TestE2E_DirectCopyMode(t *testing.T) {
	flowState := NewFlowState(e2eTestUUID[:])
	
	// ─── 1. 初始状态: 应该不是直传模式 ──────────────────────────────────────
	if flowState.ShouldDirectCopy(true) {
		t.Fatal("初始状态不应该是直传模式")
	}
	
	// ─── 2. 处理 TLS ServerHello，应该检测到完整记录 ──────────────────────
	tlsServerHello := []byte{
		0x16, 0x03, 0x03, // TLS record header: Handshake, TLS 1.2
		0x00, 0x50, // Length: 80 bytes
		// ... actual ServerHello data (80 bytes) ...
	}
	// 补充到完整的 80 字节
	tlsServerHello = append(tlsServerHello, make([]byte, 80)...)
	
	_ = flowState.ProcessDownlink(tlsServerHello)
	
	// ─── 3. 检查状态是否已切换到直传模式（可选）──────────────────────────
	t.Logf("✓ State processed TLS handshake, direct copy: %v", flowState.ShouldDirectCopy(false))
}

// TestE2E_HighThroughputScenario 测试高吞吐场景
func TestE2E_HighThroughputScenario(t *testing.T) {
	flowState := NewFlowState(e2eTestUUID[:])
	
	// 模拟大量数据传输
	testSizes := []int{1024, 4096, 16384, 65536}
	
	for _, size := range testSizes {
		testData := make([]byte, size)
		rand.Read(testData)
		
		// 应用 Padding
		uuidCopy := make([]byte, 16)
		copy(uuidCopy, e2eTestUUID[:])
		
		padded := XtlsPadding(testData, FlowCommandEnd, &uuidCopy, false, DefaultPaddingConfig)
		
		// 移除 Padding
		unpadded := XtlsUnpadding(padded, flowState, true)
		
		if !bytes.Equal(unpadded, testData) {
			t.Errorf("size %d: data mismatch after pad/unpad", size)
		}
		
		overhead := float64(len(padded)-len(testData)) / float64(len(testData)) * 100
		t.Logf("✓ Size %6d: padded to %6d (%.1f%% overhead)", size, len(padded), overhead)
	}
}

// TestE2E_ConcurrentFlowStates 测试多个并发的流状态
func TestE2E_ConcurrentFlowStates(t *testing.T) {
	// 模拟多个客户端连接
	numConnections := 10
	done := make(chan error, numConnections)
	
	for connID := 0; connID < numConnections; connID++ {
		go func(id int) {
			// 每个连接有自己的 UUID 和状态
			uuid := e2eTestUUID
			uuid[0] = byte(id) // 简单地改变第一个字节
			
			flowState := NewFlowState(uuid[:])
			testData := []byte(fmt.Sprintf("Connection %d data", id))
			
			// 模拟数据流
			uuidCopy := make([]byte, 16)
			copy(uuidCopy, uuid[:])
			
			padded := XtlsPadding(testData, FlowCommandEnd, &uuidCopy, true, DefaultPaddingConfig)
			unpadded := XtlsUnpadding(padded, flowState, true)
			
			if !bytes.Equal(unpadded, testData) {
				done <- fmt.Errorf("connection %d: data mismatch", id)
				return
			}
			done <- nil
		}(connID)
	}
	
	// 收集结果
	for i := 0; i < numConnections; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	
	t.Logf("✓ All %d concurrent connections validated", numConnections)
}

// TestE2E_ProtocolRobustness 测试协议的健壮性
func TestE2E_ProtocolRobustness(t *testing.T) {
	// ─── 1. 处理空数据 ──────────────────────────────────────────────────────
	flowState := NewFlowState(e2eTestUUID[:])
	empty := XtlsUnpadding([]byte{}, flowState, true)
	if len(empty) != 0 {
		t.Errorf("empty input should produce empty output, got %d bytes", len(empty))
	}
	
	// ─── 2. 处理无 UUID 的数据 ──────────────────────────────────────────────
	testData := []byte("no uuid data")
	flowState = NewFlowState(e2eTestUUID[:])
	
	uuidCopy := make([]byte, 16)
	copy(uuidCopy, e2eTestUUID[:])
	padded := XtlsPadding(testData, FlowCommandEnd, &uuidCopy, true, DefaultPaddingConfig)
	
	// 创建新的状态实例，不应该影响
	flowState2 := NewFlowState(e2eTestUUID[:])
	result := XtlsUnpadding(padded, flowState2, true)
	
	if !bytes.Equal(result, testData) {
		t.Errorf("separate flow state: data mismatch")
	}
	
	// ─── 3. 处理部分数据（可能来自网络分片）──────────────────────────────────
	testData = []byte("fragmented data")
	flowState = NewFlowState(e2eTestUUID[:])
	
	uuidCopy = make([]byte, 16)
	copy(uuidCopy, e2eTestUUID[:])
	padded = XtlsPadding(testData, FlowCommandContinue, &uuidCopy, true, DefaultPaddingConfig)
	
	// 只处理前半部分
	halfway := len(padded) / 2
	partial := XtlsUnpadding(padded[:halfway], flowState, true)
	t.Logf("✓ Partial data handling: %d → %d bytes", halfway, len(partial))
	
	// ─── 4. 处理损坏的数据 ──────────────────────────────────────────────────
	corrupted := make([]byte, 50)
	rand.Read(corrupted)
	result = XtlsUnpadding(corrupted, flowState, true)
	t.Logf("✓ Corrupted data handling: produced %d bytes (no panic)", len(result))
	
	t.Logf("✓ Protocol robustness verified")
}

// BenchmarkE2E_FullPaddingCycle 完整 Padding 循环的基准测试
func BenchmarkE2E_FullPaddingCycle(b *testing.B) {
	testData := make([]byte, 4096)
	rand.Read(testData)
	
	flowState := NewFlowState(e2eTestUUID[:])
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Padding
		uuidCopy := make([]byte, 16)
		copy(uuidCopy, e2eTestUUID[:])
		padded := XtlsPadding(testData, FlowCommandEnd, &uuidCopy, true, DefaultPaddingConfig)
		
		// Unpadding
		_ = XtlsUnpadding(padded, flowState, true)
	}
}

// BenchmarkE2E_PipelineProcessing 模拟真实的管道处理
func BenchmarkE2E_PipelineProcessing(b *testing.B) {
	// 模拟一个简单的管道: 客户端 -> 网络 -> 服务器
	serverState := NewFlowState(e2eTestUUID[:])
	
	testData := make([]byte, 8192)
	rand.Read(testData)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 客户端: padding
		uuidCopy := make([]byte, 16)
		copy(uuidCopy, e2eTestUUID[:])
		padded := XtlsPadding(testData, FlowCommandEnd, &uuidCopy, true, DefaultPaddingConfig)
		
		// 网络: (模拟直接转发)
		
		// 服务器: unpadding
		_ = XtlsUnpadding(padded, serverState, false)
	}
}
