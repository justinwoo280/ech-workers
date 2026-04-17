---
id: "40ff6b69-b89a-4c26-a479-1e03b0ed66fd"
title: "Bug-C: XHTTP Handshake Response Timing / XHTTP 握手响应时序差异"
assignee: ""
status: 0
createdAt: "2026-04-17T11:29:22.296Z"
updatedAt: "2026-04-17T11:29:31.640Z"
type: ticket
---

# Bug-C: XHTTP Handshake Response Timing / XHTTP 握手响应时序差异

## 🔵 Severity / 优先级

**Bug — Medium (Defense Depth)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/xhttp_handler.go `xhttpHandshakeHandler` line 286-291

## 🎯 Description / 漏洞描述与影响

- `HandleEWPHandshakeBinary` 失败:返回 400 + respData(假响应),**快**
- 成功但后续 dial 失败:返回 502,**慢**
- DPI 可通过响应时间区分"用户真实/虚假"

## 💥 Reproduction / 复现条件

1. 攻击者大量请求,部分用合法 UUID + 不可解析目标,部分用错 UUID
2. 响应时间分布有显著差异
3. 标记真实用户

## 🔧 Fix / 修复方案

统一响应时序:

- 失败时也 sleep 模拟 dial 延迟,或
- 成功时立即返回握手响应,dial 异步进行

```go
// 示意:固定 timing 窗口
timing := time.NewTimer(uniformDelay)
// ... 处理
<-timing.C; w.Write(resp)
```

## ✅ Acceptance Criteria / 验收标准

真假响应时序统计上不可区分不影响正常握手延迟

## 🧪 Verification / 验证方法

- **统计测试**: 1000 真假请求,响应时间分布对比

## 🔗 Dependencies / 依赖关系

- 与 `P1-29` (假响应长度区分) 是同类防御深度

## ⚠️ Regression Risk / 回归风险

**低**

</TRAYCER_TICKET>
