---
id: "bfae2648-e471-4b5c-b55b-5a8aa22dd3de"
title: "P1-14: Vision Counter Per-Direction / Vision 双向独立计数器"
assignee: ""
status: 0
createdAt: "2026-04-17T11:22:48.243Z"
updatedAt: "2026-04-17T11:22:56.914Z"
type: ticket
---

# P1-14: Vision Counter Per-Direction / Vision 双向独立计数器

## 🟠 Severity / 优先级

**P1 — High (Filter Window Exhaustion)** | Sprint 4 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/ewp/flow_state.go `ProcessUplink` 与 `ProcessDownlink` 共用同一计数器

## 🎯 Description / 漏洞描述与影响

8 个包窗口被两方向**共享**,TLS 握手通常 6+ 包 RTT,容易窗口耗尽前观察不全。

## 💥 Reproduction / 复现条件

1. TLS 握手:Client Hello (1 up) + Server Hello+Cert+Done (4 down) + Client Key+CCS (2 up) = 7 包
2. 计数器从 8 减到 1,但 TLS 识别可能尚未完成
3. 后续 App Data 错过识别窗口

## 🔧 Fix / 修复方案

改为分方向独立计数;参考 Xray 的实现:

```go
type FlowState struct {
    uplinkPacketsLeft   int
    downlinkPacketsLeft int
    // ...
}
```

## ✅ Acceptance Criteria / 验收标准

uplink/downlink 各有独立计数器(默认各 8)完整 TLS 握手能在窗口内被识别不影响 P0-3 修复的 direct-copy 切换

## 🧪 Verification / 验证方法

- **单元测试**: 模拟 1up + 4down + 2up 握手,断言两方向均成功识别 TLS
- **e2e**: 与 Xray 服务端互操作测试

## 🔗 Dependencies / 依赖关系

- 与 `P1-13` 紧耦合,应一并修复
- 与 `P0-3` 同模块

## ⚠️ Regression Risk / 回归风险

**中**: 同 P1-13 的回归风险
