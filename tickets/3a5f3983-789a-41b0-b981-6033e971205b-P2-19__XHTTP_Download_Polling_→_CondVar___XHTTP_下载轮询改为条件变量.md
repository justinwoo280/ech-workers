---
id: "3a5f3983-789a-41b0-b981-6033e971205b"
title: "P2-19: XHTTP Download Polling → CondVar / XHTTP 下载轮询改为条件变量"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:14.496Z"
updatedAt: "2026-04-17T11:27:17.962Z"
type: ticket
---

# P2-19: XHTTP Download Polling → CondVar / XHTTP 下载轮询改为条件变量

## 🟡 Severity / 优先级

**P2 — Low (CPU Waste)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/xhttp_handler.go `xhttpDownloadHandler` polling 50ms

## 🎯 Description / 漏洞描述与影响

50ms 轮询持续消耗 CPU。

## 🔧 Fix / 修复方案

用 `sync.Cond` 或 channel 代替 polling:

```go
session.cond.Wait()  // 数据就绪时被 broadcast
```

## ✅ Acceptance Criteria / 验收标准

下载 handler 不再 pollingCPU 消耗下降

## 🧪 Verification / 验证方法

- **基准测试**: idle 状态 CPU 占用对比

## 🔗 Dependencies / 依赖关系

- 与 `P0-7` (Session Limit) 同模块

## ⚠️ Regression Risk / 回归风险

**低**
