---
id: "41b36860-5548-4d1b-bcd0-18a0b7f4a448"
title: "P2-33: GUI Reconnect Backoff Jitter / GUI 重连退避加抖动"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:21.031Z"
updatedAt: "2026-04-17T11:28:24.389Z"
type: ticket
---

# P2-33: GUI Reconnect Backoff Jitter / GUI 重连退避加抖动

## 🟡 Severity / 优先级

**P2 — Low** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-gui/src/CoreProcess.cpp `scheduleReconnect` 指数退避 `2^retry`

## 🎯 Description / 漏洞描述与影响

可能等过久(8s),无 jitter 在多客户端场景下可能同时重连造成"惊群"。

## 🔧 Fix / 修复方案

加 jitter:

```cpp
int delay = pow(2, retry) * 1000 + QRandomGenerator::global()->bounded(500);
```

## ✅ Acceptance Criteria / 验收标准

退避加 ±500ms 抖动上限合理(如 30s)

## 🧪 Verification / 验证方法

- **基准测试**: 多次重连分布

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
