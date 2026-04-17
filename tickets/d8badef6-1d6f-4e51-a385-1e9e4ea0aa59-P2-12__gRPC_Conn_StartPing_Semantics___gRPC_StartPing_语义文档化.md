---
id: "d8badef6-1d6f-4e51-a385-1e9e4ea0aa59"
title: "P2-12: gRPC Conn StartPing Semantics / gRPC StartPing 语义文档化"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:40.476Z"
updatedAt: "2026-04-17T11:26:43.911Z"
type: ticket
---

# P2-12: gRPC Conn StartPing Semantics / gRPC StartPing 语义文档化

## 🟡 Severity / 优先级

**P2 — Low** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/transport/grpc/transport.go `Conn.StartPing` 返回空 channel

## 🎯 Description / 漏洞描述与影响

接口语义不一致 — 其他 transport 的 StartPing 返回有意义 channel,gRPC 返回空。

## 🔧 Fix / 修复方案

- 文档说明依赖 H2 keepalive
- 或实现 ping 帧

## ✅ Acceptance Criteria / 验收标准

注释明确说明依赖 H2 keepalive接口契约一致

## 🧪 Verification / 验证方法

- **代码审查**

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
