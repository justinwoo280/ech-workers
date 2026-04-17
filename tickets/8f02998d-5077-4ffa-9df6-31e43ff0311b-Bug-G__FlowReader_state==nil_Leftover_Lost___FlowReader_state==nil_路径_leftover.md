---
id: "8f02998d-5077-4ffa-9df6-31e43ff0311b"
title: "Bug-G: FlowReader state==nil Leftover Lost / FlowReader state==nil 路径 leftover"
assignee: ""
status: 0
createdAt: "2026-04-17T11:30:02.910Z"
updatedAt: "2026-04-17T11:30:08.418Z"
type: ticket
---

# Bug-G: FlowReader state==nil Leftover Lost / FlowReader state==nil 路径 leftover

## 🔵 Severity / 优先级

**Bug — Low (Edge Case)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/ewp/flow_writer.go `FlowReader.Read` line 113

## 🎯 Description / 漏洞描述与影响

`if r.state == nil { return r.reader.Read(p) }` — 若上一次有 leftover 但 state 变 nil(理论上不太可能),leftover 会被遗忘。**边缘情况,实际不太触发**。

## 💥 Reproduction / 复现条件

- state 变 nil 的路径不明确,实际可能不触发
- 防御性编程

## 🔧 Fix / 修复方案

state==nil 路径也要先消费 leftover:

```go
if r.state == nil {
    if len(r.leftover) > 0 { ... }
    return r.reader.Read(p)
}
```

## ✅ Acceptance Criteria / 验收标准

state==nil 时 leftover 被正确消费单元测试覆盖

## 🧪 Verification / 验证方法

- **单元测试**: 构造 state nil + 有 leftover 场景

## 🔗 Dependencies / 依赖关系

- 与 `P0-3` (Vision FlowReader) 同模块,可一并修复

## ⚠️ Regression Risk / 回归风险

**极低**
