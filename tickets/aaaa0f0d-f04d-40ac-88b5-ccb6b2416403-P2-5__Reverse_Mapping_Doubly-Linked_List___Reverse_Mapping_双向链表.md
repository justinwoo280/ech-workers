---
id: "aaaa0f0d-f04d-40ac-88b5-ccb6b2416403"
title: "P2-5: Reverse Mapping Doubly-Linked List / Reverse Mapping 双向链表"
assignee: ""
status: 0
createdAt: "2026-04-17T11:25:59.521Z"
updatedAt: "2026-04-17T11:26:04.120Z"
type: ticket
---

# P2-5: Reverse Mapping Doubly-Linked List / Reverse Mapping 双向链表

## 🟡 Severity / 优先级

**P2 — Low (Performance)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/dns/reverse_mapping.go `removeOrder` O(N)

## 🎯 Description / 漏洞描述与影响

高频更新性能差(O(N) 删除),长跑下 GC 压力大。

## 💥 Reproduction / 复现条件

- 高频 fakeip 替换场景,CPU 因 removeOrder 上升

## 🔧 Fix / 修复方案

用 `container/list` 双向链表,O(1) 删除:

```go
type entry struct { elem *list.Element; ... }
list.Remove(entry.elem)  // O(1)
```

## ✅ Acceptance Criteria / 验收标准

removeOrder 改为 O(1)基准测试性能改善

## 🧪 Verification / 验证方法

- **基准测试**: `BenchmarkReverseMapping`

## 🔗 Dependencies / 依赖关系

- 与 `P1-30` (FakeIP 池) 同模块

## ⚠️ Regression Risk / 回归风险

**低**
