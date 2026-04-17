---
id: "66b203d3-a697-4c8e-986f-34d49a7daa32"
title: "P2-38: TFO Actual Activation / TFO 真正启用"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:47.051Z"
updatedAt: "2026-04-17T11:28:54.239Z"
type: ticket
---

# P2-38: TFO Actual Activation / TFO 真正启用

## 🟡 Severity / 优先级

**P2 — Low (Misleading Feature)** | Sprint 5 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-core/common/net/tfo.go 与各平台 `tfo_*.go`

## 🎯 Description / 漏洞描述与影响

仅设置了 sockopt,但用 `Dial`/`DialContext` 普通拨号,**未实际发起带数据的 SYN**。功能名不副实。

## 🔧 Fix / 修复方案

- 用 `tfo-go` 库或自己实现 sendto+MSG_FASTOPEN
- 或文档明确说明当前实现不真正启用 TFO

```go
// 示意
n, err := syscall.Sendto(fd, firstData, syscall.MSG_FASTOPEN, addr)
```

## ✅ Acceptance Criteria / 验收标准

选项 A: 真正实现 TFO(带数据 SYN)选项 B: 移除 TFO 选项,文档说明不再误导用户

## 🧪 Verification / 验证方法

- **抓包**: 验证 SYN 是否含数据 payload

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**中**: 真正 TFO 在某些 NAT 后不通
