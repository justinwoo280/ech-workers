---
id: "c6608599-1cf9-4954-bcbe-534abf7a941a"
title: "P1-17: Mobile ProtectSocket Failure → Error / Mobile Protect 失败传递错误"
assignee: ""
status: 0
createdAt: "2026-04-17T11:23:18.013Z"
updatedAt: "2026-04-17T11:23:27.269Z"
type: ticket
---

# P1-17: Mobile ProtectSocket Failure → Error / Mobile Protect 失败传递错误

## 🟠 Severity / 优先级

**P1 — High (Routing Loop)** | Sprint 4 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/ewpmobile/protect_dialer.go line 11-15

## 🎯 Description / 漏洞描述与影响

当前代码:

```go
c.Control(func(fd uintptr) { ProtectSocket(int(fd)) })
return nil
```

Protect 失败时仍返回 nil,VPN 流量循环回 TUN(**死循环 / OOM / 电池耗尽**)。

## 💥 Reproduction / 复现条件

1. Android VpnService.protect 偶发失败(如系统 bug)
2. socket 未被 protect
3. socket 流量再次进入 TUN
4. TUN 又走代理,代理 dial 又创建未 protect socket
5. 死循环,内存与电池耗尽

## 🔧 Fix / 修复方案

`ProtectSocket` 失败时让 Control 返回 error,Dial 立即失败:

```go
return c.Control(func(fd uintptr) {
    if !ProtectSocket(int(fd)) { /* 设置 closure 错误标志 */ }
})
// ↓
// 由 Control 返回 error
```

## ✅ Acceptance Criteria / 验收标准

ProtectSocket 失败时 Dial 立即失败,带明确错误不再静默 swallow 错误应用层有 metric/log 记录 protect 失败次数

## 🧪 Verification / 验证方法

- **单元测试**: mock ProtectSocket 返回 false,断言 Dial 失败
- **手工验证**: 模拟 protect 失败场景,观察是否立即停止而非循环

## 🔗 Dependencies / 依赖关系

- 与 `P1-1` (TUN 模式 ECH) 同类的死循环类问题

## ⚠️ Regression Risk / 回归风险

**低**
