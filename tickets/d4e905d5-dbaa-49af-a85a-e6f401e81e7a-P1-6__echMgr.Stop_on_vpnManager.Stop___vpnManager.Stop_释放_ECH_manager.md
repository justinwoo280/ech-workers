---
id: "d4e905d5-dbaa-49af-a85a-e6f401e81e7a"
title: "P1-6: echMgr.Stop on vpnManager.Stop / vpnManager.Stop 释放 ECH manager"
assignee: ""
status: 0
createdAt: "2026-04-17T11:21:26.009Z"
updatedAt: "2026-04-17T11:21:33.903Z"
type: ticket
---

# P1-6: echMgr.Stop on vpnManager.Stop / vpnManager.Stop 释放 ECH manager

## 🟠 Severity / 优先级

**P1 — High (Goroutine Leak)** | Sprint 3 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/ewpmobile/vpn_manager.go `Stop` 完全未引用 `echMgr`

## 🎯 Description / 漏洞描述与影响

每次断开+重连 VPN 都创建一个新 echMgr,旧 echMgr 的 cleanupLoop goroutine **永久泄漏**。长时间使用累积。

## 💥 Reproduction / 复现条件

1. 移动端连接 VPN → 断开 → 重连,循环 100 次
2. pprof goroutine dump 显示 100 个 cleanupLoop goroutine 残留

## 🔧 Fix / 修复方案

vpnManager 持有 echMgr 引用,Stop 时调用 `echMgr.Stop()`:

```go
func (vm *vpnManager) Stop() {
    if vm.echMgr != nil { vm.echMgr.Stop(); vm.echMgr = nil }
    // ... 其他清理
}
```

## ✅ Acceptance Criteria / 验收标准

vpnManager.Stop() 显式调用 echMgr.Stop()echMgr.Stop() 实现幂等(重复调用安全)100 次连接/断开循环后 goroutine 数稳定

## 🧪 Verification / 验证方法

- **单元测试**: 模拟 100 次 Start/Stop 循环,pprof 断言 goroutine 数稳定
- **手工验证**: Android 应用反复连接断开,长跑后 RSS 不持续增长

## 🔗 Dependencies / 依赖关系

- 与 `P1-1` (ECH BypassDialer in TUN) 同模块

## ⚠️ Regression Risk / 回归风险

**低**: 简单的资源释放修复
