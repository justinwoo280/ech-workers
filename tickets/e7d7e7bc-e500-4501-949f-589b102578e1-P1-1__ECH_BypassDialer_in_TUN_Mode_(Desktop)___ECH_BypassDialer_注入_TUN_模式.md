---
id: "e7d7e7bc-e500-4501-949f-589b102578e1"
title: "P1-1: ECH BypassDialer in TUN Mode (Desktop) / ECH BypassDialer 注入 TUN 模式"
assignee: ""
status: 0
createdAt: "2026-04-17T11:20:26.239Z"
updatedAt: "2026-04-17T11:20:39.782Z"
type: ticket
---

# P1-1: ECH BypassDialer in TUN Mode (Desktop) / ECH BypassDialer 注入 TUN 模式

## 🟠 Severity / 优先级

**P1 — High (Deadlock)** | Sprint 2 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/client/main.go `createTransport` line 113
- file:ewp-core/common/tls/ech.go `cleanupLoop`(每 30 分钟)

## 🎯 Description / 漏洞描述与影响

桌面客户端 `echMgr.Refresh()` 在 TUN setup **之前** 调用一次,且**未对 echMgr 调用 SetBypassDialer**(Mobile 路径有,Desktop 没有)。

后果: 1 小时后 ECH 缓存过期,自动 Refresh:

1. 走系统 DNS
2. 系统 DNS 走 TUN
3. TUN 走代理
4. 代理需要 ECH
5. **死锁**

## 💥 Reproduction / 复现条件

1. 桌面用户启用 TUN 模式
2. 持续运行 1 小时以上(ECH 缓存过期触发 Refresh)
3. 此时所有新连接卡死,直至 TUN 关闭

## 🔧 Fix / 修复方案

在 `tun.New()` 之后将 bypass dialer 注入 echMgr(同 Mobile 路径):

```go
echMgr.SetBypassDialer(bypassCfg.TCPDialer)  // ← 桌面缺这一行
```

或文档明确说明 ECH 在 TUN 模式下需配 bypass dialer。

## ✅ Acceptance Criteria / 验收标准

桌面 cmd/client/main.go 在 tun setup 后注入 bypass dialerechMgr.Refresh() 始终走 bypass(物理网卡)而非 TUN长跑测试 24h 无死锁移动/桌面共用同一逻辑,避免分叉

## 🧪 Verification / 验证方法

- **e2e**: TUN 模式下手动加速 ECH 缓存过期,触发 Refresh,流量正常
- **日志**: ECH refresh 日志显示走的是 bypass dialer
- **回归**: 非 TUN 模式不受影响

## 🔗 Dependencies / 依赖关系

- 与 `P1-6` (echMgr.Stop on vpnManager.Stop) 同模块
- 与 `P0-12` (DoH 多源) 配合可显著降低 bootstrap 失败率

## ⚠️ Regression Risk / 回归风险

**低**: 仅添加注入逻辑。需:

- bypass dialer 是否在所有平台正确初始化
- TUN 关闭时 bypass dialer 是否被正确释放
