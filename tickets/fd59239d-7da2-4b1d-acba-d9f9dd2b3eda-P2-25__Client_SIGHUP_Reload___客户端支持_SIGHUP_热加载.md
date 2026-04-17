---
id: "fd59239d-7da2-4b1d-acba-d9f9dd2b3eda"
title: "P2-25: Client SIGHUP Reload / 客户端支持 SIGHUP 热加载"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:39.351Z"
updatedAt: "2026-04-17T11:27:43.924Z"
type: ticket
---

# P2-25: Client SIGHUP Reload / 客户端支持 SIGHUP 热加载

## 🟡 Severity / 优先级

**P2 — Low (Ops)** | Sprint 5 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/client/main.go `startProxyMode` 不支持 SIGHUP reload

## 🎯 Description / 漏洞描述与影响

配置变更需重启,影响运维体验。

## 🔧 Fix / 修复方案

```go
sigCh := make(chan os.Signal, 1); signal.Notify(sigCh, syscall.SIGHUP)
go func() { for range sigCh { reloadConfig() } }()
```

注意 reload 需平滑切换 outbound 与监听 socket。

## ✅ Acceptance Criteria / 验收标准

SIGHUP 触发配置重新加载在用连接不中断新配置生效

## 🧪 Verification / 验证方法

- **手工验证**: `kill -HUP <pid>` 观察日志

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**中**: reload 需仔细处理资源生命周期
