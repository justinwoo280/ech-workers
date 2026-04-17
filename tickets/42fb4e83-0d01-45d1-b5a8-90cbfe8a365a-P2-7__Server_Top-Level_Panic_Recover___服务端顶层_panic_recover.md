---
id: "42fb4e83-0d01-45d1-b5a8-90cbfe8a365a"
title: "P2-7: Server Top-Level Panic Recover / 服务端顶层 panic recover"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:12.724Z"
updatedAt: "2026-04-17T11:26:17.426Z"
type: ticket
---

# P2-7: Server Top-Level Panic Recover / 服务端顶层 panic recover

## 🟡 Severity / 优先级

**P2 — Medium (Availability)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/main.go

## 🎯 Description / 漏洞描述与影响

server panic 顶层无 recover → **单个 handler panic 直接拉垮整个 server 进程**。

## 💥 Reproduction / 复现条件

1. 任一 handler 触发 panic(如未处理的 nil dereference)
2. 整个 server 进程退出
3. 所有连接断开,服务中断

## 🔧 Fix / 修复方案

加 middleware,在每个 HTTP handler 外包装 recover:

```go
func recoverMW(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w, r) {
        defer func() { if e := recover(); e != nil { log.Errorf("panic: %v", e) } }()
        h.ServeHTTP(w, r)
    })
}
```

## ✅ Acceptance Criteria / 验收标准

所有 handler 有 recover middlewarepanic 时 log 完整 stack trace不影响其他连接配套 metric: panic 计数

## 🧪 Verification / 验证方法

- **单元测试**: 注入故意 panic 的 handler,服务不中断
- **alert**: panic 计数 > 0 时告警

## 🔗 Dependencies / 依赖关系

- 与 `P1-8` (recover 反模式) 是不同层次的 recover 使用

## ⚠️ Regression Risk / 回归风险

**低**
