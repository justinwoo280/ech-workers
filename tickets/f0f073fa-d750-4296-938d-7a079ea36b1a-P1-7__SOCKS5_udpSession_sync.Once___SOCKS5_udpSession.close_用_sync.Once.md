---
id: "f0f073fa-d750-4296-938d-7a079ea36b1a"
title: "P1-7: SOCKS5 udpSession sync.Once / SOCKS5 udpSession.close 用 sync.Once"
assignee: ""
status: 0
createdAt: "2026-04-17T11:21:34.662Z"
updatedAt: "2026-04-17T11:21:54.000Z"
type: ticket
---

# P1-7: SOCKS5 udpSession sync.Once / SOCKS5 udpSession.close 用 sync.Once

## 🟠 Severity / 优先级

**P1 — High (Panic)** | Sprint 2 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/socks5/udp.go `udpSession.close` line 32-39

## 🎯 Description / 漏洞描述与影响

当前模式:

```go
select { case <-s.stopPing: default: close(s.stopPing) }
```

两个 goroutine 同时进入 `default` 分支会触发 `close of closed channel` **panic**,直接 crash 整个进程(SOCKS5 中无 recover)。

## 💥 Reproduction / 复现条件

1. UDP session 在 cleanup goroutine 与 主流程同时调用 close
2. 二者都通过 select default
3. 二者都执行 close(s.stopPing)
4. 第二个触发 panic

## 🔧 Fix / 修复方案

用 `sync.Once`:

```go
type udpSession struct {
    closeOnce sync.Once
    // ...
}
func (s *udpSession) close() {
    s.closeOnce.Do(func() { close(s.stopPing); /* ... */ })
}
```

## ✅ Acceptance Criteria / 验收标准

udpSession.close 使用 sync.Once同类模式审视 SOCKS5/HTTP/EWP 其他 close 路径race detector 测试无新警告

## 🧪 Verification / 验证方法

- **单元测试**: 100 个 goroutine 并发 close 同一 session,无 panic
- **race detector**: `go test -race ./protocol/socks5/...`

## 🔗 Dependencies / 依赖关系

- 与 `P1-8` (UDP recover 反模式) 是同类问题,Sprint 中可一并审视

## ⚠️ Regression Risk / 回归风险

**极低**

</TRAYCER_TICKET>

<TRAYCER_TICKET title="P1-8: UDP chanWriter Race via sync.Once / UDP chanWriter recover 反模式重构">

## 🟠 Severity / 优先级

**P1 — High (Hidden Race)** | Sprint 3 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/internal/server/udp_handler.go line 263-269 (`chanWriter.write`)
- file:ewp-core/internal/server/udp_handler.go line 411-417 (`safeSend`)

## 🎯 Description / 漏洞描述与影响

虽然功能可用,但**用 ****`recover()`**** 掩盖 send-on-closed-channel 是反模式**:

- 潜在的 race-condition 永远不会被发现
- 任何关于此 channel 的逻辑变更都很危险
- pprof 看不到真实问题

## 💥 Reproduction / 复现条件

- 实际不易触发 panic(被 recover),但代码维护中:
- 加新逻辑时不知道 close 已发生
- 行为不可预测(send 可能成功也可能默默失败)

## 🔧 Fix / 修复方案

用 `closeOnce + done channel` 重构:

```go
type chanWriter struct {
    ch chan []byte
    done chan struct{}
    closeOnce sync.Once
}
func (w *chanWriter) Close() { w.closeOnce.Do(func() { close(w.done) }) }
func (w *chanWriter) Write(p []byte) error {
    select { case w.ch <- p: return nil; case <-w.done: return errClosed }
}
```

## ✅ Acceptance Criteria / 验收标准

移除所有 recover() 掩盖 send-on-closed用 done channel 显式标记关闭状态所有 send 路径返回明确 errorrace detector 通过

## 🧪 Verification / 验证方法

- **race detector**: `go test -race ./internal/server/...`
- **单元测试**: 并发 close + write,断言无 panic 且 write 在 close 后返回 errClosed

## 🔗 Dependencies / 依赖关系

- 与 `P1-7` (SOCKS5 sync.Once) 是同类,可同 sprint review

## ⚠️ Regression Risk / 回归风险

**中**: 重构涉及 channel 生命周期,需仔细验证:

- 所有 caller 正确处理 errClosed
- 不影响正常 UDP 转发性能

</TRAYCER_TICKET>
