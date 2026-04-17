---
id: "190629d3-6918-4e8a-ae3a-2cd3af550a9a"
title: "Bug-E: StreamDownConn Trojan UDP Branch / StreamDownConn Trojan UDP 路径"
assignee: ""
status: 0
createdAt: "2026-04-17T11:29:44.398Z"
updatedAt: "2026-04-17T11:29:52.144Z"
type: ticket
---

# Bug-E: StreamDownConn Trojan UDP Branch / StreamDownConn Trojan UDP 路径

## 🔵 Severity / 优先级

**Bug — Medium (Functional Bug)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/transport/xhttp/stream_down.go line 180

## 🎯 Description / 漏洞描述与影响

注释 `// ConnectUDP sends UDP connection request using EWP native UDP protocol`,但函数体既包含 EWP 也未显式分支 `useTrojan`。**Trojan UDP over XHTTP stream-down 的实现路径不清晰,实测可能不工作**。

## 💥 Reproduction / 复现条件

1. 配置 Trojan + XHTTP stream-down 模式
2. 应用层发起 UDP 连接(如 DNS over UDP)
3. 流量未按 Trojan 协议封装 → 服务端拒绝

## 🔧 Fix / 修复方案

- 显式分支 useTrojan
- 实现 Trojan UDP over XHTTP stream-down

```go
if c.useTrojan { return c.connectTrojanUDP(addr) }
return c.connectEWPUDP(addr)
```

## ✅ Acceptance Criteria / 验收标准

connectUDP 显式分支Trojan UDP over XHTTP stream-down 端到端可用单元测试覆盖两种协议

## 🧪 Verification / 验证方法

- **e2e**: Trojan + XHTTP UDP 流量测试
- **单元测试**: mock branch 调用

## 🔗 Dependencies / 依赖关系

- 与 `Bug-F` (StreamOne 握手 leftover) 同模块

## ⚠️ Regression Risk / 回归风险

**中**: 增加 Trojan UDP 路径,需大量 e2e
