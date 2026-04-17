---
id: "fc1c685b-862c-4dd3-8ea0-7acf070704a0"
title: "P1-22: SOCKS5 UDP Source Port Validation / SOCKS5 UDP 源端口校验"
assignee: ""
status: 0
createdAt: "2026-04-17T11:24:08.522Z"
updatedAt: "2026-04-17T11:24:19.574Z"
type: ticket
---

# P1-22: SOCKS5 UDP Source Port Validation / SOCKS5 UDP 源端口校验

## 🟠 Severity / 优先级

**P1 — High (Local Threat)** | Sprint 4 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/socks5/udp.go `relayUDPLoop` line 210

## 🎯 Description / 漏洞描述与影响

源端口未校验。同一宿主机的其他进程可冒用合法 IP 向 UDP 中继发包,被代理出去。仅本地威胁,但**违反 SOCKS5 RFC 1928 期待**。

## 💥 Reproduction / 复现条件

1. 应用 A 通过 SOCKS5 UDP-ASSOCIATE 建立中继(client port = 12345)
2. 同机恶意应用 B 从随机端口向中继 socket 发 UDP 包,源 IP 同(127.0.0.1)
3. 中继接受并代理出去 — 应用 B 借用了应用 A 的代理通道

## 🔧 Fix / 修复方案

记录 ASSOCIATE 阶段的 client UDP src port,后续仅接受同 (IP, port):

```go
// 示意
session.expectedAddr = clientAssociateAddr
if !addrMatches(packetAddr, session.expectedAddr) { drop(); continue }
```

## ✅ Acceptance Criteria / 验收标准

ASSOCIATE 时记录 client UDP (IP, port)relayUDPLoop 严格校验源不匹配的包丢弃并 log warn

## 🧪 Verification / 验证方法

- **单元测试**: 模拟另一端口的源,断言被丢弃
- **手工验证**: 同机两进程,只有 ASSOCIATE 端能用中继

## 🔗 Dependencies / 依赖关系

- 与 `P1-7` (SOCKS5 sync.Once) 同模块

## ⚠️ Regression Risk / 回归风险

**低**: 部分 SOCKS5 实现可能用 ephemeral port pool,需测试主流客户端兼容性
