---
id: "4be71f6b-9019-4b69-9103-dd4ffcb2b022"
title: "P1-30: FakeIP IPv6 Pool Expansion / FakeIP IPv6 池扩大"
assignee: ""
status: 0
createdAt: "2026-04-17T11:25:26.963Z"
updatedAt: "2026-04-17T11:25:41.851Z"
type: ticket
---

# P1-30: FakeIP IPv6 Pool Expansion / FakeIP IPv6 池扩大

## 🟠 Severity / 优先级

**P1 — High (Long-Running Correctness)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/dns/fakeip.go `ip6Size = 65534`

## 🎯 Description / 漏洞描述与影响

长跑 app + 海量 AAAA 查询会循环替换映射,旧映射的连接会查不到 domain reverse,**被当 IP target 处理可能错误**。

## 💥 Reproduction / 复现条件

1. 长跑客户端,IPv6 AAAA 查询累积 65535+
2. 旧 fakeip 映射被覆盖
3. 旧连接的 reverse lookup 失效 → 错误目标

## 🔧 Fix / 修复方案

扩大 IPv6 池到 /64 或 /96 范围:

```go
ip6Size = 1 << 32  // /96 范围,40亿条
// 或 /64 全空间(需稀疏映射)
```

或采用 LRU + 长 TTL,确保活跃映射不被淘汰。

## ✅ Acceptance Criteria / 验收标准

IPv6 fakeip 池扩大到至少 /96或采用 LRU 淘汰活跃映射保留长跑测试无 reverse lookup 失败

## 🧪 Verification / 验证方法

- **长跑测试**: 7 天,断言无 fakeip reverse 失败 log

## 🔗 Dependencies / 依赖关系

- 与 `P1-5` (cache 上限) 是同类资源治理

## ⚠️ Regression Risk / 回归风险

**低**: 内存占用稍增

</TRAYCER_TICKET>

<TRAYCER_TICKET title="P2-1: NonceCache Key Include UUID Hash / NonceCache key 引入 UUID 维度">

## 🟡 Severity / 优先级

**P2 — Medium** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/ewp/security.go `NonceCache`

## 🎯 Description / 漏洞描述与影响

NonceCache 仅以 nonce 为 key,理论上不同 UUID 同 nonce 误判为重放(2^96 概率,实际不发生)。属于防御深度问题。

## 💥 Reproduction / 复现条件

- 概率 2^-96,实际不可触发

## 🔧 Fix / 修复方案

文档化即可,或 key=(uuidHash, nonce):

```go
key := xxhash.Sum64String(uuid+string(nonce))
```

## ✅ Acceptance Criteria / 验收标准

选项 A: 仅文档化 2^96 概率说明选项 B: key 加入 uuid hash

## 🧪 Verification / 验证方法

- **单元测试**: 不同 UUID 同 nonce,不被认为重放

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
