---
id: "fd6d2f3c-4d0b-4992-acb6-f2cff11e7f85"
title: "P1-26: crypto/rand Error Handling / crypto/rand 错误必须处理"
assignee: ""
status: 0
createdAt: "2026-04-17T11:24:47.242Z"
updatedAt: "2026-04-17T11:24:57.897Z"
type: ticket
---

# P1-26: crypto/rand Error Handling / crypto/rand 错误必须处理

## 🟠 Severity / 优先级

**P1 — High (Cryptographic Failure)** | Sprint 4 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/ewp/protocol.go `NewHandshakeRequest` 多处 `rand.Read(...)` `rand.Int(...)` 忽略错误

## 🎯 Description / 漏洞描述与影响

`crypto/rand` 在 Linux fork 后或 entropy 不足时(罕见但存在),可能返回 short read 或 error。**忽略错误意味着 nonce 可能是零字节 / 非随机,密码学协议崩溃**。

## 💥 Reproduction / 复现条件

1. 系统 entropy 极低 / `/dev/urandom` 异常
2. `rand.Read` 返回 (0, error)
3. nonce 字段被填零
4. 多次握手用同一 nonce → 重放攻击 / 破解

## 🔧 Fix / 修复方案

错误必须 panic 或返回 error 给上层:

```go
if _, err := rand.Read(nonce); err != nil {
    return nil, fmt.Errorf("crypto/rand failed: %w", err)
}
```

## ✅ Acceptance Criteria / 验收标准

所有 crypto/rand 调用错误均被处理grep 确认无 rand.Read(...) 后的下划线丢弃接口签名允许返回 error

## 🧪 Verification / 验证方法

- **静态分析**: 加 lint 规则禁止丢弃 crypto/rand 错误
- **单元测试**: mock 注入 rand 错误,断言 NewHandshakeRequest 返回 error

## 🔗 Dependencies / 依赖关系

- 与 `P2-3` (DNS BuildQuery 用 crypto/rand) 同类问题

## ⚠️ Regression Risk / 回归风险

**低**: API 变化(增 error 返回),需:

- 更新所有 caller
- 测试错误传播路径
