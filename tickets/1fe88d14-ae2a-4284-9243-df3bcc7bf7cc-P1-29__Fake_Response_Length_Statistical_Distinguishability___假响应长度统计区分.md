---
id: "1fe88d14-ae2a-4284-9243-df3bcc7bf7cc"
title: "P1-29: Fake Response Length Statistical Distinguishability / 假响应长度统计区分"
assignee: ""
status: 0
createdAt: "2026-04-17T11:25:14.900Z"
updatedAt: "2026-04-17T11:25:26.593Z"
type: ticket
---

# P1-29: Fake Response Length Statistical Distinguishability / 假响应长度统计区分

## 🟠 Severity / 优先级

**P1 — High (Defense Depth)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/ewp/protocol.go `GenerateFakeResponse`

## 🎯 Description / 漏洞描述与影响

- `HandshakeResponse` 真实长度也是 26 字节(VersionEcho+Status+ServerTime+NonceEcho+AuthTag)
- 两者长度相同 — 但内容随机分布 vs 结构化
- DPI 可通过统计学(熵分布)区分
- **被发现后只能识别为"该服务在拒绝认证",无法识别合法用户,可接受但应改进**

## 💥 Reproduction / 复现条件

1. 攻击者大量请求 ECH Workers 服务
2. 收集响应字节熵分布
3. 区分"假响应"(高熵 random)与"真响应"(部分结构化)
4. 标记本服务

## 🔧 Fix / 修复方案

让假响应与真响应**结构化字段位置一致**,仅内容随机:

```go
// 示意:模仿真响应的字段布局
fake.VersionEcho = randVersion()
fake.Status = randInvalidStatus()
fake.ServerTime = uint32(time.Now().Unix() ^ randMask)
// AuthTag 用确定性 HMAC 风格的随机
```

## ✅ Acceptance Criteria / 验收标准

假响应字段布局与真响应一致内容看似合理(时间戳合理范围、状态码非全 0)文档记录此防御深度改进

## 🧪 Verification / 验证方法

- **统计测试**: 抓 1000 条真假响应,熵分布与字段位置应难区分
- **单元测试**: 假响应长度仍为 26 字节

## 🔗 Dependencies / 依赖关系

- 与 `Bug-C` (XHTTP 时序差异) 同类问题

## ⚠️ Regression Risk / 回归风险

**极低**: 防御深度改进
