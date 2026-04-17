---
id: "7160be52-ebfa-4a19-a16f-9ba3a11377aa"
title: "P1-28: H3-gRPC Decode Error Tolerance / H3-gRPC 解码错误容忍"
assignee: ""
status: 0
createdAt: "2026-04-17T11:25:06.379Z"
updatedAt: "2026-04-17T11:25:14.503Z"
type: ticket
---

# P1-28: H3-gRPC Decode Error Tolerance / H3-gRPC 解码错误容忍

## 🟠 Severity / 优先级

**P1 — High (Brittleness)** | Sprint 3 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/transport/h3grpc/conn.go `receiveLoop` line 746-752

## 🎯 Description / 漏洞描述与影响

`proto.Unmarshal` 偶发错误(如对端发送伪数据用于探测)就让整个 H3 流断开。**健壮性差,易被 DoS**。

## 💥 Reproduction / 复现条件

1. 攻击者注入伪 protobuf 帧到 H3 流
2. Unmarshal 失败
3. receiveLoop 立即关连接 → 连接断
4. 影响所有正常流量

## 🔧 Fix / 修复方案

单帧解码失败 `continue`,记录次数;超过阈值再断:

```go
if err := proto.Unmarshal(data, frame); err != nil {
    decodeErrCount++
    if decodeErrCount > maxDecodeErr { return err }
    continue
}
```

## ✅ Acceptance Criteria / 验收标准

单帧解码失败仅 log + continue累计错误超阈值才断连接(默认 10)metric 记录解码错误率

## 🧪 Verification / 验证方法

- **单元测试**: 注入 5 个错误帧 + 100 个正常帧,断言连接不断
- **DoS 测试**: 持续注入伪数据,连接最终断,但不影响其他连接

## 🔗 Dependencies / 依赖关系

- 与 `P1-2` (pendingBuf 反压) 同模块

## ⚠️ Regression Risk / 回归风险

**低**
