---
id: "60a46557-9ac3-4327-af65-c18cf9e8436d"
title: "P2-11: h3grpc SetSNI Return Error / h3grpc SetSNI 返回错误"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:36.124Z"
updatedAt: "2026-04-17T11:26:40.031Z"
type: ticket
---

# P2-11: h3grpc SetSNI Return Error / h3grpc SetSNI 返回错误

## 🟡 Severity / 优先级

**P2 — Low** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/transport/h3grpc/transport.go `SetSNI`

## 🎯 Description / 漏洞描述与影响

调用 reinitClient 但忽略错误 → 静默配置失败,SNI 未实际更新。

## 💥 Reproduction / 复现条件

- 调用 SetSNI 后 reinit 失败,继续用旧 SNI

## 🔧 Fix / 修复方案

```go
func (t *Transport) SetSNI(sni string) error {
    t.sni = sni; return t.reinitClient()
}
```

## ✅ Acceptance Criteria / 验收标准

SetSNI 返回 errorcaller 处理错误

## 🧪 Verification / 验证方法

- **单元测试**: mock reinit 失败,断言 SetSNI 返回 error

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
