---
id: "f5ca0878-27dc-4481-860c-288f8452a15f"
title: "Bug-A: parseUUID Accept 32-Hex Without Dashes / parseUUID 接受去短横 hex"
assignee: ""
status: 0
createdAt: "2026-04-17T11:29:05.610Z"
updatedAt: "2026-04-17T11:29:14.266Z"
type: ticket
---

# Bug-A: parseUUID Accept 32-Hex Without Dashes / parseUUID 接受去短横 hex

## 🔵 Severity / 优先级

**Bug — Low** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-core/internal/server/ewp_handler.go `parseUUID`
- file:ewp-core/transport/transport.go `ParseUUID`

## 🎯 Description / 漏洞描述与影响

`strings.ReplaceAll(s, "-", "")` 然后只校验长度 32。32 位 hex 字符串(无短横)也被接受。**与标准 UUIDv4 格式校验不一致**,可能导致跨工具拷贝时静默成功,但实际上与服务端不匹配。

## 💥 Reproduction / 复现条件

1. 用户复制 UUID 时丢了短横,粘贴 `d342d11ed4244583b36e524ab1f0afa4`
2. 客户端 parseUUID 接受
3. 服务端可能也接受,也可能拒绝(版本不一)
4. 行为不一致

## 🔧 Fix / 修复方案

严格校验 RFC 4122 格式:

```go
u, err := uuid.Parse(s); if err != nil { return errInvalidUUID }
```

## ✅ Acceptance Criteria / 验收标准

parseUUID 仅接受标准格式 8-4-4-4-12客户端与服务端行为一致单元测试覆盖各种格式

## 🧪 Verification / 验证方法

- **单元测试**: 各种合法/非法 UUID 字符串

## 🔗 Dependencies / 依赖关系

- 与 `P0-1` (默认 UUID 移除) 配套

## ⚠️ Regression Risk / 回归风险

**低**
