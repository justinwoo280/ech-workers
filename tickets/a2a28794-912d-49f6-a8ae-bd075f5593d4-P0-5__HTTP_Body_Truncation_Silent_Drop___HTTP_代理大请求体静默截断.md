---
id: "a2a28794-912d-49f6-a8ae-bd075f5593d4"
title: "P0-5: HTTP Body Truncation Silent Drop / HTTP 代理大请求体静默截断"
assignee: ""
status: 0
createdAt: "2026-04-17T11:18:25.428Z"
updatedAt: "2026-04-17T11:18:40.141Z"
type: ticket
---

# P0-5: HTTP Body Truncation Silent Drop / HTTP 代理大请求体静默截断

## 🔴 Severity / 优先级

**P0 — Critical (Data Integrity)** | Sprint 1 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/http/server.go line 111

## 🎯 Description / 漏洞描述与影响

当前实现:

```go
if length > 0 && length < 10*1024*1024 {
    body := make([]byte, length); io.ReadFull(reader, body)
    requestBuilder.Write(body)
}
```

**任何 ****`Content-Length >= 10 MB`**** 的 POST/PUT 请求,请求体被完全丢弃,但 method+headers 仍透传**。客户端误以为请求成功(HTTP 200/201),实际上传文件全部丢失。**严重数据完整性破坏**。

## 💥 Reproduction / 复现条件

1. 客户端通过 HTTP 代理上传 11MB 文件 (POST `/upload`)
2. 服务端实际收到 method+headers,body 为空
3. 上游服务返回 200(因为它收到了完整 HTTP 请求,只是 body 为 0 字节)
4. 客户端"以为"上传成功,实际数据丢失

## 🔧 Fix / 修复方案

两种方案选其一:

- **方案 A**: 流式转发 body,不在内存缓冲(推荐)— `io.Copy(upstream, reader)` 配合 chunked 透传
- **方案 B**: 超过限制返回 `413 Payload Too Large`,**不静默截断**

```go
if length > maxBodySize {
    w.WriteHeader(http.StatusRequestEntityTooLarge); return
}
```

## ✅ Acceptance Criteria / 验收标准

大于 10MB 的请求不再被静默截断选择方案 A: 实现流式转发,内存占用与文件大小无关选择方案 B: 明确返回 413,客户端能感知失败限制值为可配置项(默认值合理)文档明确说明大文件处理策略

## 🧪 Verification / 验证方法

- **单元测试**: 上传 11MB / 100MB / 1GB 文件,断言或全部到达上游(方案 A)或返回 413(方案 B)
- **手工验证**: `curl -X POST -d @large.bin` 应符合预期行为
- **数据完整性**: 上下游 hash 校验

## 🔗 Dependencies / 依赖关系

- 与 `P0-6` (XHTTP Body OOM) 是同类问题,可统一封装 `LimitedReader` 工具
- 与 `P2-9` (HTTP ABNF) 与 `P2-10` (Keep-Alive) 同文件,Sprint 中可一并审视

## ⚠️ Regression Risk / 回归风险

**低-中**: 现有功能在 < 10MB 时不变;> 10MB 行为改变属于修复 Bug。需:

- 测试 chunked transfer encoding 兼容性
- 测试 multipart form-data 大文件场景
