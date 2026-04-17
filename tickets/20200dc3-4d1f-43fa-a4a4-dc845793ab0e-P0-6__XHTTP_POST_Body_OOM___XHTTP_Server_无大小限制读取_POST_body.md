---
id: "20200dc3-4d1f-43fa-a4a4-dc845793ab0e"
title: "P0-6: XHTTP POST Body OOM / XHTTP Server 无大小限制读取 POST body"
assignee: ""
status: 0
createdAt: "2026-04-17T11:18:40.921Z"
updatedAt: "2026-04-17T11:18:54.760Z"
type: ticket
---

# P0-6: XHTTP POST Body OOM / XHTTP Server 无大小限制读取 POST body

## 🔴 Severity / 优先级

**P0 — Critical (DoS)** | Sprint 1 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/xhttp_handler.go `xhttpUploadHandler` line 418: `io.ReadAll(r.Body)`
- file:ewp-core/cmd/server/xhttp_handler.go `xhttpHandshakeHandler` line 280

## 🎯 Description / 漏洞描述与影响

已通过 `X-Auth-Token` 鉴权的请求(攻击者只需有 UUID),可发任意大小 body 让服务端 **OOM**。`io.ReadAll` 无上限,攻击者只需上传 GB 级 body 即可耗尽服务端内存。

## 💥 Reproduction / 复现条件

1. 攻击者拥有任一合法 UUID(默认 UUID 或泄露的)
2. 构造 XHTTP POST 请求,Content-Length: 8589934592 (8GB)
3. 服务端 `io.ReadAll` 持续分配内存
4. 服务端 OOM 崩溃

## 🔧 Fix / 修复方案

用 `io.LimitReader(r.Body, maxFrameSize)`,根据帧最大长度合理上限。

```go
data, err := io.ReadAll(io.LimitReader(r.Body, maxXHTTPFrameSize))
if int64(len(data)) >= maxXHTTPFrameSize { return errFrameTooLarge }
```

`maxXHTTPFrameSize` 应基于 XHTTP 协议合理值(如 1MB/帧)。

## ✅ Acceptance Criteria / 验收标准

xhttpUploadHandler 与 xhttpHandshakeHandler 均使用 LimitReader超过上限的请求返回 413 或关闭连接上限值定义为常量,有明确注释说明依据不影响合法 XHTTP 帧传输

## 🧪 Verification / 验证方法

- **单元测试**: 注入 1GB body 请求,断言服务端内存增量 < 上限 + 几 KB,而非线性增长
- **DoS 验证**: 并发 100 个大 body 请求,服务端 RSS 不暴增
- **正功能**: 正常 XHTTP 上传/下载流量不受影响

## 🔗 Dependencies / 依赖关系

- 与 `P0-5` (HTTP body truncation) 同类,可共享 `LimitedReader` 工具
- 与 `P0-7` (XHTTP Session Limit) 是配套的 DoS 防护,但可独立修复

## ⚠️ Regression Risk / 回归风险

**低**: 上限设置合理(如 1MB/帧)对正常流量无影响。需测试:

- XHTTP `auto` / `stream-up` / `stream-down` 三种模式
- 长连接场景下多帧累积
