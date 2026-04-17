---
id: "b8a6769f-0abf-406c-8439-42247fda9e54"
title: "Bug-F: StreamOne EWP Handshake Leftover / StreamOne EWP 握手 leftover"
assignee: ""
status: 0
createdAt: "2026-04-17T11:29:52.532Z"
updatedAt: "2026-04-17T11:30:01.992Z"
type: ticket
---

# Bug-F: StreamOne EWP Handshake Leftover / StreamOne EWP 握手 leftover

## 🔵 Severity / 优先级

**Bug — High (Data Loss)** | Sprint 2 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/transport/xhttp/stream_one.go `connectEWP` line 288-292

## 🎯 Description / 漏洞描述与影响

当前代码:

```go
handshakeResp := make([]byte, 64)
n, err := c.respBody.Read(handshakeResp)
```

`Read(64)` **可能一次读到握手响应 26 字节 + 后续应用层数据 38 字节**。后续 `c.respBody.Read(buf)` 跳过这 38 字节 → **数据丢失**。

## 💥 Reproduction / 复现条件

1. 服务端在握手响应后立即发送应用数据(常见快速响应)
2. 客户端 Read(64) 一次读到 26+38 字节
3. 后续 Read 漏掉 38 字节
4. 应用层数据损坏

## 🔧 Fix / 修复方案

用 `io.ReadFull` 精确读 26 字节;或将多余数据回写到 leftover:

```go
handshakeResp := make([]byte, 26)
if _, err := io.ReadFull(c.respBody, handshakeResp); err != nil { return err }
// 后续 Read 自然读到应用数据
```

## ✅ Acceptance Criteria / 验收标准

用 ReadFull 精确读握手响应字节数后续 Read 不丢失数据单元测试覆盖"握手+数据合并"场景

## 🧪 Verification / 验证方法

- **单元测试**: mock respBody 一次返回 26+38 字节,断言后续 Read 拿到完整 38 字节
- **e2e**: 服务端立即响应数据,客户端正确接收

## 🔗 Dependencies / 依赖关系

- 与 `Bug-G` (FlowReader leftover) 同类问题
- 与 `P0-3` (Vision FlowReader) 同 Sprint

## ⚠️ Regression Risk / 回归风险

**中**: 修复后 Read 行为变化,需 e2e 验证 stream-one 模式各场景
