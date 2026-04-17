---
id: "2ad61157-f42e-4257-9a16-0eb594aca973"
title: "P2-10: HTTP Keep-Alive Support / HTTP 代理支持 keep-alive"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:30.025Z"
updatedAt: "2026-04-17T11:26:35.373Z"
type: ticket
---

# P2-10: HTTP Keep-Alive Support / HTTP 代理支持 keep-alive

## 🟡 Severity / 优先级

**P2 — Low (Performance)** | Sprint 5 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/http/server.go

## 🎯 Description / 漏洞描述与影响

不支持 keep-alive,每次 GET/POST 都新建 tunnel,**性能差**。

## 💥 Reproduction / 复现条件

- 浏览器多请求场景,每请求一个 TCP 隧道,RTT 累加

## 🔧 Fix / 修复方案

复用 tunnel,正确处理 Connection: keep-alive 头与多请求复用。

## ✅ Acceptance Criteria / 验收标准

支持 HTTP/1.1 keep-alive同一连接多请求复用同一 tunnel基准测试吞吐改善

## 🧪 Verification / 验证方法

- **基准测试**: 多请求场景吞吐对比
- **e2e**: curl 多 URL 共享连接

## 🔗 Dependencies / 依赖关系

- 与 `P0-5`、`P2-9` 同文件

## ⚠️ Regression Risk / 回归风险

**中**: 涉及连接生命周期变化,需仔细处理
