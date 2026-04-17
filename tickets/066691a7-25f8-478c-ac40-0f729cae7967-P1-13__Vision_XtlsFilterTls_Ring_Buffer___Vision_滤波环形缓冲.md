---
id: "066691a7-25f8-478c-ac40-0f729cae7967"
title: "P1-13: Vision XtlsFilterTls Ring Buffer / Vision 滤波环形缓冲"
assignee: ""
status: 0
createdAt: "2026-04-17T11:22:35.892Z"
updatedAt: "2026-04-17T11:22:47.869Z"
type: ticket
---

# P1-13: Vision XtlsFilterTls Ring Buffer / Vision 滤波环形缓冲

## 🟠 Severity / 优先级

**P1 — High (Performance Regression)** | Sprint 4 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/ewp/flow_state.go line 96 (`XtlsFilterTls` 仅看 `data[:6]`)

## 🎯 Description / 漏洞描述与影响

若 TLS Server Hello 被分片到多个 read(常见于慢速链路),前 6 字节可能不在第一个 read 中,过滤窗口耗尽(`NumberOfPacketToFilter=8`)后**永远不识别 TLS**。Vision 全程用 padding,失去零拷贝优势。

## 💥 Reproduction / 复现条件

1. 慢速链路下,TLS Server Hello 分 10 个 TCP 包到达
2. 第一个 read 仅 3 字节,XtlsFilterTls 认为非 TLS
3. 8 个包后过滤窗口耗尽,Vision 失去识别机会
4. 后续全程 padding,性能损失

## 🔧 Fix / 修复方案

用一个小 ring buffer 缓冲前 N 字节再判断:

```go
// 示意
state.filterBuf = append(state.filterBuf, data...)
if len(state.filterBuf) >= 6 { return checkTLS(state.filterBuf[:6]) }
```

参考 Xray 的实现细节。

## ✅ Acceptance Criteria / 验收标准

XtlsFilterTls 累积前 ≥6 字节后才做判断分片场景下能正确识别 TLS不增加非 TLS 流量的开销

## 🧪 Verification / 验证方法

- **单元测试**: 模拟 1 字节/次的 read,断言 TLS 仍被正确识别
- **基准测试**: 修复前后吞吐对比

## 🔗 Dependencies / 依赖关系

- 与 `P1-14` (counter 双向独立) 紧耦合,应一并修复
- 与 `P0-3` (FlowReader direct-copy) 同模块

## ⚠️ Regression Risk / 回归风险

**中**: 涉及 Vision 数据面识别逻辑,需:

- 大量 e2e 流量回放
- Xray 互操作测试(若适用)
