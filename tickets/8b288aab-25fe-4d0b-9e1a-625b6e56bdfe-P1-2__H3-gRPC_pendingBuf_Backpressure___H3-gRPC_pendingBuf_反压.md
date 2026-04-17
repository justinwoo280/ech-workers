---
id: "8b288aab-25fe-4d0b-9e1a-625b6e56bdfe"
title: "P1-2: H3-gRPC pendingBuf Backpressure / H3-gRPC pendingBuf 反压"
assignee: ""
status: 0
createdAt: "2026-04-17T11:20:40.317Z"
updatedAt: "2026-04-17T11:20:53.819Z"
type: ticket
---

# P1-2: H3-gRPC pendingBuf Backpressure / H3-gRPC pendingBuf 反压

## 🟠 Severity / 优先级

**P1 — High (Memory Exhaustion)** | Sprint 3 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/transport/h3grpc/conn.go `receiveLoop` line 727: `pendingBuf [][]byte`

## 🎯 Description / 漏洞描述与影响

当 `recvChan` 满(慢消费者)时,所有解码出的帧追加到 `pendingBuf`。**无上限**。在持续高带宽下,GB 级内存占用是可触发的。

## 💥 Reproduction / 复现条件

1. 客户端建立 H3-gRPC 连接
2. 上层消费者主动卡顿(模拟应用层慢)
3. 远端持续高速发送数据
4. `pendingBuf` 持续增长,内存爆炸

## 🔧 Fix / 修复方案

设置上限(如 64MB 或 1024 帧),超出时**阻塞 receiveLoop**(自然反压 QUIC 流窗口):

```go
if pendingBytes >= maxPendingBytes {
    // 阻塞等待消费,QUIC 流量窗口自然收缩
    select { case recvChan <- buf: case <-ctx.Done(): return }
}
```

## ✅ Acceptance Criteria / 验收标准

pendingBuf 有明确字节/帧数上限(可配置,默认 64MB / 1024 帧)超限时 receiveLoop 阻塞,而非继续追加消费恢复后 receiveLoop 自动恢复不影响正常吞吐(消费者快速时无开销)

## 🧪 Verification / 验证方法

- **单元测试**: 注入卡顿消费者 + 高速生产者,断言 RSS 稳定 < 上限
- **基准测试**: 正常场景吞吐与之前一致
- **长跑**: 24h 高带宽 + 间歇消费,内存稳定

## 🔗 Dependencies / 依赖关系

- 与 `P1-28` (H3-gRPC 解码错误容忍) 同模块
- 与 `P1-5` (cache 上限) 是同类资源治理

## ⚠️ Regression Risk / 回归风险

**中**: 阻塞 receiveLoop 可能放大尾延迟。需:

- 测试在突发流量下的恢复时间
- 监控 metric: pendingBuf 利用率

</TRAYCER_TICKET>
