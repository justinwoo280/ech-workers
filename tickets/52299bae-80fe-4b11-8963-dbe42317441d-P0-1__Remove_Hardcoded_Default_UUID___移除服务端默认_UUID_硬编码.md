---
id: "52299bae-80fe-4b11-8963-dbe42317441d"
title: "P0-1: Remove Hardcoded Default UUID / 移除服务端默认 UUID 硬编码"
assignee: ""
status: 0
createdAt: "2026-04-17T11:17:12.008Z"
updatedAt: "2026-04-17T11:17:30.198Z"
type: ticket
---

# P0-1: Remove Hardcoded Default UUID / 移除服务端默认 UUID 硬编码

## 🔴 Severity / 优先级

**P0 — Critical** | Sprint 1 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/main.go line 18: `getEnv("UUID", "d342d11e-d424-4583-b36e-524ab1f0afa4")`
- file:ewp-core/option/server_config.go line 92: `DefaultServerConfig` 同一 UUID

## 🎯 Description / 漏洞描述与影响

服务端在未设置 `UUID` 环境变量或未提供完整配置时,fallback 到硬编码的默认 UUID。**任何看过本仓库源码的人都能直接以此 UUID 通过 EWP 认证,完全绕过身份验证**。这是一个 fail-open 的运维默认值。

## 💥 Reproduction / 复现条件 (Attacker POV)

1. 攻击者克隆公开仓库 → 直接拿到默认 UUID `d342d11e-d424-4583-b36e-524ab1f0afa4`
2. 扫描 ECH Workers 默认部署(可通过 SNI/Server 指纹识别)
3. 用默认 UUID 构造 EWP HandshakeRequest → 立即获得代理隧道,可访问内网资源

## 🔧 Fix / 修复方案

**Fail-closed**: 启动时若未显式提供 UUID,**拒绝启动并退出非零状态**。

```go
// cmd/server/main.go (示意 2-3 行)
uuid := os.Getenv("UUID")
if uuid == "" { log.Fatal("UUID env var required, refusing to start") }
```

同时 `option/server_config.go::DefaultServerConfig` 的 UUID 字段改为空字符串,加载时校验。

## ✅ Acceptance Criteria / 验收标准

cmd/server/main.go 不再含任何硬编码 UUID 字面量未设置 UUID 环境变量时启动失败并 log 明确错误信息DefaultServerConfig 中 UUID 字段为空,Load 时校验非空README/部署文档更新,说明 UUID 必须显式配置CI 中加入"启动无 UUID 应失败"的测试

## 🧪 Verification / 验证方法

- **单元测试**: 新增 `TestServerStartupRequiresUUID`,断言无 UUID 时 `main` 返回错误
- **手工验证**: `UUID="" ./server` 应立即退出并打印错误
- **回归**: 用合法 UUID 启动应正常工作,所有 example/*.json 须显式包含 UUID

## 🔗 Dependencies / 依赖关系

- 应在 `Bug-A` (parseUUID 接受 32-hex 无短横) 之前或同时修复,以保证 UUID 严格性一致
- `P2-24` (DefaultServerConfig 默认 UUID) 与本 ticket 高度耦合,可合并修复

## ⚠️ Regression Risk / 回归风险

**低-中**: 现有测试/部署脚本若依赖默认 UUID 将失败。需:

- 检查所有 `example/*.json` 已显式指定 UUID
- 检查 CI 集成测试脚本是否依赖默认值
- 检查 docker-compose / k8s manifests
