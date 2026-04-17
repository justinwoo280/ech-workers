---
id: "b8b10c9b-7d2f-461c-b2b7-1fbfff8afe36"
title: "P2-36: CI Cosign Sign-Blob / CI 引入 Cosign 签名"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:36.408Z"
updatedAt: "2026-04-17T11:28:41.438Z"
type: ticket
---

# P2-36: CI Cosign Sign-Blob / CI 引入 Cosign 签名

## 🟡 Severity / 优先级

**P2 — Medium (Supply Chain)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:.github/workflows/release.yml 无 SBOM / SLSA / 签名

## 🎯 Description / 漏洞描述与影响

**供应链信任弱**,用户无法验证下载的二进制未被篡改。

## 🔧 Fix / 修复方案

加 cosign sign-blob:

```yaml
- uses: sigstore/cosign-installer@v3
- run: cosign sign-blob --yes ./release/*.tar.gz > sig.txt
```

同时加 SBOM 生成(syft)。

## ✅ Acceptance Criteria / 验收标准

release 产物含 cosign 签名release 产物含 SBOM (CycloneDX 或 SPDX)文档说明验证步骤

## 🧪 Verification / 验证方法

- **手工验证**: `cosign verify-blob` 通过

## 🔗 Dependencies / 依赖关系

- 与 `P2-35`、`P2-37` 同 sprint

## ⚠️ Regression Risk / 回归风险

**极低**
