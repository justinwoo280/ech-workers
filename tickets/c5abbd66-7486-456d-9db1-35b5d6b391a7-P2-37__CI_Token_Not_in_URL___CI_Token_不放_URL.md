---
id: "c5abbd66-7486-456d-9db1-35b5d6b391a7"
title: "P2-37: CI Token Not in URL / CI Token 不放 URL"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:41.850Z"
updatedAt: "2026-04-17T11:28:46.053Z"
type: ticket
---

# P2-37: CI Token Not in URL / CI Token 不放 URL

## 🟡 Severity / 优先级

**P2 — Medium (Token Leak)** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:.github/workflows/release.yml `git push https://x-access-token:${{ secrets.GITHUB_TOKEN }}@...`

## 🎯 Description / 漏洞描述与影响

URL 中带 token,**log 可能泄露**(action log 默认 mask 但仍是反模式)。

## 🔧 Fix / 修复方案

用 actions/checkout token + git push 默认行为:

```yaml
- uses: actions/checkout@v4
  with: { token: ${{ secrets.GITHUB_TOKEN }} }
- run: git push
```

## ✅ Acceptance Criteria / 验收标准

移除 URL 中的 token使用 actions/checkout 注入 credentials

## 🧪 Verification / 验证方法

- **CI 运行**

## 🔗 Dependencies / 依赖关系

- 与 `P2-35`、`P2-36` 同 sprint

## ⚠️ Regression Risk / 回归风险

**极低**
