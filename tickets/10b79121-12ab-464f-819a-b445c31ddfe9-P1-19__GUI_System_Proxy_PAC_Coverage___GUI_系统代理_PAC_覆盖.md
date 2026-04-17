---
id: "10b79121-12ab-464f-819a-b445c31ddfe9"
title: "P1-19: GUI System Proxy PAC Coverage / GUI 系统代理 PAC 覆盖"
assignee: ""
status: 0
createdAt: "2026-04-17T11:23:38.724Z"
updatedAt: "2026-04-17T11:23:48.243Z"
type: ticket
---

# P1-19: GUI System Proxy PAC Coverage / GUI 系统代理 PAC 覆盖

## 🟠 Severity / 优先级

**P1 — High (Bypass)** | Sprint 4 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-gui/src/SystemProxy.cpp

## 🎯 Description / 漏洞描述与影响

Chromium 系浏览器(Edge/Chrome/新 Edge WebView2)有自己的 proxy resolver,QUIC/H3 直连可能不走 WinINet 设置 → **设置代理后浏览器流量仍直连**,绕过 VPN。

## 💥 Reproduction / 复现条件

1. 启用 GUI 系统代理(WinINet)
2. Chrome 启用 QUIC,访问 google.com
3. 抓包发现 QUIC 流量直连,未经代理

## 🔧 Fix / 修复方案

- 文档说明 Chromium 的限制
- 改用 PAC 文件 + 系统设置(部分 Chromium 会读)
- 或提供命令行选项启动 Chromium 时强制走代理

```cpp
// 示意
generatePACFile(proxyAddr); setSystemPACUrl("file:///path/to/pac");
```

## ✅ Acceptance Criteria / 验收标准

提供 PAC 文件生成系统设置同时配置 PAC URL文档说明 Chromium QUIC 的限制及推荐配置(--proxy-server)可选: 检测到 Chromium 时给出提示

## 🧪 Verification / 验证方法

- **手工验证**: Chrome 启用 QUIC 后,抓包确认走代理
- **e2e**: 多浏览器测试(Edge/Chrome/Firefox)

## 🔗 Dependencies / 依赖关系

- 无强依赖

## ⚠️ Regression Risk / 回归风险

**中**: PAC 文件影响范围广,需:

- 测试 PAC 在各浏览器的兼容性
- 卸载/退出时正确清理 PAC URL
