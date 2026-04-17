---
id: "0c0d5af1-4ab4-4c70-9aef-2f0d8a9d78e1"
title: "P1-21: GUI Clipboard Import Confirmation / GUI 剪贴板导入确认"
assignee: ""
status: 0
createdAt: "2026-04-17T11:23:59.103Z"
updatedAt: "2026-04-17T11:24:08.131Z"
type: ticket
---

# P1-21: GUI Clipboard Import Confirmation / GUI 剪贴板导入确认

## 🟠 Severity / 优先级

**P1 — High (Phishing/MITM)** | Sprint 4 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-gui/src/MainWindow.cpp `onImportFromClipboard` line 358-379

## 🎯 Description / 漏洞描述与影响

用户在公共电脑/钓鱼场景下,某 app 静默写入剪贴板恶意 ewp:// 链接,**用户不慎点导入即被注入"中间人"节点**,后续流量可被攻击者代理服务器拦截。

## 💥 Reproduction / 复现条件

1. 攻击者程序在剪贴板写入 `ewp://attacker-uuid@mitm.evil.com:443/?...`
2. 用户打开 GUI 点"从剪贴板导入"
3. 节点直接入库,无确认
4. 用户切换到此节点 → 流量经攻击者代理

## 🔧 Fix / 修复方案

导入前显示"将导入 N 个节点,服务器:..." **确认对话框**,用户必须明确同意:

```cpp
QMessageBox::question(this, "确认导入",
    QString("将导入 %1 个节点:\n%2\n\n确认?").arg(n).arg(serversList));
```

## ✅ Acceptance Criteria / 验收标准

导入前弹出确认对话框,显示节点数量与服务器列表用户明确点"确认"才入库可选:显示节点详情(host/port/protocol)

## 🧪 Verification / 验证方法

- **手工验证**: 触发导入,看到确认对话框
- **单元测试**: 模拟"取消" → 节点未入库

## 🔗 Dependencies / 依赖关系

- 与 `P1-20` 同 sprint

## ⚠️ Regression Risk / 回归风险

**低**
