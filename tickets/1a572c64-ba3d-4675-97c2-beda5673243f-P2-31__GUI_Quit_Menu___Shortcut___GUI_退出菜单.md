---
id: "1a572c64-ba3d-4675-97c2-beda5673243f"
title: "P2-31: GUI Quit Menu / Shortcut / GUI 退出菜单"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:11.392Z"
updatedAt: "2026-04-17T11:28:15.674Z"
type: ticket
---

# P2-31: GUI Quit Menu / Shortcut / GUI 退出菜单

## 🟡 Severity / 优先级

**P2 — Low (UX)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-gui/src/MainWindow.cpp `closeEvent` 永远隐藏到托盘,无 quit

## 🎯 Description / 漏洞描述与影响

用户无法真正退出,关闭按钮只能 hide → 用户困惑。

## 🔧 Fix / 修复方案

加 quit menu / Ctrl+Q:

```cpp
QAction *quitAction = new QAction("Quit", this);
quitAction->setShortcut(QKeySequence::Quit);
connect(quitAction, &QAction::triggered, qApp, &QApplication::quit);
```

## ✅ Acceptance Criteria / 验收标准

文件菜单含"退出"项Ctrl+Q 触发退出退出前确认对话框(可选)

## 🧪 Verification / 验证方法

- **手工验证**

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
