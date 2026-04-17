---
id: "afe9fd49-0422-4caf-9f11-9c281af91644"
title: "P0-11: GUI QTemporaryFile for Config / GUI 用 QTemporaryFile 写配置"
assignee: ""
status: 0
createdAt: "2026-04-17T11:19:56.912Z"
updatedAt: "2026-04-17T11:20:08.970Z"
type: ticket
---

# P0-11: GUI QTemporaryFile for Config / GUI 用 QTemporaryFile 写配置

## 🔴 Severity / 优先级

**P0 — Critical (Multi-User Credential Leak)** | Sprint 1 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-gui/src/CoreProcess.cpp `generateConfigFile` line 215-231
- 当前: `QString configPath = tempDir + "/ewp-gui-config-<pid>.json"`

## 🎯 Description / 漏洞描述与影响

- Windows `%TEMP%` 默认权限是 user-only,但 **macOS/Linux ****`/tmp`**** 是 world-readable**
- 配置文件中含 UUID/Trojan 密码明文
- GUI 进程崩溃时 `QFile::remove` 不会执行,**残留文件**被其他用户读取

## 💥 Reproduction / 复现条件 (Linux 多用户)

1. 用户 A 启动 GUI,生成 `/tmp/ewp-gui-config-1234.json`
2. 用户 B `cat /tmp/ewp-gui-config-1234.json` → 看到所有节点凭证
3. GUI 崩溃 → 残留文件长期可读

## 🔧 Fix / 修复方案

用 `QTemporaryFile`(自动严格权限 + 析构删除),并在 Linux 显式 `chmod 0600`:

```cpp
QTemporaryFile f(QDir::temp().filePath("ewp-gui-config-XXXXXX.json"));
f.setAutoRemove(true);
f.open(); QFile::setPermissions(f.fileName(), QFile::ReadOwner|QFile::WriteOwner);
```

## ✅ Acceptance Criteria / 验收标准

配置临时文件使用 QTemporaryFile 创建Linux/macOS 上文件权限 0600(owner only)进程退出/崩溃时文件被清理(autoRemove + atexit handler)CoreProcess 重启后旧配置文件清理逻辑正确

## 🧪 Verification / 验证方法

- **手工验证 Linux**: `ls -l /tmp/ewp-gui-*` 应为 `-rw-------`,user 私有
- **崩溃测试**: `kill -9` GUI 后,临时文件应消失或下次启动被清理
- **多用户**: 用户 B 读取应得 `Permission denied`

## 🔗 Dependencies / 依赖关系

- 无强依赖,可与 P0-1 同 sprint 并行

## ⚠️ Regression Risk / 回归风险

**低**: 文件名变为随机后缀,需:

- 检查日志/调试信息中是否有硬编码文件名引用
- CoreProcess 启动参数传递 file path 仍正常工作
