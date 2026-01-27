# ECH Workers GUI (C++ Qt6)

基于 Qt6 的现代化图形界面客户端，用于管理和控制 ECH Workers 代理核心。

## 项目概述

这是一个使用 C++ 和 Qt6 框架开发的 GUI 客户端，通过启动和管理 `ech-workers.exe` 核心进程来提供代理服务。

## 架构设计

```
┌─────────────────────────────────────────────────────────┐
│              ECH Workers GUI (C++ Qt6)                  │
├─────────────────────────────────────────────────────────┤
│  MainWindow     - 主窗口，节点列表，日志显示            │
│  CoreProcess    - 核心进程管理 (启动/停止)              │
│  NodeManager    - 节点配置管理 (增删改查)               │
│  SystemProxy    - 系统代理设置 (WinINet API)            │
│  NodeTester     - 节点延迟测试                          │
│  ShareLink      - 分享链接解析/生成                     │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼ QProcess 启动
        ┌───────────────────────────────┐
        │   ech-workers.exe (Go 核心)   │
        │   - SOCKS5/HTTP 代理          │
        │   - TUN 模式                  │
        │   - ECH + Vision 流控         │
        └───────────────────────────────┘
```

## 核心功能

- ✅ **节点管理**: 添加、编辑、删除、复制节点
- ✅ **节点测试**: TCP 连接延迟测试
- ✅ **分享链接**: 导入/导出 `ewp://` 格式链接
- ✅ **系统代理**: 自动设置 Windows 系统代理
- ✅ **TUN 模式**: 全局代理模式
- ✅ **系统托盘**: 最小化到托盘运行
- ✅ **日志显示**: 实时显示核心进程日志

## 分享链接格式

```
ewp://uuid@server:port?mode=ws&ech=1&flow=1&pqc=0&ip=xxx#name
```

参数说明:
- `uuid`: 认证令牌
- `server:port`: 服务器地址和端口
- `mode`: 传输协议 (ws/grpc/xhttp)
- `ech`: 是否启用 ECH (1/0)
- `flow`: 是否启用 Vision 流控 (1/0)
- `pqc`: 是否启用后量子加密 (1/0)
- `ip`: 优选 IP (可选)
- `#name`: 节点名称

## 编译要求

### 环境准备
1. **Qt6**: 下载并安装 Qt 6.5+ (包含 Qt Creator)
2. **CMake**: 3.16 或更高版本
3. **编译器**: MSVC 2019+ 或 MinGW 11+

### 编译步骤

#### 使用 Qt Creator (推荐)
1. 打开 Qt Creator
2. File → Open File or Project
3. 选择 `CMakeLists.txt`
4. 配置 Kit (选择 Qt6 + 编译器)
5. Build → Build Project

#### 使用命令行
```bash
mkdir build
cd build
cmake .. -DCMAKE_PREFIX_PATH="C:/Qt/6.5.0/msvc2019_64"
cmake --build . --config Release
```

## 项目结构

```
ech-workers-gui/
├── CMakeLists.txt          # CMake 构建配置
├── README.md               # 本文档
├── src/                    # 源代码
│   ├── main.cpp            # 程序入口
│   ├── MainWindow.h/cpp    # 主窗口
│   ├── CoreProcess.h/cpp   # 核心进程管理
│   ├── NodeManager.h/cpp   # 节点管理
│   ├── SystemProxy.h/cpp   # 系统代理设置
│   ├── NodeTester.h/cpp    # 节点测试
│   ├── ShareLink.h/cpp     # 分享链接
│   └── EWPNode.h           # 节点配置结构
├── ui/                     # Qt Designer UI 文件
│   ├── MainWindow.ui       # 主窗口 UI
│   ├── EditNode.ui         # 节点编辑 UI
│   └── Settings.ui         # 设置 UI
└── resources/              # 资源文件
    ├── resources.qrc       # Qt 资源文件
    └── icons/              # 图标
```

## 使用说明

1. **添加节点**: 点击"添加"按钮或从剪贴板导入分享链接
2. **测试节点**: 选中节点后点击"测试"按钮
3. **启动代理**: 双击节点或选中后点击"启动"按钮
4. **系统代理**: 勾选"系统代理"自动配置浏览器代理
5. **TUN 模式**: 勾选"TUN 模式"启用全局代理 (需管理员权限)

## 许可证

MIT License
