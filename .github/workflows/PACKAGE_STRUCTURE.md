# EWP-Workers Package Structure

## GUI Package (Bundled with Core)

GUI 包已包含内核程序，用户下载后开箱即用。

### Windows Package

```
ewp-gui-windows-amd64/
├── EWP-GUI.exe          # Qt6 图形界面程序
├── ewp-core.exe         # EWP-Core 内核 (重命名自 ewp-core-client)
├── wintun.dll           # TUN 模式驱动
├── Qt6Core.dll          # Qt6 核心库
├── Qt6Gui.dll           # Qt6 GUI 库
├── Qt6Widgets.dll       # Qt6 Widgets 库
└── platforms/           # Qt 平台插件
    └── qwindows.dll     # Windows 平台插件
```

**使用方法:**
1. 双击 `EWP-GUI.exe` 启动图形界面
2. GUI 会自动调用同目录下的 `ewp-core.exe`
3. 或直接运行 `ewp-core.exe` 使用命令行模式
4. TUN 模式需要管理员权限（使用 wintun.dll）

### Linux Package

```
ewp-gui-linux-amd64/
├── EWP-GUI              # Qt6 图形界面程序
├── EWP-GUI.sh           # 启动脚本 (设置库路径)
├── ewp-core             # EWP-Core 内核 (重命名自 ewp-core-client)
├── lib/                 # Qt6 动态库
│   ├── libQt6Core.so.6
│   ├── libQt6Gui.so.6
│   ├── libQt6Widgets.so.6
│   └── ...
└── plugins/             # Qt 平台插件
    └── platforms/
        └── libqxcb.so   # X11 平台插件
```

**使用方法:**
```bash
# 方法 1: 使用启动脚本 (推荐)
./EWP-GUI.sh

# 方法 2: 直接运行 (需要手动设置库路径)
export LD_LIBRARY_PATH="$PWD/lib:$LD_LIBRARY_PATH"
export QT_PLUGIN_PATH="$PWD/plugins"
./EWP-GUI

# 命令行模式
./ewp-core -l 127.0.0.1:1080 -f server.com:443 -token your-uuid
```

---

## Standalone Binaries

如果只需要命令行版本，可下载独立的 Client/Server 二进制文件。

### Client Binaries

```
ewp-core-client-windows-amd64.exe      # Windows x64
ewp-core-client-windows-arm64.exe      # Windows ARM64
ewp-core-client-linux-amd64            # Linux x64
ewp-core-client-linux-arm64            # Linux ARM64
```

### Server Binaries

```
ewp-core-server-linux-amd64            # Linux x64 (主要部署平台)
ewp-core-server-linux-arm64            # Linux ARM64
ewp-core-server-windows-amd64.exe      # Windows x64 (测试用)
```

---

## Release Archives

Release 版本中，GUI 包会打包为压缩包：

- **Windows**: `ewp-gui-v1.0.0-windows-amd64.tar.gz`
- **Linux**: `ewp-gui-v1.0.0-linux-amd64.tar.gz`

解压后即为上述目录结构。

---

## File Naming Convention

### Development Builds (build.yml)

- Client: `ewp-core-client-{os}-{arch}[.exe]`
- Server: `ewp-core-server-{os}-{arch}[.exe]`
- GUI: `ewp-gui-{os}-{arch}/` (目录)

### Release Builds (release.yml)

- Client: `ewp-core-client-{version}-{os}-{arch}[.exe]`
- Server: `ewp-core-server-{version}-{os}-{arch}[.exe]`
- GUI: `ewp-gui-{version}-{os}-{arch}.tar.gz` (压缩包)

---

## Integration Notes

### GUI 调用内核

GUI 程序会按以下优先级查找内核：

1. 同目录下的 `ewp-core.exe` / `ewp-core`
2. 同目录下的 `ewp-core-client.exe` / `ewp-core-client`
3. 系统 PATH 中的 `ewp-core`

### 为什么重命名为 ewp-core？

- 简化文件名，用户更容易识别
- 避免与独立下载的 client 混淆
- GUI 可以硬编码内核文件名，简化配置

---

## Download Recommendations

| 使用场景 | 推荐下载 |
|----------|---------|
| **普通用户** | GUI 包 (`ewp-gui-*.tar.gz`) |
| **命令行用户** | Client 二进制 (`ewp-core-client-*`) |
| **服务器部署** | Server 二进制 (`ewp-core-server-*`) |
| **开发测试** | 所有 artifacts |

---

## Build Workflow Logic

### Step 1: Build Core Client
```yaml
build-core-client:
  outputs: ewp-core-client-{os}-{arch}
```

### Step 2: Build GUI (依赖 Client)
```yaml
build-gui-windows:
  needs: build-core-client
  steps:
    1. Download client binaries
    2. Build GUI
    3. Copy client as ewp-core.exe
    4. Package together
```

### Step 3: Upload Artifacts
```yaml
Upload: ewp-gui-{os}-{arch}/ (目录)
```

This ensures GUI packages always include the matching version of the core.

---

## Expected Package Sizes

### Windows Package
- **Before windeployqt**: ~7 MB (仅 EXE + core)
- **After windeployqt**: ~30-50 MB (包含 Qt6 DLLs + plugins + wintun.dll)

**windeployqt 自动添加的文件:**
- `Qt6Core.dll` (~6 MB)
- `Qt6Gui.dll` (~7 MB)
- `Qt6Widgets.dll` (~4 MB)
- `Qt6Network.dll` (~2 MB) - 如果使用
- `platforms/qwindows.dll` (~2 MB)
- 其他必需的依赖库

### Linux Package
- **Before Qt deps**: ~7 MB (仅 binary + core)
- **After Qt deps**: ~40-60 MB (包含 Qt6 libs + plugins)

**手动复制的 Qt 库:**
- `libQt6Core.so.6` (~5 MB)
- `libQt6Gui.so.6` (~6 MB)
- `libQt6Widgets.so.6` (~4 MB)
- `libQt6Network.so.6` (~2 MB)
- `plugins/platforms/libqxcb.so` (~2 MB)
- 其他 Qt 依赖库

---

## Deployment Tools

### Windows: windeployqt
```cmd
windeployqt --release --no-translations --no-system-d3d-compiler --no-opengl-sw EWP-GUI.exe
```

**参数说明:**
- `--release`: 仅复制 release 版本的库（去除 debug 符号）
- `--no-translations`: 不复制翻译文件（减小体积）
- `--no-system-d3d-compiler`: 不复制 Direct3D 编译器
- `--no-opengl-sw`: 不复制 OpenGL 软件渲染器

### Linux: 手动复制
```bash
# 使用 ldd 查找依赖
ldd EWP-GUI | grep Qt | awk '{print $3}' | xargs -I {} cp {} lib/

# 复制插件
cp -r $Qt6_DIR/plugins/platforms lib/plugins/
```

**为什么不用 linuxdeploy?**
- linuxdeploy 会创建 AppImage，但我们需要目录结构
- 手动控制更灵活，可以精确选择需要的库
- 避免额外的 FUSE 依赖
