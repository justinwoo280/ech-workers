# GitHub Actions Workflows

This directory contains automated build and release workflows for the EWP-Workers project.

## Workflows

### 1. `build.yml` - Continuous Build

**Triggers:**
- Push to `main`, `master`, or `dev` branches
- Pull requests to `main` or `master`
- Manual dispatch via GitHub Actions UI

**What it builds:**
- **EWP-Core Client**: Cross-platform proxy client (Windows, Linux - amd64/arm64)
- **EWP-Core Server**: Proxy server (Linux, Windows)
- **EWP-GUI**: Graphical user interface (Windows, Linux) - **包含内核**

**Artifacts:**
- `ewp-core-client-binaries`: All client executables
- `ewp-core-server-binaries`: All server executables
- `ewp-gui-windows-binaries`: Windows GUI package (包含 ewp-core.exe)
- `ewp-gui-linux-binaries`: Linux GUI package (包含 ewp-core)

---

### 2. `release.yml` - Create Release

**Triggers:**
- Manual dispatch only (via GitHub Actions UI)

**Required Inputs:**
- `version`: Release version tag (e.g., `v1.0.0`, `v1.2.3-beta`)
- `prerelease`: Whether to mark as pre-release (default: `false`)

**What it does:**
1. Validates version tag format
2. Creates and pushes a Git tag
3. Builds all components with version embedded
4. Generates release notes
5. Creates SHA256 checksums
6. Publishes GitHub Release with all artifacts

**Usage:**
1. Go to **Actions** → **Create Release**
2. Click **Run workflow**
3. Enter version (e.g., `v1.0.0`)
4. Optionally check **Mark as pre-release**
5. Click **Run workflow**

---

## Build Matrix

### EWP-Core Client

| Platform | Architecture | Binary Name |
|----------|-------------|-------------|
| Windows | amd64 | `ewp-core-client-windows-amd64.exe` |
| Windows | arm64 | `ewp-core-client-windows-arm64.exe` |
| Linux | amd64 | `ewp-core-client-linux-amd64` |
| Linux | arm64 | `ewp-core-client-linux-arm64` |

### EWP-Core Server

| Platform | Architecture | Binary Name |
|----------|-------------|-------------|
| Linux | amd64 | `ewp-core-server-linux-amd64` |
| Linux | arm64 | `ewp-core-server-linux-arm64` |
| Windows | amd64 | `ewp-core-server-windows-amd64.exe` |

### EWP-GUI (包含内核 + Qt 依赖)

| Platform | Architecture | Package Name | 包含内容 |
|----------|-------------|-------------|---------|
| Windows | amd64 | `ewp-gui-windows-amd64/` | `EWP-GUI.exe`, `ewp-core.exe`, `wintun.dll`, Qt6 DLLs, plugins |
| Linux | amd64 | `ewp-gui-linux-amd64/` | `EWP-GUI`, `EWP-GUI.sh`, `ewp-core`, Qt6 libs, plugins |

---

## Requirements

### GitHub Repository Settings

1. **Secrets**: No additional secrets required (uses built-in `GITHUB_TOKEN`)
2. **Permissions**: Workflows need write permissions for:
   - Contents (to create releases)
   - Actions (to upload artifacts)

### Build Dependencies

- **Go**: Version 1.24+ (handled by `actions/setup-go@v5`)
- **Qt6**: Version 6.6+ (handled by `jurplel/install-qt-action@v3`)
- **CMake**: Version 3.16+ (pre-installed on runners)

---

## Version Tagging Convention

Follow semantic versioning:
- **Release**: `v1.0.0`, `v2.3.1`
- **Pre-release**: `v1.0.0-beta`, `v2.0.0-rc1`, `v1.5.0-alpha`

**Valid formats:**
- `v[MAJOR].[MINOR].[PATCH]`
- `v[MAJOR].[MINOR].[PATCH]-[PRERELEASE]`

---

## Troubleshooting

### Build Failures

**Go version mismatch:**
```yaml
# Update Go version in workflow files
uses: actions/setup-go@v5
with:
  go-version: '1.24'  # Change this
```

**Qt6 installation issues:**
```yaml
# Try different Qt version
uses: jurplel/install-qt-action@v3
with:
  version: '6.7.*'  # Update version
```

### Release Issues

**Invalid version tag:**
```
Error: Invalid version format
```
- Ensure version starts with `v`
- Follow format: `v1.0.0` or `v1.0.0-beta`

**Permission denied:**
```
Error: Resource not accessible by integration
```
- Check repository settings → Actions → General
- Enable **Read and write permissions**

---

## Manual Build Locally

### Client
```bash
cd ewp-core/cmd/client
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ewp-core-client .
```

### Server
```bash
cd ewp-core/cmd/server
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ewp-core-server .
```

### GUI
```bash
cd ewp-gui
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

---

## Platform Support

**Currently Supported:**
- ✅ Windows (amd64, arm64)
- ✅ Linux (amd64, arm64)

**Not Yet Supported:**
- ⚠️ macOS (compatibility work in progress)
- ⚠️ Android (not included in CI/CD)

## Package Structure

### GUI Package (开箱即用)

**Windows:**
```
ewp-gui-windows-amd64/
├── EWP-GUI.exe          # 图形界面
├── ewp-core.exe         # 内核程序
├── wintun.dll           # TUN 驱动
├── Qt6*.dll             # Qt6 动态库
└── platforms/           # Qt 插件
```

**Linux:**
```
ewp-gui-linux-amd64/
├── EWP-GUI              # 图形界面
├── EWP-GUI.sh           # 启动脚本
├── ewp-core             # 内核程序
├── lib/                 # Qt6 动态库
└── plugins/             # Qt 插件
```

### Release Archives

- **Build Workflow**: 上传目录结构
- **Release Workflow**: 打包为 `.tar.gz` 压缩包

## Notes

- **GUI 已包含内核**: 用户下载 GUI 即可使用，无需单独下载 client
- GUI builds use Qt6 and require appropriate toolchains
- All binaries are stripped (`-s -w`) to reduce size
- Release workflow embeds version via `-X main.Version`
- Cross-compilation is handled by Go's GOOS/GOARCH flags
