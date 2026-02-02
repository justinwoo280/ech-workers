# AAR Library Directory

## 编译 ewp-core.aar

在使用前，请先编译 ewp-core AAR 库并放置到此目录：

```bash
# 1. 进入 ewp-core 目录
cd ..\..\ewp-core

# 2. 运行 Android 编译脚本
build_android.bat

# 3. 复制生成的 AAR 到此目录
copy output\android\ewp-core.aar ..\ewp-android\app\libs\
```

## 预期文件

编译完成后，此目录应包含：
- `ewp-core.aar` - EWP 核心库 (Android)

## 注意事项

- AAR 文件大小约 20-30 MB（包含 arm64、arm、x86_64 三种架构）
- 确保使用 Go 1.23+ 和 gomobile 工具编译
- 编译时间约 3-5 分钟，取决于机器性能
