@echo off
REM EWP-Core Android AAR 编译脚本（Windows 版本）
REM 用于生成 Android AAR 供 Kotlin 调用

REM 配置 Go 代理（加速依赖下载）
set GO111MODULE=on
set GOPROXY=https://goproxy.cn,direct

echo ========================================
echo EWP-Core Android AAR Builder
echo ========================================
echo.

REM 检查 Go 环境
where go >nul 2>nul
if %errorlevel% neq 0 (
    echo [错误] 未找到 Go 环境，请先安装 Go 1.24+
    echo 下载地址: https://golang.org/dl/
    exit /b 1
)

echo [1/5] 检查 Go 版本...
go version
echo.

REM 检查 gomobile
where gomobile >nul 2>nul
if %errorlevel% neq 0 (
    echo [2/5] 安装 gomobile...
    go install golang.org/x/mobile/cmd/gomobile@latest
    if %errorlevel% neq 0 (
        echo [错误] gomobile 安装失败
        exit /b 1
    )
    
    echo [3/5] 初始化 gomobile...
    gomobile init
    if %errorlevel% neq 0 (
        echo [错误] gomobile 初始化失败
        exit /b 1
    )
) else (
    echo [2/5] gomobile 已安装
    echo [3/5] gomobile 已初始化
)
echo.

REM 创建输出目录
if not exist "output" mkdir output
if not exist "output\android" mkdir output\android

echo [4/5] 编译 Android AAR...
echo 目标架构: arm64, arm, amd64
echo 这可能需要几分钟...
echo.

REM 编译 AAR（所有架构）
gomobile bind -v -target=android -androidapi 21 -o output\android\ewp-core.aar .\ewpmobile
if %errorlevel% neq 0 (
    echo [错误] AAR 编译失败
    exit /b 1
)

echo.
echo [5/5] 编译完成！
echo.
echo ========================================
echo 构建结果:
echo ========================================
dir output\android\ewp-core.aar
echo.

REM 检查是否有 Android 项目
if exist "..\ech-workers-NG\app\libs" (
    echo [可选] 发现 Android 项目，是否复制 AAR？
    echo 按任意键复制，Ctrl+C 取消...
    pause >nul
    
    copy /Y output\android\ewp-core.aar ..\ech-workers-NG\app\libs\
    if %errorlevel% equ 0 (
        echo [成功] AAR 已复制到 Android 项目
    )
)

echo.
echo ========================================
echo 下一步操作:
echo ========================================
echo 1. 将 ewp-core.aar 添加到 Android 项目的 libs 目录
echo 2. 在 build.gradle.kts 中添加依赖:
echo    implementation(files("libs/ewp-core.aar"))
echo 3. 参考 ewpmobile\EWPVpnExample.kt 实现 VPN 功能
echo 4. 运行 Android 应用测试
echo ========================================
echo.

pause
