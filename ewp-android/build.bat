@echo off
chcp 65001 >nul
echo ================================
echo EWP Android 构建脚本
echo ================================
echo.

set "CORE_PATH=..\ewp-core"
set "AAR_SOURCE=%CORE_PATH%\output\android\ewp-core.aar"
set "AAR_DEST=app\libs\ewp-core.aar"

echo [1/3] 检查 ewp-core.aar...
if not exist "%AAR_SOURCE%" (
    echo ❌ 未找到 ewp-core.aar
    echo 正在编译 ewp-core...
    cd %CORE_PATH%
    call build_android.bat
    if errorlevel 1 (
        echo ❌ ewp-core 编译失败
        pause
        exit /b 1
    )
    cd ..\ewp-android
)

echo ✅ ewp-core.aar 已找到
echo.

echo [2/3] 复制 ewp-core.aar...
if not exist "app\libs" mkdir app\libs
copy /Y "%AAR_SOURCE%" "%AAR_DEST%"
if errorlevel 1 (
    echo ❌ 复制失败
    pause
    exit /b 1
)
echo ✅ AAR 已复制
echo.

echo [3/3] 编译 Android 应用...
call gradlew.bat assembleDebug
if errorlevel 1 (
    echo ❌ 编译失败
    pause
    exit /b 1
)

echo.
echo ================================
echo ✅ 编译成功！
echo ================================
echo.
echo APK 位置：app\build\outputs\apk\debug\app-debug.apk
echo.

pause
