@echo off
chcp 65001 >nul
echo === 编译 ECH 内核 ===

:: 编译内核
echo 正在编译...
go build -o ech-core.exe -ldflags="-s -w" ech-workers.go
if errorlevel 1 (
    echo 编译失败!
    pause
    exit /b 1
)

:: 复制到客户端目录
echo 正在复制到客户端目录...
copy /Y ech-core.exe ..\tunnel\ >nul
copy /Y ech-core.exe ..\workers\ >nul

echo.
echo === 编译成功! ===
echo 输出文件: ech-core.exe
echo 已复制到: tunnel\ 和 workers\ 目录
pause
