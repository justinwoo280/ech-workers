@echo off
chcp 65001 >nul
echo === 重新生成 Protobuf 文件 ===

:: 确保安装了正确版本的 protoc-gen-go
echo 安装/更新 protoc-gen-go...
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

:: 生成 proto 文件
echo 生成 proto 文件...
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative tunnel.proto

if errorlevel 1 (
    echo 生成失败! 请确保已安装 protoc
    pause
    exit /b 1
)

echo === 生成成功! ===
pause
