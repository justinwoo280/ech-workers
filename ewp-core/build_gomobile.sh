#!/bin/bash

# GoMobile 构建脚本
# 用于生成 Android AAR 和 iOS Framework

set -e

echo "🚀 开始构建 GoMobile 绑定..."

# 检查环境
if ! command -v gomobile &> /dev/null; then
    echo "❌ gomobile 未安装，请先安装："
    echo "go install golang.org/x/mobile/cmd/gomobile@latest"
    exit 1
fi

if ! command -v gomobile bind &> /dev/null; then
    echo "❌ gomobile bind 未找到，正在初始化..."
    gomobile init
fi

# 设置环境变量
export GOPATH="$HOME/go"
export GOOS=android
export GOARCH=arm64

# 创建输出目录
mkdir -p output/android
mkdir -p output/ios

echo "📦 构建 Android AAR..."

# 构建 Android AAR (arm64)
gomobile bind -target=android/arm64 -o output/android/ewp-core-arm64.aar ./ewpmobile

# 构建 Android AAR (arm)
gomobile bind -target=android/arm -o output/android/ewp-core-arm.aar ./ewpmobile

# 构建 Android AAR (x86_64)
gomobile bind -target=android/amd64 -o output/android/ewp-core-x86_64.aar ./ewpmobile

echo "📦 构建 iOS Framework..."

# 构建 iOS Framework (arm64)
gomobile bind -target=ios/arm64 -o output/ios/ewp-core-arm64.framework ./ewpmobile

# 构建 iOS Framework (x86_64)
gomobile bind -target=ios/amd64 -o output/ios/ewp-core-x86_64.framework ./ewpmobile

# 构建 iOS Framework (模拟器)
gomobile bind -target=ios -o output/ios/ewp-core.framework ./ewpmobile

echo "✅ 构建完成！"

# 复制到 Android 项目
if [ -d "../ewp-NG/android/app/libs" ]; then
    echo "📋 复制 AAR 到 Android 项目..."
    cp output/android/ewp-core-arm64.aar ../ewp-NG/android/app/libs/
    cp output/android/ewp-core-arm.aar ../ewp-NG/android/app/libs/
    cp output/android/ewp-core-x86_64.aar ../ewp-NG/android/app/libs/
    echo "✅ AAR 已复制到 Android 项目"
else
    echo "⚠️  Android 项目路径不存在，请手动复制 AAR 文件"
fi

echo ""
echo "📊 构建结果："
echo "Android AAR:"
ls -la output/android/
echo ""
echo "iOS Framework:"
ls -la output/ios/

echo ""
echo "🎯 下一步："
echo "1. 将 AAR 文件添加到 Android 项目的 libs 目录"
echo "2. 在 build.gradle 中添加依赖"
echo "3. 更新 Android 项目中的 EWPClient 类"
echo "4. 测试连接功能"
