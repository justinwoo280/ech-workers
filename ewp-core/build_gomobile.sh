#!/bin/bash

# GoMobile 构建脚本 - 生成 Android AAR
# 用法: ./build_gomobile.sh [android|ios|all]

set -e

TARGET=${1:-android}

# 检查 gomobile
if ! command -v gomobile &> /dev/null; then
    echo "[INFO] Installing gomobile..."
    go install golang.org/x/mobile/cmd/gomobile@latest
    go install golang.org/x/mobile/cmd/gobind@latest
fi

if [ -z "$ANDROID_NDK_HOME" ] && [ -n "$ANDROID_HOME" ]; then
    NDK_DIR="$ANDROID_HOME/ndk"
    if [ -d "$NDK_DIR" ]; then
        LATEST_NDK=$(ls "$NDK_DIR" | sort -V | tail -1)
        export ANDROID_NDK_HOME="$NDK_DIR/$LATEST_NDK"
        echo "[INFO] Using NDK: $ANDROID_NDK_HOME"
    fi
fi

gomobile init

mkdir -p output/android output/ios

ANDROID_OUT="../ewp-android/app/libs"

if [ "$TARGET" = "android" ] || [ "$TARGET" = "all" ]; then
    echo "[BUILD] Android AAR (all arch)..."
    gomobile bind \
        -v \
        -target=android \
        -androidapi=21 \
        -ldflags="-s -w" \
        -o output/android/ewp-core.aar \
        ./ewpmobile
    echo "[OK] output/android/ewp-core.aar"

    if [ -d "$ANDROID_OUT" ]; then
        cp output/android/ewp-core.aar "$ANDROID_OUT/ewp-core.aar"
        echo "[OK] Copied to $ANDROID_OUT"
    fi
fi

if [ "$TARGET" = "ios" ] || [ "$TARGET" = "all" ]; then
    echo "[BUILD] iOS xcframework..."
    gomobile bind \
        -v \
        -target=ios \
        -ldflags="-s -w" \
        -o output/ios/EwpCore.xcframework \
        ./ewpmobile
    echo "[OK] output/ios/EwpCore.xcframework"
fi

echo ""
echo "=== Build Complete ==="
[ -d output/android ] && ls -lh output/android/ 2>/dev/null || true
[ -d output/ios ]     && ls -lh output/ios/     2>/dev/null || true
