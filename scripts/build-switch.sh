#!/usr/bin/env bash
# Switch 目标交叉构建（devkitA64）。产物：build/switch/app/nsteamlink.nro
# 依赖：DEVKITPRO 指向 devkitPro 安装目录（本机 /opt/devkitpro）。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEVKITPRO="${DEVKITPRO:-/opt/devkitpro}"
BUILD_TYPE="${NSL_BUILD_TYPE:-Release}"
BUILD_DIR="${NSL_BUILD_DIR:-$ROOT/build/switch}"
TOOLCHAIN="${DEVKITPRO}/cmake/Switch.cmake"

[ -f "$TOOLCHAIN" ] || { echo "错误: 找不到工具链文件 $TOOLCHAIN" >&2; exit 1; }

cmake -S "$ROOT" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" "$@"
cmake --build "$BUILD_DIR" -j"$(nproc)"

NROS=(
    "$BUILD_DIR/app/nsteamlink.nro"
    "$BUILD_DIR/tools/switch-discover/switch-discover.nro"
    "$BUILD_DIR/client/switch-stream-selftest.nro"
)
for NRO in "${NROS[@]}"; do
    if [ -f "$NRO" ]; then
        echo "== 产物: $NRO =="
    fi
done
echo "   真机安装: 复制到 SD 卡 sd:/switch/ 下，经 Title Redirection 方式启动 hbmenu 后运行"
