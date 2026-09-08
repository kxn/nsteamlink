#!/usr/bin/env bash
# 桌面目标构建。产物：build/desktop/app/nsteamlink
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_TYPE="${NSL_BUILD_TYPE:-Release}"
BUILD_DIR="${NSL_BUILD_DIR:-$ROOT/build/desktop}"

cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" "$@"
cmake --build "$BUILD_DIR" -j"$(nproc)"

echo "== 产物: $BUILD_DIR/app/nsteamlink =="
