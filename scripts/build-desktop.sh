#!/usr/bin/env bash
# 桌面目标构建。产物：build/desktop/app/nsteamlink
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_TYPE="${NSL_BUILD_TYPE:-Release}"

cmake -S "$ROOT" -B "$ROOT/build/desktop" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" "$@"
cmake --build "$ROOT/build/desktop" -j"$(nproc)"

echo "== 产物: $ROOT/build/desktop/app/nsteamlink =="
