#!/usr/bin/env bash
# Offline audit: exit 1 means the production code violated a wire/memory invariant.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
audit_build="$repo_dir/build/ihslib-audit"
cmake -S "$repo_dir/third_party/ihslib" -B "$audit_build" \
    -DCMAKE_BUILD_TYPE=Debug -DIHSLIB_HID_SDL=ON -DIHSLIB_HID_SDL_USE_SDL2=ON
cmake --build "$audit_build" --target ihslib ihs-test-session -j4
cc -g -UNDEBUG \
    -I"$repo_dir/third_party/ihslib/include" \
    -I"$repo_dir/third_party/ihslib/src" \
    -I"$repo_dir/third_party/ihslib/tests" \
    "$repo_dir/scripts/audit-ihslib-control.c" -o "$audit_build/audit-control" \
    -Wl,--start-group "$audit_build/libihslib.a" \
    "$audit_build/tests/common/libihs-test-session.a" \
    "$audit_build/src/protobuf/libihs-protobuf.a" \
    "$audit_build/src/platforms/libihs-platforms.a" \
    -Wl,--end-group -lprotobuf-c -lm -lmbedcrypto -lpthread
"$audit_build/audit-control"
