#!/usr/bin/env bash
# Pinned protobuf C++ runtime for SNS on Switch. Never uses a host libprotobuf
# as the target runtime. The compiler is host-runnable and version-matched.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEVKITPRO="${DEVKITPRO:-/opt/devkitpro}"
NSL_SNS_DEPS="$ROOT/build/deps"
NSL_PROTO_SOURCE="$NSL_SNS_DEPS/protobuf-cpp"
NSL_PROTO_PIN=f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c
mkdir -p "$NSL_SNS_DEPS"
if [ ! -d "$NSL_PROTO_SOURCE/.git" ]; then
    git init -q "$NSL_PROTO_SOURCE"
    git -C "$NSL_PROTO_SOURCE" remote add origin https://github.com/protocolbuffers/protobuf.git
fi
if [ "$(git -C "$NSL_PROTO_SOURCE" rev-parse HEAD 2>/dev/null || true)" != "$NSL_PROTO_PIN" ]; then
    git -C "$NSL_PROTO_SOURCE" fetch --depth 1 origin "$NSL_PROTO_PIN"
    git -C "$NSL_PROTO_SOURCE" checkout --detach FETCH_HEAD
fi
test "$(git -C "$NSL_PROTO_SOURCE" rev-parse HEAD)" = "$NSL_PROTO_PIN"
for NSL_PROTO_PATCH in "$ROOT"/third_party/patches/protobuf/*.patch; do
    if ! git -C "$NSL_PROTO_SOURCE" apply --reverse --check "$NSL_PROTO_PATCH" 2>/dev/null; then
        git -C "$NSL_PROTO_SOURCE" apply "$NSL_PROTO_PATCH"
    fi
done
NSL_PROTO_COMPILER="$(command -v protoc || true)"
if [ -z "$NSL_PROTO_COMPILER" ] || [ "$("$NSL_PROTO_COMPILER" --version)" != 'libprotoc 3.21.12' ]; then
    cmake -S "$NSL_PROTO_SOURCE/cmake" -B "$NSL_SNS_DEPS/protobuf-cpp-host" \
        -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_WITH_ZLIB=OFF
    cmake --build "$NSL_SNS_DEPS/protobuf-cpp-host" --target protoc -j"$(nproc)"
    NSL_PROTO_COMPILER="$NSL_SNS_DEPS/protobuf-cpp-host/protoc"
fi
mkdir -p "$NSL_SNS_DEPS/sns-host/bin"
NSL_PROTO_COMPILER="$(readlink -f "$NSL_PROTO_COMPILER")"
ln -sfn "$NSL_PROTO_COMPILER" "$NSL_SNS_DEPS/sns-host/bin/protoc"
cmake -S "$NSL_PROTO_SOURCE/cmake" -B "$NSL_SNS_DEPS/protobuf-cpp-switch" \
    -DCMAKE_TOOLCHAIN_FILE="$DEVKITPRO/cmake/Switch.cmake" -DCMAKE_BUILD_TYPE=Release \
    -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_PROTOC_BINARIES=OFF -Dprotobuf_BUILD_LIBPROTOC=OFF \
    -Dprotobuf_WITH_ZLIB=OFF -Dprotobuf_DISABLE_RTTI=ON \
    -DCMAKE_INSTALL_PREFIX="$NSL_SNS_DEPS/sns-switch"
cmake --build "$NSL_SNS_DEPS/protobuf-cpp-switch" -j"$(nproc)"
cmake --install "$NSL_SNS_DEPS/protobuf-cpp-switch"
