#!/usr/bin/env bash
# Run inside devkitpro/devkita64, or with a preinstalled devkitPro SDK.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEVKITPRO="${DEVKITPRO:-/opt/devkitpro}"
DEPS="$ROOT/build/deps"
mkdir -p "$DEPS"
checkout() {
    local repo="$1" revision="$2" destination="$3"
    if [ ! -d "$destination/.git" ]; then
        git init -q "$destination"
        git -C "$destination" remote add origin "$repo"
    fi
    git -C "$destination" fetch --depth 1 origin "$revision"
    git -C "$destination" checkout --detach FETCH_HEAD
    test "$(git -C "$destination" rev-parse HEAD)" = "$revision"
}
if [ "${1:-}" != --packager-only ]; then
    # The pinned CI image supplies the toolchain; portlibs are recorded in its manifest.
    dkp-pacman -S --needed --noconfirm switch-sdl2 switch-sdl2_ttf switch-ffmpeg switch-libopus switch-mbedtls
    checkout https://github.com/protobuf-c/protobuf-c.git 8c201f6e47a53feaab773922a743091eb6c8972a "$DEPS/protobuf-c"
    cmake -S "$ROOT/cmake/deps/protobuf-c" -B "$DEPS/protobuf-build" \
        -DCMAKE_TOOLCHAIN_FILE="$DEVKITPRO/cmake/Switch.cmake" \
        -DCMAKE_BUILD_TYPE=Release -DPROTOBUF_SOURCE="$DEPS/protobuf-c" \
        -DCMAKE_INSTALL_PREFIX="$DEVKITPRO/portlibs/switch"
    cmake --build "$DEPS/protobuf-build" -j"$(nproc)"
    cmake --install "$DEPS/protobuf-build"
    dkp-pacman -Q > "$DEPS/devkitpro-packages.txt"
fi
checkout https://github.com/dragonflylee/hacBrewPack.git 745b16ecfc9ce055743067d200572204cb2aac6c "$DEPS/hacBrewPack"
cp "$DEPS/hacBrewPack/config.mk.template" "$DEPS/hacBrewPack/config.mk"
make -C "$DEPS/hacBrewPack" -j"$(nproc)"
printf 'hacBrewPack: %s\n' "$DEPS/hacBrewPack/hacbrewpack"
