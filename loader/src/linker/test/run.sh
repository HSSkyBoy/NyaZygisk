#!/usr/bin/env bash
# Build the custom-linker test harness and run it inside a bionic chroot for
# each architecture. Requires the dev-env to be set up (NDK + rootfs under
# /tmp/claude-0/rootfs). Not part of the Gradle build.
#
#   run.sh [aarch64|x86_64] ...    (default: both)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LINKER_DIR="$(dirname "$HERE")"
INCLUDE_DIR="$LINKER_DIR/../include"
NDK="${ANDROID_NDK_HOME:-/opt/android-sdk/ndk/27.2.12479018}"
BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
ROOTFS_BASE="${ROOTFS_BASE:-/tmp/claude-0/rootfs}"
OUT="${OUT:-/tmp/claude-0/linker-test}"
mkdir -p "$OUT"

declare -A TRIPLE=( [aarch64]=aarch64-linux-android [x86_64]=x86_64-linux-android )
declare -A ROOTDIR=( [aarch64]=arm64-v8a [x86_64]=x86_64 )
API=30

archs=("$@")
[ ${#archs[@]} -eq 0 ] && archs=(aarch64 x86_64)

for arch in "${archs[@]}"; do
    cc="$BIN/${TRIPLE[$arch]}$API-clang++"
    rootfs="$ROOTFS_BASE/${ROOTDIR[$arch]}"
    echo "############ $arch ############"

    # Three variants of the test lib, covering the relocation encodings a real
    # module might use.
    "$cc" -shared -fPIC -std=c++20 -static-libstdc++ \
        -Wl,--pack-dyn-relocs=android "$HERE/test_lib.cpp" -o "$OUT/$arch-aps2.so"
    "$cc" -shared -fPIC -std=c++20 -static-libstdc++ \
        -Wl,--pack-dyn-relocs=relr -Wl,-z,max-page-size=65536 \
        "$HERE/test_lib.cpp" -o "$OUT/$arch-relr64k.so"
    "$cc" -shared -fPIC -std=c++20 -static-libstdc++ \
        -Wl,--pack-dyn-relocs=none "$HERE/test_lib.cpp" -o "$OUT/$arch-plain.so"

    # Module-shaped lib linked against SHARED libc++ (DT_NEEDED libc++_shared.so),
    # staged into the rootfs so the system linker can resolve it for the module's
    # cross-DSO C++. Exercises what the static-libstdc++ test_lib cannot.
    "$cc" -shared -fPIC -std=c++20 \
        "$HERE/mod_lib.cpp" -o "$OUT/$arch-mod.so"

    # Runner: compile the linker sources straight in (static lib equivalent).
    # static-libstdc++ so the chroot needs no libc++_shared.so.
    "$cc" -std=c++23 -fno-rtti -Wall -Wextra -static-libstdc++ \
        -I"$INCLUDE_DIR" -I"$LINKER_DIR" \
        "$HERE/runner.cpp" \
        "$LINKER_DIR/linker.cpp" "$LINKER_DIR/relocate.cpp" "$LINKER_DIR/interpose.cpp" "$LINKER_DIR/cfi.cpp" \
        -llog -o "$OUT/$arch-runner"

    # Stage into the rootfs and run under chroot (qemu-user handles aarch64).
    dst="$rootfs/data/local/tmp"
    mkdir -p "$dst"
    cp "$OUT/$arch-runner" "$dst/runner"
    cp "$OUT/$arch-aps2.so" "$OUT/$arch-relr64k.so" "$OUT/$arch-plain.so" "$OUT/$arch-mod.so" "$dst/"
    mountpoint -q "$rootfs/proc" || mount -t proc proc "$rootfs/proc"
    mountpoint -q "$rootfs/dev" || mount --bind /dev "$rootfs/dev"

    chroot "$rootfs" /data/local/tmp/runner \
        /data/local/tmp/$arch-plain.so \
        /data/local/tmp/$arch-aps2.so \
        /data/local/tmp/$arch-relr64k.so

    echo "---- module-shaped (shared libc++) ----"
    chroot "$rootfs" /data/local/tmp/runner --module /data/local/tmp/$arch-mod.so
done
