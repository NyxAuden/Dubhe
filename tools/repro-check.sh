#!/bin/sh
# 在两个全新 target 目录中构建同一 release，比较 SHA-256。
# 必须显式固定 SOURCE_DATE_EPOCH；只证明相同源码/工具链/平台下的可复现性。
set -eu

cd "$(dirname "$0")/.."
: "${SOURCE_DATE_EPOCH:?请设置固定的 SOURCE_DATE_EPOCH}"
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
# 避免空 RUSTFLAGS 前导空格改变 Cargo 指纹，导致同一份源码出现不同字节。
if [ -n "${RUSTFLAGS:-}" ]; then
    export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$PWD=/build"
else
    export RUSTFLAGS="--remap-path-prefix=$PWD=/build"
fi

# 使用固定的 target 前缀，避免绝对路径差异被部分构建脚本写入产物；
# 并发运行本脚本会互相干扰，验收时应串行执行。
TARGET_A="${REPRO_TARGET_A:-/tmp/rpk-repro-a}"
TARGET_B="${REPRO_TARGET_B:-/tmp/rpk-repro-b}"
rm -rf "$TARGET_A" "$TARGET_B"
trap 'rm -rf "$TARGET_A" "$TARGET_B"' EXIT

CARGO_TARGET_DIR="$TARGET_A" cargo build --locked --release --bin dubhe
CARGO_TARGET_DIR="$TARGET_B" cargo build --locked --release --bin dubhe

A="$TARGET_A/release/dubhe"
B="$TARGET_B/release/dubhe"
if command -v sha256sum >/dev/null 2>&1; then
    HASH_A="$(sha256sum "$A" | awk '{print $1}')"
    HASH_B="$(sha256sum "$B" | awk '{print $1}')"
else
    HASH_A="$(shasum -a 256 "$A" | awk '{print $1}')"
    HASH_B="$(shasum -a 256 "$B" | awk '{print $1}')"
fi

printf 'a: %s\nb: %s\n' "$HASH_A" "$HASH_B"
if [ "$HASH_A" != "$HASH_B" ]; then
    printf '%s\n' "repro-check: binaries differ" >&2
    exit 1
fi
printf '%s\n' "repro-check: identical"
