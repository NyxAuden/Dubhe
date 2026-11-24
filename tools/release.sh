#!/bin/sh
# 构建可分发产物；不自动上传、不自动生成签名密钥。
# 可复现构建要求显式固定 SOURCE_DATE_EPOCH，并使用 rust-toolchain.toml 的工具链。
# 建议先用 tools/repro-check.sh 验证，再在空 target 目录执行本脚本；已有 target/
# 可能复用旧构建缓存，不能保证与记录哈希一致。
set -eu

cd "$(dirname "$0")/.."

: "${SOURCE_DATE_EPOCH:?请设置固定的 SOURCE_DATE_EPOCH（例如源码归档时间）}"
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
# 去掉构建目录的绝对路径；保留调用方已有的 RUSTFLAGS。
# 空 RUSTFLAGS 前导空格会改变 Cargo 指纹，必须避免。
if [ -n "${RUSTFLAGS:-}" ]; then
    export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$PWD=/build"
else
    export RUSTFLAGS="--remap-path-prefix=$PWD=/build"
fi

DIST_DIR="${DIST_DIR:-dist}"
# 固定且先清空的构建目录，避免已有 target/ 指纹改变产物字节。
# 默认路径与 tools/repro-check.sh 的 A 目录一致，便于对照记录哈希。
RELEASE_TARGET_DIR="${RELEASE_TARGET_DIR:-/tmp/rpk-repro-a}"
rm -rf "$RELEASE_TARGET_DIR"
export CARGO_TARGET_DIR="$RELEASE_TARGET_DIR"
BIN="$RELEASE_TARGET_DIR/release/dubhe"
ARCHIVE="$DIST_DIR/dubhe-0.1.0-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m).tar.gz"

cargo build --locked --release --bin dubhe
mkdir -p "$DIST_DIR"

cp "$BIN" "$DIST_DIR/"
# NOTICE 的「分发义务」要求随二进制附带 NOTICE 本身与 vendor/ 下各组件
# 的原始许可文本。
cp LICENSE NOTICE THIRD-PARTY.md README.md "$DIST_DIR/"
cp -R packaging/systemd "$DIST_DIR/" 2>/dev/null || true
mkdir -p "$DIST_DIR/examples" "$DIST_DIR/licenses"
cp examples/socks5.json "$DIST_DIR/examples/"
for dir in vendor/*/; do
    component="$(basename "$dir")"
    for file in "$dir"LICENSE* "$dir"COPYING*; do
        [ -f "$file" ] || continue
        cp "$file" "$DIST_DIR/licenses/${component}-$(basename "$file")"
    done
done

SBOM_FILE=""
if command -v cargo-cyclonedx >/dev/null 2>&1; then
    # cargo-cyclonedx 没有 --output；它把文件写在 package 根目录，
    # 并对 workspace 每个成员各生成一个。只保留根包结果到 dist/。
    cargo cyclonedx --format json --override-filename sbom
    mv sbom.json "$DIST_DIR/sbom.cdx.json"
    rm -f vendor/shadowsocks/sbom.json
    SBOM_FILE="sbom.cdx.json"
else
    printf '%s\n' "提示：未安装 cargo-cyclonedx，未生成 SBOM；安装后再发布。" >&2
fi

tar -czf "$ARCHIVE" -C "$DIST_DIR" \
    dubhe LICENSE NOTICE THIRD-PARTY.md README.md systemd examples licenses \
    ${SBOM_FILE:+"$SBOM_FILE"}

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
else
    shasum -a 256 "$ARCHIVE" > "$ARCHIVE.sha256"
fi

if command -v minisign >/dev/null 2>&1 && [ -n "${MINISIGN_SECRET_KEY:-}" ]; then
    minisign -Sm "$ARCHIVE" -s "$MINISIGN_SECRET_KEY"
else
    printf '%s\n' "提示：未签名；设置 MINISIGN_SECRET_KEY 后可用 minisign 签名。" >&2
fi

printf 'artifact: %s\n' "$ARCHIVE"
cat "$ARCHIVE.sha256"
