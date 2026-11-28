#!/bin/bash
# 编译一批测试目标并导出可执行文件。
# 用法: build-batch.sh <batchfile>
set -u
cd /Users/ice/WorkSpace/dubhe || exit 1
export CARGO_TARGET_DIR=/tmp/dubhe-xbuild
export CC_x86_64_unknown_linux_musl=/tmp/x86_64-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=/tmp/x86_64-linux-musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$PWD/tools/rust-lld-cc.py"

batch="$1"
tag="$(basename "$batch" | sed 's/suite-batch-//')"
mkdir -p /tmp/out-$tag

# 用数组传参，避免空格被当成一个整体
args=()
while IFS= read -r name; do
    [ -n "$name" ] && args+=(--test "$name")
done < "$batch"

echo "batch $tag: $(( ${#args[@]} / 2 )) targets"
CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_STRIP=symbols \
cargo test --locked --no-run --target x86_64-unknown-linux-musl -j 1 \
    "${args[@]}" --message-format=json > "/tmp/art-$tag.jsonl" 2>"/tmp/art-$tag.err"
echo "cargo_exit=$?"
