#!/bin/sh
# 依赖公告与许可证门禁。工具未安装时明确失败，不静默跳过。
set -eu

cd "$(dirname "$0")/.."

if ! command -v cargo-deny >/dev/null 2>&1; then
    printf '%s\n' "缺少 cargo-deny；安装固定版本：cargo install cargo-deny --version 0.20.2 --locked" >&2
    printf '%s\n' "不要不指定版本：cargo-deny 0.22 要求 rustc 1.95，本项目固定 1.91.0。" >&2
    exit 1
fi
cargo deny check

if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit
else
    printf '%s\n' "提示：未安装 cargo-audit，cargo-deny 的 advisories 检查已执行。" >&2
fi
