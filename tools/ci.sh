#!/bin/sh
# 本地/CI 基础门禁。需要 rust-toolchain.toml 固定的工具链及 rustfmt、clippy。
# 首次使用：rustup component add rustfmt clippy
set -eu

cd "$(dirname "$0")/.."
export CARGO_INCREMENTAL=0

cargo fmt --all -- --check
# 本项目代码零警告；vendor/ 里固定版本的上游源码不在此门禁范围内。
# `--` 之后的参数只作用于当前 crate，不会把第三方依赖的警告升级为错误。
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release --bin dubhe

# `clippy --all-targets` 与 `test --all-targets` 各自产生一套产物，叠加约
# 6–8 GiB：76 个集成测试二进制各 85–101 MiB，每个都静态链接整份代码。
# 这是 Rust 集成测试的结构性成本，无法通过配置消除，只能跑完回收。
# 设 DUHBE_CI_KEEP_TARGET=1 可保留产物用于调试。
if [ "${DUHBE_CI_KEEP_TARGET:-0}" != "1" ]; then
    cargo clean -p dubhe 2>/dev/null || true
    printf '%s\n' "ci: 已回收本项目构建产物（DUHBE_CI_KEEP_TARGET=1 可保留）"
fi

printf '%s\n' "ci: all checks passed"
