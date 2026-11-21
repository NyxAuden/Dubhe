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

printf '%s\n' "ci: all checks passed"
