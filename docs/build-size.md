# 构建产物体积

`target/` 的占用与源码规模不成比例，主要来自三个结构性原因，不是配置错误。

## 构成

| 项 | 量级 | 说明 |
|---|---|---|
| 集成测试二进制 | **~6 GiB** | `tests/` 下 76 个文件各自是一个 test crate，每个都静态链接全部依赖（rustls、aws-lc-rs、quinn、h3、smoltcp、boringtun、prost 等），单个约 78–87 MiB |
| 本项目 rlib | ~150 MiB | lib 与 lib-test 两份，自身代码带行号表 |
| 依赖 rlib | ~420 MiB | 只编译一次，被上面的二进制共享 |
| release + LTO | 数 GiB 峰值 | `lto="thin"`、`codegen-units=1` 的中间产物；构建结束后大部分会被回收 |
| incremental | 最多 ~16 GiB | 仅 dev 构建；`[profile.test]` 已显式关闭 |

## 已生效的约束

- `[profile.test] debug = false`：测试二进制不再带自身代码的调试信息（单文件 87 → 78 MiB）。
  需要行号时用 `CARGO_PROFILE_TEST_DEBUG=line-tables-only cargo test ...`。
- `[profile.dev.package."*"] debug = false`：依赖一律不带调试信息。
- `[profile.release] strip = "debuginfo"`：发布二进制去掉调试段，保留符号表。
- `[profile.test] incremental = false`：避免测试构建产生 incremental 缓存。

## 日常清理

```sh
# 只删本包产物，保留依赖缓存（最常用）
cargo clean -p dubhe

# 删掉全部测试二进制与中间产物
cargo clean

# 查看占用分布
du -sh target/* target/debug/*
```

CI 每次都是全新容器，不需要额外处理；本地连续跑多轮全量测试时才需要上面的清理。

## 还能再省的地方

把 76 个测试二进制合并成 6–8 个分组（每个 test crate 只能有一个 crate root），
可以省下约 4–5 GiB。代价是每个测试文件里的 `mod common;` 都要改成显式
`#[path]`，并重新核对模块名冲突；这属于测试布局重构，单独一批做。
