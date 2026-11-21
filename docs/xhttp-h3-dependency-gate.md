# XHTTP/3 依赖门禁记录

状态日期：2026-11-06。结论：**新增固定版本 `h3` 与 `h3-quinn`，以源码随仓库固定，不启用其可选 datagram 扩展；未执行编译与测试。**

## 固定来源

| 包 | 版本 | 许可 | 上游标签 | 提交 |
|---|---|---|---|---|
| `h3` | 0.0.8 | MIT | `h3-v0.0.8`（hyperium/h3） | `22c1aa3f44d1463cd7644c8f654fffc9a6da305c` |
| `h3-quinn` | 0.0.10 | MIT | `h3-quinn-v0.0.10`（hyperium/h3） | `2dc3412bdf6083451920d5bfd7a9484d054c1859` |
| `h3-datagram` | 0.0.2 | MIT | 同一标签树 | 同上 |

`h3-datagram` 只作为 `h3-quinn` 的可选依赖路径存在，未启用 `datagram` feature。

## 兼容性核查

- `h3` 声明 `rust-version = 1.70`，低于本仓库 MSRV 1.91。
- `h3-quinn` 依赖 `quinn ^0.11.7`，与既有固定 `quinn =0.11.11` 兼容；不新增第二份 quinn。
- 传递依赖 `bytes`、`futures`、`futures-util`、`http`、`tokio`、`tokio-util`、`pin-project-lite`、`fastrand` 均已在既有依赖闭包中。
- 许可为 MIT，不属于禁止复制的 GPL/MPL 模块。

## 落地方式

- 源码位于 `vendor/h3`、`vendor/h3-quinn`、`vendor/h3-datagram`，通过 `[patch.crates-io]` 覆盖同名 crates.io 包。
- 三个 vendor 目录排除在 workspace 成员之外，只作为依赖编译；不继承本仓库的测试面。
- 冻结的 `vendor/rustls` 与 `vendor/shadowsocks` 未改动。
- 未运行 `cargo`，`Cargo.lock` 的解析结果需在集中验收时生成并核对。
