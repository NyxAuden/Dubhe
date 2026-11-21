# 第三方组件与许可

本项目整体采用 **GPL-3.0-only**（见 `LICENSE`）。以下为本仓库直接内嵌（vendored）的第三方源码及其原许可。各目录内保留原始版权头与许可文件，本地修改记录在该目录的补丁/门禁文档中。

| 目录 | 组件 | 版本/基线 | 许可 | 本地修改 |
|---|---|---|---|---|
| `vendor/rustls` | rustls | 固定 `=0.23.46` | Apache-2.0 OR ISC OR MIT | 固定且含已记录的 REALITY/SID 最小补丁、默认关闭的客户端 HRR SID 放行，以及官方 Xray 互通所需的 Ed25519 CertificateVerify/目标 record 自然长度修正（见 `vendor/rustls/PATCHED.json` 与 `REALITY-SOURCE.txt`）；进一步修改需独立门禁 |
| `vendor/shadowsocks` | shadowsocks-rust 协议层 | 固定 `=1.25.0` | MIT | 见 `vendor/shadowsocks/PATCH.md`、`UPSTREAM.json` |
| `vendor/h3` | h3 | 标签 `h3-v0.0.8`，提交 `22c1aa3f44d1463cd7644c8f654fffc9a6da305c` | MIT | 未修改；仅作为依赖编译 |
| `vendor/h3-quinn` | h3-quinn | 标签 `h3-quinn-v0.0.10`，提交 `2dc3412bdf6083451920d5bfd7a9484d054c1859` | MIT | 未修改；仅作为依赖编译 |
| `vendor/h3-datagram` | h3-datagram | 0.0.2（`vendor/h3-datagram`） | MIT | 含 Quarter Stream ID 一行修复，见 `vendor/h3-datagram/PATCH.md`；作为 h3-quinn datagram 依赖保留 |
| `vendor/nowhere` | Nowhere | 3.3.0 | **GPL-3.0-only** | `Cargo.toml` 固定 `quinn = 0.11.11`、`quinn-proto = 0.11.16`；`src/portal/runtime/mod.rs` 新增 `Portal::run_with_stop` / `run_inner` 外部停止令牌；`src/egress/runtime.rs` 新增 `Egress::run_with_stop` / `run_inner` |
| `vendor/blake3` | blake3 | 固定 `1.8.7` | Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR CC0-1.0 | `src/hazmat.rs` 新增任意字节 derive-key 上下文入口（见 `vendor/blake3/PATCH.md`） |

来源与版本核对记录：

- HTTP/3 系列：`docs/xhttp-h3-dependency-gate.md`
- Nowhere：`docs/nw3.md`

`vendor/nowhere` 为 GPL-3.0-only，因此本项目以 GPL-3.0-only 整体分发；GPL 兼容性由该选择保证，本文件不是法律审计。分发二进制时须同时提供对应源码与上述许可文本。
