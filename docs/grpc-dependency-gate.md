# gRPC 依赖门禁与固定来源记录

审查日期：2026-11-06；范围：`add-grpc-inbound-transport` task 1.1 / 1.2 及 design D2。**结论：精确候选 `h2 =0.4.20`、`prost =0.14.4` 在当前官方索引存在且未 yanked；静态闭包预计新增 8 个包、无既有版本升级、无本范围内未修复 RustSec 版本命中；许可均为宽松许可，声明 MSRV 最高 1.85，低于本项目声明 1.91。这不是 Cargo 解析、编译、完整安全审计或依赖变更授权；修改 Cargo/锁前仍须真实用户确认。**

## 实施状态（2026-11-06）

用户已确认仅加入下列 8 个精确新包与两条根边，不升级既有依赖、不提高 MSRV。确认后的真实结果：

- `Cargo.toml` 已写入两条精确根边；未建立第二把锁，未修改两个 vendor。
- 锁 SHA256：`56b19d93fc724a1cf6b2cf0dd52264029112e41194bb5f0299ae8000d613b723` → `8987396fae9900d154c9ff52e4a0eb1e0c66ed61c3e3c45d9a70d22dd65ef47b`。
- 包数 317 → 325；新增恰为下表 8 包；删除 0；既有包版本变化 0。证据：`gate/lock-delta.json`。
- `cargo check --locked --all-targets` 退出 0；`cargo tree -p dubhe -e features --locked` 退出 0。证据：`gate/check-all-targets.log`、`gate/features-tree.txt`。
- 两个冻结 vendor 相对既有 WS 批次快照逐文件一致：rustls 131/131、shadowsocks 70/70，无缺失/新增/变化。证据：`gate/vendor-freeze.json`。
- 旧普通 TLS/ALPN 回归 `websocket_alpn` 1 passed、0 failed。证据：`gate/tls-regression.log`。
- 可执行 API 原型 10 passed、0 failed，实际失败/修复与未覆盖边界见 `gate/prototype-notes.md`。

以上仅为本地开发证据，不是官方客户端、平台或精确 MSRV 验收。

## 固定来源

只读归档 27 个固定提交文件的原文、大小和 SHA256，清单见私有工件 `.test-artifacts/grpc-dev-l4x9k2m7/sources/manifest.json`。下载内容只作为数据保存，未解包执行、未从其中运行任何解释器。

| 基线 | 归档文件数 | 已核事实 |
|---|---:|---|
| Xray v26.10.31 / `a4a3dff5b20c2faae567b742c172c7b95e75c083` | 10 | `main/distro/all/all.go` 仍导入 grpc；`hub.go` 调用 `RegisterGRPCServiceServerX` 并同时创建 `NewMultiHunkConn`；`dial.go` 实际分支 `TunCustomName`/`TunMultiCustomName`；`config.go` 对普通/自定义服务名使用 `url.PathEscape`；`stream.proto` 定义 `MultiHunk` 与 `rpc TunMulti`；`transport_internet.go:27` 是 `PrintNonRemovalDeprecatedFeatureWarning`，不是移除。 |
| sing-box v1.14.4 / `c005f35300ce76427dc285481ec5695f5b179cd2` | 11 | `transport.go` 真实分派 `NewGRPCServer`/`NewGRPCClient`；`grpc.go` 走 full，`grpc_lite.go` 走 Lite；full 只注册 `GunService.Tun`，路径 `"/"+name+"/Tun"`；Lite 同样 `/Tun`，显式 `TE: trailers` 与 `Content-Type: application/grpc`。 |
| Mihomo v1.19.33 / `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` | 4 | VLESS/VMess/Trojan 出站均实际调用 `gun.NewClient` 及 `gunClient.Dial`；`gun.ServiceNameToPath` 组成 `/GunService/Tun`；请求显式头只有 `Content-Type` 与 `User-Agent`，**归档文件中没有 `trailers` token**，因此不能断言其请求带 `TE: trailers`。 |
| gRPC 规范 / `cf61c7d62a1a7f43b9d2ea6488186bc14fc41a8c` | 1 | `PROTOCOL-HTTP2.md` 原文。 |
| RFC 9113 | 1 | 文本原文，用于 HTTP/2 资源与状态语义。 |

证据行和缺失检查见 `.test-artifacts/grpc-dev-l4x9k2m7/gate/source-facts.json`。这些是公开源码事实，不是官方客户端运行或互通通过。

## 候选与根边

已按用户确认写入 `Cargo.toml` 的最小根边：

```toml
h2 = { version = "=0.4.20", default-features = false }
prost = { version = "=0.14.4", default-features = false, features = ["derive", "std"] }
```

- `h2 0.4.20` 的 manifest 默认特性为空；显式关闭默认不改变 `server` 可用性，本批不使用其 `stream`/`unstable` 特性。
- `prost 0.14.4` 的 `derive` 由 `features2` 定义为 `dep:prost-derive`，`std` 为独立特性；不启用 `no-recursion-limit`。
- `bytes 1.12.1` 已锁定，可由 `prost::bytes` 公开重导出使用，不需要新增根直接边。
- `tokio-util 0.7.20` 已锁定；`h2` 请求的 `codec`/`io` 特性只启用既有 `libc`，不新增包。
- 不引入 `tonic`、`hyper`、`prost-build`、`prost-types` 或 `protoc`。

## 新增包静态闭包

官方 sparse index 精确行与 `static.crates.io` 归档逐包校验；`archive_sha256` 与 index `cksum` 全部一致。旧锁 SHA256 为 `56b19d93fc724a1cf6b2cf0dd52264029112e41194bb5f0299ae8000d613b723`。

| 包 | 版本 | 相对旧锁 | 实际许可 | 声明 rust-version | 归档 SHA256 |
|---|---|---|---|---|---|
| h2 | 0.4.20 | 新增直接 | MIT | 1.63 | `7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118` |
| prost | 0.14.4 | 新增直接 | Apache-2.0 | 1.85 | `528ac67416ff8646872a3c02cad9cc4ee5dc9f9540c9b10771855c95cb2e5ae1` |
| prost-derive | 0.14.4 | 新增传递 | Apache-2.0 | 1.85 | `b570b25f7617e43d59005d0990ccb79e950a423952cea19671b7a876da390adf` |
| atomic-waker | 1.1.2 | 新增传递 | Apache-2.0 OR MIT | 1.36 | `1505bd5d3d116872e7271a6d4e16d81d0c8570876c8de68093a09ac269d8aac0` |
| fnv | 1.0.7 | 新增传递 | Apache-2.0 / MIT | 未声明 | `3f9eec918d3f24069decb9af1554cad7c880e2da24a9afd88aca000531ab82c1` |
| indexmap | 2.14.2 | 新增传递 | Apache-2.0 OR MIT | 1.85 | `cc4e190f5d26ca7051642629da2c52fc03bde85a03197c99408dcd291734c855` |
| hashbrown | 0.17.1 | 新增传递 | MIT OR Apache-2.0 | 1.85.0 | `ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a` |
| itertools | 0.14.0 | 新增传递 | MIT OR Apache-2.0 | 1.63.0 | `2b192c782037fadd9cfa75548310488aabdbf3d2da73885b31bd0abd03351285` |

复用旧锁且无版本升级：`bytes 1.12.1`、`http 1.5.0`、`tokio 1.54.1`、`tokio-util 0.7.20`、`slab 0.4.12`、`tracing 0.1.44`、`tracing-core 0.1.36`、`futures-core/futures-sink 0.3.34`、`pin-project-lite 0.2.17`、`libc 0.2.191`、`anyhow 1.0.104`、`syn 2.0.119`、`quote 1.0.47`、`proc-macro2 1.0.107`、`unicode-ident 1.0.27`、`either 1.19.0`、`equivalent 1.0.3`、`itoa 1.0.18`。既有名称的多版本未被删除或升级。

特性增量审查：`syn/extra-traits`、`tokio-util/codec+io`、`tracing/std`、`indexmap/std` 不启用新的可选依赖包；`tokio-util/codec` 只启用已锁 `libc`；`prost/derive` 只启用新增 `prost-derive`。闭包边与逐项来源见 `.test-artifacts/grpc-dev-l4x9k2m7/gate/dependency-gate.json`。

## RustSec 公告范围

只查询新增 8 个包名的 advisory-db 目录原文；这不是全锁审计，也不代表无未知漏洞。

| 包 | 公告 | 修复条件 | 本候选 |
|---|---|---|---|
| h2 | RUSTSEC-2023-0034 | `>= 0.3.17` | 4.20 已修复 |
| h2 | RUSTSEC-2024-0003 | `^0.3.24` 或 `>= 0.4.2` | 已修复 |
| h2 | RUSTSEC-2024-0332 | `^0.3.26` 或 `>= 0.4.4` | 已修复 |
| h2 | RUSTSEC-2026-0258 | `>= 0.4.16` | 已修复 |
| prost | RUSTSEC-2020-0002 | `>= 0.6.1` | 已修复 |
| hashbrown | RUSTSEC-2024-0402 | `>= 0.15.1`；仅 `=0.15.0` 的 borsh 序列化受影响 | 0.17.1 不受影响 |
| prost-derive / atomic-waker / fnv / indexmap / itertools | 无目录 | — | 无已知公告，不等于安全证明 |

公告原文与查询快照见 `.test-artifacts/grpc-dev-l4x9k2m7/gate/advisories.json`。

## 已知边界

- 闭包由自写静态解析器按官方 index 的依赖/特性计算，不是 `cargo` 解析结果；实际锁差异仍须在获准后以真实解析验证，多出未审新包或既有升级时回到门禁。
- 只评估 macOS/unix 相关目标；Windows/wasm 等条件依赖未计入，锁中已存在的多平台包不受本批影响。
- 声明 MSRV 元数据不等于 Rust 1.91 实际编译通过；精确 MSRV 与三平台验收仍在后置组。
- RustSec 查询只覆盖新增包名；既有包的新特性不引入新版本，但未重新审计全部历史公告。
- 首版门禁报告在修正版本匹配和席次标记前生成，作为失败历史保留：`gate/dependency-gate.first.json`、`gate/advisories.first.json`；不得引用其错误标记。
- 本节的静态结论本身不构成修改授权；实际修改在用户明确确认 8 个新包与两条根边后执行，真实锁差异与验证见“实施状态”。它仍不授权开始生产实现或后置集中验收。
