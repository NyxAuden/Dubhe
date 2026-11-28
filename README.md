# Dubhe

**一个 Rust 编写的服务端代理内核。目标是在一台服务器上用单个进程替代并列部署的多个协议内核，让现有的 Clash / sing-box / Xray 系客户端直接连上来。**

[![CI](https://github.com/NyxAuden/Dubhe/actions/workflows/ci.yml/badge.svg)](https://github.com/NyxAuden/Dubhe/actions/workflows/ci.yml)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](LICENSE)

> Dubhe is a Rust server-side proxy kernel. It replaces multiple protocol kernels
> with a single process on one server. **Development version — not a production
> release.** Available evidence per protocol is tracked in the
> [compatibility matrix](docs/compatibility-matrix.md).

---

## 目录

- [项目定位](#项目定位)
- [支持的协议](#支持的协议)
- [证据口径（重要）](#证据口径重要)
- [快速开始](#快速开始)
- [客户端配置生成](#客户端配置生成)
- [从上游内核迁移](#从上游内核迁移)
- [工程门槛](#工程门槛)
- [文档索引](#文档索引)
- [许可](#许可)
- [安全](#安全)

---

## 项目定位

- **只做服务端。** 不开发终端客户端、不提供运营面板、不包装其他内核子进程。
- **线协议兼容，不追求配置兼容。** 本项目的配置是自定义 schema；从 Xray / sing-box
  迁移由独立的 `dubhe convert` 完成，避免运行时双 schema 维护。
- **一个进程，多协议共存。** 不同协议默认各占一个监听端口。单端口内承载多协议
  只有两种情形：`mixed`（按首字节区分 SOCKS5 / HTTP）与 `fallbacks`
  （认证失败后回放到本机另一个入口）。**不支持**按 ALPN / SNI 在同一端口
  自动分流到不同协议栈。
- **编译期模块化。** 不支持的协议不会被编译进二进制。

**明确不做**：TUN / redirect / tproxy 等系统级透明代理、出站 BIND、
官方 APT/DNF 仓库、二进制 GPG 签名、LTS 分支。理由见
[开源项目补齐计划](docs/oss-checklist.md)。

## 支持的协议

### 入站

| 协议 | 变体 |
|---|---|
| **VLESS** | `vless`(RAW/TLS/REALITY) · Vision · Encryption · `-ws` · `-grpc` · `-xhttp` · `-httpupgrade` · `-kcp` · `-quic` · `-http` |
| **VMess** | `vmess`(AEAD) · `-reality` · `-ws` · `-grpc` · `-xhttp` · `-httpupgrade` · `-kcp` · `-quic` · `-http` |
| **Trojan** | `trojan` · `-reality` · `-ws` · `-grpc` · `-xhttp` · `-httpupgrade` · `-kcp` · `-quic` · `-http` |
| **Shadowsocks** | AEAD 2017 · AEAD 2022（含单层 EIH 多用户） |
| **Hysteria2** | QUIC / HTTP3，含 salamander 与 gecko obfs |
| **TUIC v5** | QUIC，含 cubic / new_reno / bbr 拥塞控制与显式 0-RTT |
| **AnyTLS** | 含 padding scheme 协商与空闲会话池 |
| **Snell** | v4 / v5 / v6（default / shaped / unshaped / unsafe-raw） |
| **ShadowTLS** | v3（含 SNI 映射与 wildcard SNI） |
| **Naive** | H1 / H2 / H3，含 padding 层 |
| **WireGuard** | 用户态服务端，无 TUN |
| **NW3** | Portal 入站（含 `direct` / `egress` / SOCKS5 出口）。**注意：自行出站，不经本内核 `route` / `reject` / 统计与限额**，见 [NW3](docs/nw3.md) |
| **通用** | SOCKS5（CONNECT / UDP ASSOCIATE / BIND）· HTTP · Mixed · dokodemo-door |

**13 个协议族，不是 40 个协议。** 上表的 `-ws` / `-grpc` 等是同一协议的承载变体，
配置里写作独立类型名（`type: "vless-ws"`）；VLESS/VMess/Trojan × 9 种承载共 27 个
类型值。这与出站（`type: "vless"` + `transport`）以及上游 Xray/sing-box 都不一致，
属已知结构债，代价见[架构概览](docs/architecture.md#入站结构协议与承载被扁平化)。

### 出站

SOCKS5 · HTTP CONNECT · VLESS · VMess · Trojan · Shadowsocks · AnyTLS · Snell ·
Naive · ShadowTLS detour · Hysteria2 · TUIC · WireGuard · NW3 Vector ·
`selector`（静态组）· `urltest`（延迟探测组）· `reverse`（反向 Mux Portal）

支持 TCP 单跳与多跳链式，以及 VLESS/VMess/Trojan 的 WS / gRPC / HTTPUpgrade /
XHTTP / mKCP / QUIC 承载。

### 传输与扩展

REALITY（含 ML-DSA-65 校验）· Vision · Mux.Cool · UoT v1/v2 · XHTTP(h1/h2/h3) ·
fallback 子集 · 全站首包嗅探 · 按用户流量统计 · SIGHUP 热重载

## 证据口径（重要）

本项目按 **证据等级** 标注每项能力，不做笼统的「全支持」声明：

| 等级 | 含义 |
|---|---|
| **已验收** | 有可复现的固定版本官方客户端互通测试、负向用例与平台记录 |
| **已实现待验收** | 代码完成、本机回环测试通过，但**缺第三方客户端证据** |
| **实验** | 上游标记为 experimental，或依赖的规范本身不稳定 |

**当前只有 Trojan / VLESS（含 XUDP）/ Shadowsocks 有可复现的第三方客户端
测试**（`tests/reference_clients.rs`）。其余协议目前仅本机回环，详见
[服务端兼容矩阵](docs/compatibility-matrix.md) 顶部的口径说明。

判定标准：六列全绿才算「已验收」——上游版本、方向、业务载荷、负向用例、
平台、构建。缺任何一列都不得写「已验收」。

## 快速开始

需要 Rust 1.91.0（`rust-toolchain.toml` 已固定）与系统 `curl`。

```sh
cargo build --locked --release

./target/release/dubhe version
./target/release/dubhe check -c examples/socks5.json
./target/release/dubhe run   -c examples/socks5.json
```

`examples/` 下有 58 个配置模板。其中 18 个可直接 `check` 通过；
其余含证书路径或凭据占位符，**必须先替换**才能加载——尤其 Trojan / VLESS
等示例不能直接作为公网配置使用。SOCKS5 示例只监听 `127.0.0.1:1080`。

**从发布包安装时**同样适用以上命令，只需把路径换成解包目录：

```sh
./dubhe version
./dubhe check -c examples/socks5.json
./dubhe run   -c examples/socks5.json
```

发布包内含 `NOTICE`、`LICENSE`、`THIRD-PARTY.md` 与 `licenses/`（vendor 下各
组件的原始许可文本），以及 `examples/socks5.json` 与 `systemd/dubhe.service`。
`NOTICE` 要求以二进制分发时随附这些文件，请勿在二次分发时移除。

停机语义：Ctrl+C 或 SIGTERM 触发有期限排空；Unix 下 SIGHUP 在配置未变时只
轮换 TCP/TLS 证书，不中断既有连接。

详细配置参考、默认限额与已知限制见[构建与运行](docs/usage.md)。

## 客户端配置生成

`dubhe export` 从服务端配置生成客户端配置，并用真实客户端内核校验：

```sh
# 首次：下载固定版本的三家客户端
python3 tools/fetch_reference_clients.py

# 生成四种格式
dubhe export -c config.json --host example.com -o ./client

# 用真实内核校验（xray run -test / sing-box check / mihomo -t）
python3 tools/verify_export.py ./client
```

输出格式：**Xray** · **sing-box** · **Mihomo** · **Anywhere AJSON**。

目标格式不支持的协议会写入 stderr 报告并跳过，不生成半可用配置。
覆盖矩阵与实测结论见[使用说明](docs/usage.md#用真实内核校验导出结果)。

## 从上游内核迁移

```sh
dubhe convert --from xray --input xray-config.json --output dubhe.json
dubhe check -c dubhe.json
```

支持入口、出站、静态路由与 DNS。路由规则可直接引用地理数据集：
`geosite:` / `geoip:`（Xray、Mihomo 的 `.dat`）、`mmdb:`（MaxMind）、
`rule_set:`（sing-box source JSON）——内核只读用户提供的数据文件，
不内置、不下载、不校验，见[地理数据集](docs/geo.md)。

其余高级语义（`downloadSettings`、`balancerTag` 等）会被显式拒绝而非
静默丢弃。字段对照见[迁移指南](docs/migration.md)。

**一个端口接多个协议**：上游 Xray 的做法是 `fallbacks`（认证失败后把字节
回放到本地目标），sing-box 则要求每个入站各占一个端口。本内核与前者一致：

```json
{
  "type": "vless", "tag": "front", "listen": "0.0.0.0:443",
  "users": [{"uuid": "..."}],
  "certificate": "/path/fullchain.pem", "private_key": "/path/key.pem",
  "fallbacks": [{"dest": "127.0.0.1:8443"}]
}
```

把 443 上 VLESS 认证失败的连接交给本机 8443 的另一个入口。

限制（实测）：

- **回放的是 TLS 解密后的明文**，所以 `dest` 只能是接受明文的目标——
  本机的 `http` / `mixed` / `socks5` 入口、普通 Web 服务，或 Unix 套接字。
  指向另一个 TLS 入口（例如 `trojan`）不会工作：对端读到的是密文，
  实测报 `InvalidData`。
- 匹配依据只有 `name`（SNI）/ `alpn` / `path`，**不是协议嗅探**。
  未通过认证的流量按你写的 `dest` 走，不会「自动落到正确的协议栈」。
- 按 SNI/ALPN 在不同协议栈之间自动选择，本内核**不支持**。

## 工程门槛

所有 PR 必须通过以下全部检查：

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo deny check
```

或直接运行 `tools/ci.sh`。

其他工程基线：三平台 CI（Linux x86_64 / Linux ARM64 / macOS ARM64）、
`rust-toolchain.toml` 固定工具链、可复现构建记录、CycloneDX SBOM、
cargo-fuzz 每周定时任务、systemd unit 与容器镜像。

当前测试基线：**1467 通过 / 0 失败 / 42 忽略**（macOS ARM64）。

## 文档索引

**状态与证据**

- [服务端兼容矩阵](docs/compatibility-matrix.md) — 逐协议状态
- [实验能力清单](docs/experimental.md) — 已实现但缺完整验收
- [生产可用性评估](docs/production-readiness.md) — 生产门禁与未完成项
- [上游事实核对](docs/upstream-facts.md) — 每条结论的证据等级
- [协议与功能的上游归属](docs/protocol-ownership.md) — 哪个协议由谁定义

**使用与开发**

- [构建与运行](docs/usage.md) — 完整配置参考
- [架构概览](docs/architecture.md) — 代码结构
- [迁移指南](docs/migration.md) — Xray / sing-box 字段对照
- [故障排查](docs/faq.md) — 常见问题
- [领域术语](CONTEXT.md)

**工程与安全**

- [威胁模型](docs/threat-model.md) · [失败关闭矩阵](docs/fail-closed-matrix.md)
- [运维基线](docs/operations.md) · [管理 API 与配置应用契约](docs/api.md) · [可复现构建](docs/reproducibility.md)
- [依赖基线](docs/dependency-baseline.md) · [SBOM](docs/sbom.md)
- [开源补齐计划](docs/oss-checklist.md)

## 许可

**GPL-3.0-only**，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

原因：NW3 的 Portal 与 Egress 直接整包复用
[Nowhere](https://github.com/NodePassProject/Nowhere) 3.3.0 的 GPL-3.0-only
源码，链接该代码的程序必须整体采用 GPL-3.0-only。

内嵌的第三方组件、版本、许可与本地修改记录见 [THIRD-PARTY.md](THIRD-PARTY.md)。
以二进制分发时须同时提供源码与本项目所列全部许可文本。

`Cargo.toml` 设置 `publish = false`，不作为 crate 发布。

## 安全

发现漏洞请**不要**开公开 issue，按 [SECURITY.md](SECURITY.md) 私密报告。

请注意：

- 本程序不修改系统代理、防火墙或系统 DNS，也不会自动安装服务。
- 无认证的 SOCKS5 / HTTP 默认拒绝非回环监听，需显式 `allow_insecure` 才允许。
- `.test-artifacts/` 含本机测试凭据与临时私钥，已被 gitignore，**不要公开**。
- 当前验收不构成安全审计或生产容量证明。

---

**本项目不承诺生产 SLA。** 定位是社区项目：能自建、能推荐、出问题有人修。
在受控内测之外使用前，请先读[生产可用性评估](docs/production-readiness.md)。
