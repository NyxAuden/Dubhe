# 架构概览

面向准备读代码或提交 PR 的人。领域术语以 [CONTEXT.md](../CONTEXT.md) 为准。

## 一次连接的路径

```
监听器 (runtime/listener.rs)
  └─ accept 循环 (runtime/accept.rs)
       ├─ 握手与认证（各协议在 protocol/ 或 transport/ 内）
       └─ 认证后分派 (runtime/serve.rs)
            ├─ 选路 / DNS / 嗅探 (route.rs, dns.rs, transport/sniff.rs)
            ├─ 建上游 (forward.rs: Context::connect_routed)
            └─ 双向转发 (forward.rs: relay)
```

UDP 走另一条：`udp.rs` 的 `Association` 负责目标映射、预算和回程来源校验；
各传输层的原生 UDP（Hysteria2/TUIC/Shadowsocks）在各自模块内维护会话。

## 模块地图

| 目录 | 职责 | 不该放什么 |
|---|---|---|
| `runtime.rs` + `runtime/` | Server 生命周期、监听绑定、接受循环、热重载 | 协议编解码 |
| `config.rs` + `config/` | 配置结构与静态校验 | 运行时状态 |
| `protocol/` | 线协议编解码与认证（SOCKS5、VLESS、VMess、Trojan、Snell、HTTP、Shadowsocks 适配） | 路由、出站策略 |
| `transport/` | 承载与传输（WS、gRPC、XHTTP、HTTPUpgrade、Hysteria2、TUIC、AnyTLS、ShadowTLS、WireGuard、Naive） | 业务转发决策 |
| `tls/` | 受控 TLS、REALITY、Vision 记录层 | 监听器管理 |
| `udp.rs` + `udp/` | 共享 UDP 关联与各协议 UDP 承载 | 协议认证 |
| `forward.rs` | 路由后的拨号、中继、连接登记、热重载上下文 | 具体协议细节 |
| `route.rs` / `dns.rs` | 规则匹配与解析 | 协议状态 |
| `telemetry.rs` | 计数、Prometheus 文本、按用户归因 | 业务逻辑 |
| `admin.rs` | 只读管理 API | 配置写入 |

## 入站结构：协议与承载被扁平化

`config/inbound.rs` 的 `Inbound` 枚举有 40 个变体。其中 27 个是
**协议 × 承载** 的笛卡尔积：

| | RAW | reality | ws | grpc | xhttp | httpupgrade | kcp | http | quic |
|---|---|---|---|---|---|---|---|---|---|
| VLESS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| VMess | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Trojan | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

配置上表现为 `type: "vless-ws"`、`type: "vless-grpc"` 等 27 个类型值，
没有独立的 `transport` 字段。

**这与出站不一致，也与上游不一致**：出站是 `type: "vless"` +
`transport: {"type": "ws"}`（`OutboundKind` 17 个变体 + `OutboundTransport`
6 种承载），Xray 是 `protocol` + `streamSettings.network`，sing-box 是
`type` + `transport`。三家都是正交的。

**代价（实测）**：

- 40 个变体产生 39 种不同的字段组合签名，只有 `Http` 与 `Mixed` 字段集相同；
- `tag` / `listen` 在 40 个变体里各重复 40 次；
- 新增一种承载要改 27 个文件（`export.rs` 59 处、`inbound.rs` 30 处、
  `validate.rs` 27 处、`convert.rs` 27 处）；
- 分派靠 `runtime/accept.rs` 的 40 路 `if/else`，其中一处单行列出 20 个变体名。

**这是已知结构债，不是有意的设计**。改成 `Inbound { protocol, transport }`
需要在同一提交里改动配置、校验、分派、导出与转换五处，属较大重构；
在此之前新增承载的成本保持在上述量级。

## 加一个协议要改哪里

1. `config/`：新增配置结构与校验，必须带 `deny_unknown_fields`。
2. `protocol/<name>.rs` 或 `transport/<name>.rs`：编解码与认证，返回
   `session::Request`（带 `user`）。
3. `runtime/serve.rs`：认证成功后的分派；用
   `ctx.stats.count_user(tag, user, stream)` 包裹客户端流，保证统计归因。
4. `examples/`：一份最小可启动模板。
5. `tests/`：至少覆盖正常载荷、错误凭据、超限输入、资源回收。

协议改动必须在 PR 里给出上游版本、方向、业务载荷、负向用例、平台与构建摘要。

## 关键不变量

- **失败关闭**：未知字段、未实现能力、认证失败都直接报错，不静默降级。
- **资源有界**：连接、握手、UDP 关联、队列、重放表都有上限；超限拒绝并计数。
- **配置严格**：`deny_unknown_fields` 覆盖全部配置结构。
- **日志脱敏**：不输出密码、私钥、摘要、业务载荷与目标地址。
- **统计只算成功写出的字节**，部分写入不计。

## 测试布局

| 位置 | 内容 |
|---|---|
| `src/**` 内 `#[cfg(test)]` | 单元测试；部分模块通过 `#[path]` 被 `tests/` 复用 |
| `tests/*.rs` | 每个文件一个 test crate，覆盖协议、资源、热重载、官方客户端 |
| `fuzz/` | 15 个解析入口；每周定时冒烟 |
| `tests/reference_clients.rs` | 固定官方客户端互通（需显式授权运行） |

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo deny check
```

## 已知结构债务

- `transport/wireguard_server.rs`、`transport/xhttp.rs`、`udp.rs`、
  `config/validate.rs` 仍是 2000 行以上的大文件。
- `read_head` 有三套独立实现，`hex` 单字节解码散在多个模块；
  合并它们需要先确认各自的错误类型与 deadline 语义。
- 部分协议没有用户名（WireGuard、Shadowsocks 单密钥），按用户统计不覆盖。
