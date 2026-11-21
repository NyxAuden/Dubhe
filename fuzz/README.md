# Fuzz targets

这是独立的 cargo-fuzz 包，不属于根 workspace，不会进入普通 `cargo test` 或 release 构建。
2026-11-14 已用 nightly + cargo-fuzz 对 15 个目标各运行 30 秒（0 crash/OOM）；
完整记录见 [fuzz 运行记录](../docs/fuzzing.md)。短时冒烟不等于完整握手 fuzz 或安全审计。

## 安装与运行

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cd fuzz
cargo fuzz list
cargo fuzz run config -- -max_total_time=60
cargo fuzz run vision -- -max_total_time=60
```

其余目标同理：`socks5_datagram`、`http_authority`、`address_read`、`xudp_read`、
`vless_datagram`、`trojan_datagram`、`xhttp_head`、`xhttp_uplink`、`grpc_payload`、
`vmess_header`、`snell_request`、`snell_udp`、`tuic_wire`。
`xhttp_*`、`grpc_payload`、`vmess_header`、`snell_*` 和 `tuic_wire` 通过根库的
`fuzzing` feature 暴露非生产入口。CI 的 `workflow_dispatch` 也提供 30 秒/目标的
`fuzz-smoke` 任务；它不是完整 fuzz 验收。

## 目标与边界

- `config`：`Config::from_json`，输入上限 64 KiB。
- `vision`：`vision::Decoder::consume`，同时测试一次性输入和按首字节决定的可变分块。
- `socks5_datagram`：SOCKS5 UDP 数据报解析。
- `http_authority`：HTTP `authority_target` 解析。
- `address_read`：VLESS/VMess/Trojan 共用的地址读取。
- `xudp_read`：XUDP 帧读取。
- `vless_datagram` / `trojan_datagram`：两种 UDP 数据报读取。

这些目标覆盖公开解析入口和部分内部纯解析函数（VMess decrypted header、Snell request/
UDP、TUIC wire），但不等于完整握手 fuzz。后续仍需为 Shadowsocks AEAD/2022 EIH、REALITY、
XHTTP 会话、gRPC stream、mKCP、TUIC 状态机、WireGuard、ShadowTLS 增加受控 harness。

## 依赖门禁

- `libfuzzer-sys` 0.4：仅 fuzz 包使用；版本/许可/MSRV/公告需在升级时重新核对。
- `futures` 0.3：仅用于 `block_on` 驱动公开 async 解析器。
- 不把 fuzz 依赖加入根 `Cargo.toml`，不影响生产构建。

## 运行后记录

每个目标至少记录：运行时长、输入数、crash 数、是否 OOM、最小化后的 crash 输入和修复提交。
`fuzz/corpus` 与 `fuzz/artifacts` 可能包含敏感输入，不随发布包分发。
