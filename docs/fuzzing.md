# Fuzz 运行记录

本文件记录已执行的 fuzz 冒烟，不把短时 fuzz 当成安全审计或完整协议覆盖。

## 2026-11-14 冒烟

- 主机：macOS ARM64
- 工具链：Rust nightly 1.102.0（2026-11-13）、cargo-fuzz 0.13.2
- fuzz lock：`fuzz/Cargo.lock` SHA-256
  `113930be551d0315fddf9905695fd58ed11c4b8b1113eae7aa88e812edb12843`
- 参数：每个目标 `-max_total_time=30 -rss_limit_mb=2048`
- 结果：15 个目标全部退出 0，`fuzz/artifacts` 为空，未发现 crash/OOM
- 合计约 825 万次执行
- corpus：约 7.4 MiB，未随发布包分发

| 目标 | 执行次数 | 结果 |
|---|---:|---|
| `config` | 541,319 | 0 crash |
| `vision` | 331,027 | 0 crash |
| `socks5_datagram` | 575,055 | 0 crash |
| `http_authority` | 571,809 | 0 crash |
| `address_read` | 572,351 | 0 crash |
| `xudp_read` | 572,109 | 0 crash |
| `vless_datagram` | 567,455 | 0 crash |
| `trojan_datagram` | 571,743 | 0 crash |
| `xhttp_head` | 562,742 | 0 crash |
| `xhttp_uplink` | 554,075 | 0 crash |
| `grpc_payload` | 551,464 | 0 crash |
| `vmess_header` | 575,949 | 0 crash |
| `snell_request` | 559,420 | 0 crash |
| `snell_udp` | 572,476 | 0 crash |
| `tuic_wire` | 573,453 | 0 crash |

复现命令：

```sh
cd fuzz
cargo +nightly fuzz run config -- -max_total_time=30 -rss_limit_mb=2048
# 其余目标：vision socks5_datagram http_authority address_read
# xudp_read vless_datagram trojan_datagram
```

## 覆盖边界

当前目标覆盖公开配置解析、Vision 增量 decoder、SOCKS5 数据报、HTTP authority、
共享地址读取、XUDP 帧、VLESS/Trojan UDP 数据报读取，以及通过根库 `fuzzing` feature
暴露的 XHTTP 头/上行数据解析、gRPC payload 解码、VMess decrypted header、Snell
request/UDP 和 TUIC wire 编解码。没有覆盖：

- VMess AEAD body、Shadowsocks AEAD/2022 EIH、REALITY、XHTTP 会话、gRPC stream、
  mKCP、TUIC 状态机、WireGuard、ShadowTLS 的完整握手/状态机；
- 真实 TLS/QUIC 握手、路由、DNS、资源上限和停机路径；
- 多线程竞态、内存泄漏和长时间稳定性。

因此本轮只能证明这些解析入口在 30 秒随机输入下未崩溃，不能外推为协议安全或生产可用。
后续需要增加内部 harness、更长运行时间和独立审计。

## 清理

`fuzz/target` 在记录后删除；`fuzz/corpus` 和 `fuzz/artifacts` 已加入 `.gitignore`，
不进入发布包。临时 cargo-fuzz 安装目录在验收后删除。
