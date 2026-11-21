# 现代能力中断任务接回与验证记录（2026-11-11）

本记录只描述此次从中断子代理接回、顺序收尾的真实结果，不替代既有官方客户端验收。

## 接回并完成的内容

1. **WireGuard 服务端配置与运行时接入**
   - 保留子代理的 boringtun + smoltcp 实现，补齐全局 UDP 路由适配。
   - TCP/UDP 均使用既有路由/中继，不把代理路由静默改为 direct。
   - 修复 detached relay：停机取消未完成拨号，等待子任务并释放监听端口。
   - 空闲清理保留 Handshake 的 TAI64N 高水位与会话索引，避免重建 Tunn 丢失重放防线。
   - NAT 前验证原始 IP/L4 校验和，分离 TCP 读写关闭状态，支持 FIN 后继续接收响应。
   - 地址数量按实际 smoltcp 接口容量校验，不在合法配置上触发数组 push panic。


3. **公共资源与栈大小修复**
   - 新增 `udp::RoutedUdp`，复用既有 Association 的路由、全局预算与上游协议。
   - UDP 上游关联建立状态机单独堆分配，运行器不再把大型多协议 future 层层内联。
   - 最终回归没有设置 `RUST_MIN_STACK`；没有通过提高全局测试栈掩盖失败。

本次未新增依赖、未修改 Cargo.toml/Cargo.lock、未修改 vendor；未执行 Git、归档、
容器操作、官方客户端新运行、系统网络变更或发布。

## 验证结果

工具链：`rustc 1.95.0 (59807616e 2026-04-14)`，`cargo 1.95.0`；macOS ARM64 本机。

| 命令/范围 | 结果 |
|---|---|
| `cargo test --locked --offline` | **1178 passed，0 failed，43 ignored**；69 个测试结果块，退出 0 |
| `cargo check --locked --offline --all-targets` | 退出 0（仍有项目既存 unused/dead-code 等警告，不声称无警告） |
| `cargo fmt --all -- --check` | 退出 0 |
| WireGuard 文件内测试 | 17 passed，0 failed |
| `tests/wireguard_server.rs` | 3 passed，0 failed；含经 SOCKS5 上游的 UDP 和 TCP 统计 |
| 默认栈 REALITY 阻塞 DNS/队列/强停回归 | 通过 |

43 个 ignored 包括 42 个既有显式验收/外部门禁测试和 1 个新增文档示例；
ignored **不计通过**。没有运行 `--ignored`，不把本机协议端互测称为官方兼容。

全量日志保存在本机 `/tmp/rpk-rescued-suite.8ADmky`（临时路径，不包含在版本化成果中）；
源代码/测试才是可复现输入。原始失败包括默认栈溢出、TCP 握手前错误派生 relay、
H3 测试客户端过早丢弃请求句柄，均已定位修复并在最终全量中回归。

## 存储清理

全量编译后可用空间降至约 6.3 GiB。仅删除本项目
`target/debug/incremental` 可重建增量产物后，空间恢复至约 **18 GiB**。
源码、vendor、证据、临时证书目录与验收资产未删除。保留当前测试二进制和依赖，
避免下批从零构建。

## 不作完成声明的后续项

以下是本救援批收尾时的历史状态，不是最新缺口清单。后续已补WireGuard/NW3出站UDP（见[记录](modern-outbound-udp-development.md)）、Naive H3（见[记录](naive-h3-development.md)）；其中H1无payload padding已核正为固定上游行为，不应继续当缺项。当前能力以兼容矩阵与各批开发记录为准。

- WireGuard **出站** UDP；不由本批入站支持推导出站能力。
- Naive H1 padding/H3、TUIC 客户端 0-RTT、NW3 Vector UDP 等未完成能力。
- Hysteria2 Brutal 的 quinn 适配存在采样/半窗近似，见 `hysteria2.md`，本次全量
  通过不证明吞吐/逐包行为等于上游。
- 官方客户端、三平台、精确 MSRV、release、最终验收报告仍需单独开展。
