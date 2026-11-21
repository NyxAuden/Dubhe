# 内核替代范围评估

状态日期：2026-11-12。本文只回答“本内核当前能替代哪些上游内核的哪些角色”，不把
单个协议回环、配置被接受或编译通过写成完整替代。证据以
[官方互通记录](official-interop-development.md)、[兼容矩阵](compatibility-matrix.md)
和各协议说明为准。

## 结论

**目前没有任何一个上游内核可以被本内核完整替代。**

可以有限替代的是**服务端协议角色**：

| 上游内核 | 本内核可替代的角色 | 当前证据 | 不能替代的部分 | 结论 |
| --- | --- | --- | --- | --- |
| Nowhere / NW3 | Portal 入站、Portal `out=direct/egress/SOCKS5`、Egress 出口、`nw3-vector` 出站 | 官方 Nowhere v3.3.0：Vector→本内核 Portal、`nw3-vector`→官方 Portal、官方 Egress↔本内核 Portal、本内核 `nw3_egress`↔官方 Portal，TCP/UDP 均通过 | 官方 Anywhere 客户端；Portal 分离监听/通配主机；多实例 Egress/多密钥；Morph 认证负例；无可用 Egress 超时语义；三平台/MSRV/release | **可替代 NW3 Portal/Egress 的服务角色（有限）** |
| Xray-core | VLESS（含 Vision/REALITY/WS/gRPC/XHTTP/HTTPUpgrade/mKCP/QUIC/Encryption）、VMess、Trojan、Shadowsocks、fallback、Mux.Cool、反向 Mux 的服务端子集 | Xray v26.10.31 双向：VLESS/TLS、VLESS/WSS、Trojan/TLS、VMess/TLS、VLESS Vision、VLESS/VMess/Trojan REALITY（VLESS 含 Vision flow，RAW）、VLESS（single/multi）/VMess/Trojan gRPC/TLS、VLESS/VMess/Trojan REALITY-over-gRPC/XHTTP、VLESS/XHTTP TLS 四模式、VLESS/HTTPUpgrade TLS、mKCP、VLESS Encryption（X25519/ML-KEM-768） | 完整 XHTTP 设置/CDN 会话放置、完整 gRPC 头部/trailers、完整 fallback 语义、完整路由/DNS/观测/管理面、Linux x86_64（QEMU）与 Windows 平台、release；macOS ARM64 的 Rust 1.91/1.95 与 Linux ARM64 Rust1.95 全量已过 | **只能替代已列出的服务端协议子集，不能替代完整 Xray-core** |
| sing-box | Trojan、VLESS、VMess、Shadowsocks、Hysteria2、TUIC、ShadowTLS、AnyTLS、Snell、Naive、WireGuard、NW3 等服务端子集 | sing-box v1.14.4：ShadowTLS v3 双向、SS2022 EIH 出站、Hysteria2 出站带宽协商、VLESS Vision、Trojan/TLS、Hysteria2/TUIC v5/AnyTLS/Snell v6/Naive H2 客户端到本内核入站 TCP/UDP（部分为 UoT v2）；Mihomo 补测 Hysteria2/TUIC/ShadowTLS/AnyTLS/Snell v5 入站 | sing-box 的完整协议矩阵与版本、TUN/规则/DNS/面板/出站生态、完整配置兼容、Linux x86_64（QEMU）与 Windows 平台、release | **只能替代已列出的服务端协议子集，不能替代完整 sing-box** |
| Mihomo | 仅 SOCKS/HTTP/Mixed 本地监听入口与部分服务端协议 | 本内核可提供 SOCKS/HTTP/Mixed 等入口，但 Mihomo 主要是客户端/规则引擎 | 客户端出站选择、订阅、规则集、TUN/redirect/tproxy、面板 API、Clash 配置生态 | **不能替代 Mihomo 作为客户端内核** |

## 判定标准

只有同时满足以下条件，才把某角色写成“可替代”：

1. 固定上游版本与本内核实际完成双向或明确方向的协议互通，而不是只做配置解析或
   本机自环；
2. 业务载荷经过真实请求校验，不只检查监听端口；
3. 负向认证、错误密钥/证书信任边界与资源回收有证据，失败关闭；
4. 配置、传输、安全层和路由/统计边界与上游语义不冲突；已知缩窄显式列出；
5. 不把单版本、单平台、单配置形态扩称为全矩阵兼容。

当前所有“可替代”结论都只覆盖 macOS ARM64 本机回环、固定上游版本与列出的组合；
macOS ARM64 的 Rust 1.91/1.95 全量与 release 构建、Linux ARM64 Rust1.95 全量与 release 已完成；
Linux x86_64 的 check 通过但 QEMU 全量因 cargo fork/exec 死锁未完成，x86_64 release 未构建；
Windows、可发布 release、生产容量与完整安全审计仍未完成。

## 距离完整替代的主要缺口

### 对 Xray-core

- XHTTP 完整 `xhttpSettings`、`downloadSettings`、CDN/会话放置与 H3 交互；
- gRPC 完整头部/编码/trailers 语义与官方矩阵；
- fallback 的完整回退语义（Unix socket `dest` 已补，单条目匹配与回放仍为稳定子集）；
- 路由/DNS/观测/管理接口与 Xray 的完整配置兼容；
- VLESS Encryption 与上游可选的 Vision/无 TLS 组合当前仍有限制，需逐项核对；
- mKCP 已双向通过：Xray 客户端 → 本内核 `vless-kcp`，以及本内核 `vless` + KCP
  出站 → Xray v26 服务端；后者修复了 VLESS 应答头同步预读导致的死锁；
- Xray v26.10.31 已移除旧 QUIC transport（需改用 XHTTP H3），本内核 QUIC 出站面向
  sing-box 形状，不能以 Xray 旧 QUIC 作为官方互通目标。

### 对 sing-box

- Hysteria2 完整客户端矩阵、精确 Brutal pacing/BBR profile、realm/端口跳跃；
- TUIC 0-RTT、更多拥塞控制/版本行为；
- ShadowTLS v1/v2、Snell QUIC 等未实现能力；
- Naive、AnyTLS、Snell 的官方客户端→本内核方向已做有限组合；WireGuard 服务端入站
  未实现，仍无官方客户端交叉矩阵；
- sing-box 的规则、DNS、TUN、面板与完整配置生态（本内核不试图复制全部）。

### 对 Nowhere

- 官方 Anywhere 客户端；
- Portal 分离监听、通配主机、多用户/多密钥、多实例 Egress；
- Morph 认证负例、无可用 Egress 超时失败、复杂 NAT/限速组合；
- Linux x86_64（QEMU）与 Windows 平台、release。

## 推荐推进顺序

1. 完成 Xray REALITY-over-gRPC/XHTTP 组合，把 Xray 服务端替代范围从 RAW
   扩到 REALITY 的全部上游承载；
2. 补齐 Xray XHTTP 完整设置与 sing-box/Mihomo 的 gRPC/XHTTP 客户端组合；
3. 补 Hysteria2/TUIC 的官方客户端矩阵与明确不宣称的 Brutal/0-RTT 边界；
4. 补 Anywhere/Nowhere 剩余角色与负向语义；
5. 最后做 Linux x86_64（QEMU）、Windows、release 与完整安全/容量验收。

在完成这些之前，对外只能表述为：**可替代 Nowhere 的 Portal/Egress 服务角色，
以及在列出的协议子集内替代 Xray-core / sing-box 的服务端角色；不能替代 Mihomo，
也不能完整替代任何一家内核。**
