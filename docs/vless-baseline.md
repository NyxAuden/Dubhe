# VLESS 基础组合与验证基线

日期：2026-11-04；命令 3 语义更新于 2026-11-06。对应 `add-vless-tls-inbound`。历史验收覆盖 VLESS v0 over TCP+标准 TLS、无 flow，以及当时显式开启的 UDP-only XUDP 扩展，均有三家固定官方客户端的有限外部验收证据。**当前命令 3 已按上游语义路由到完整 Mux.Cool（TCP 会话 + `xudp` 门控的 UDP），属于“已实现待集中验收、未测试”；本文件保留的旧 XUDP 结论不能推导 TCP Mux 兼容，当前边界见 [Mux 说明](mux.md)。** REALITY/Vision、VLESS Encryption、Rvs、跨承载 1 分钟续接、WebSocket/gRPC/XHTTP 不在本历史变更内。

## 固定来源

参考 Xray-core v26.10.31，commit `a4a3dff5b20c2faae567b742c172c7b95e75c083`：

- [请求与响应编码](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/encoding/encoding.go)：版本0、UUID、addons、命令、目标；响应版本与 addons。
- [addons 与原生 UDP](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/encoding/addons.go)：addons 长度为 u8，UDP 长度为两字节大端；原生 writer 不发送零长度载荷。
- [命令](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/protocol/headers.go)：TCP=1、UDP=2、Mux=3、Rvs=4。
- [地址类型](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/protocol/payload.go)：IPv4=1、domain=2、IPv6=3。
- [地址序列化](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/protocol/address.go)：VLESS 选择 PortThenAddress，端口两字节大端；域名带 u8 字节长度。

以上为只读协议研究，未复制上游实现。Xray 许可与项目自身许可证边界见 source-research.md。

## 本次行为

基础请求为 `00 | UUID(16) | addons-length(0) | command | port(BE u16) | address-type | address`。默认只接受 TCP/UDP；非空 addons 直接拒绝而不忽略其中可能的 flow。TCP 成功拨号后发送 `00 00` 响应头，然后双向转发并保留半关闭。

原生 UDP 每条承载连接固定一个目标，帧为 `payload-length(BE u16) | payload`。不同目标需要不同 VLESS 请求；不能套用 Trojan 的逐帧地址。零长度帧消费后丢弃计数，空 UDP 回包同样丢弃；上游客户端自身也可能限制最大 UDP 载荷，不能从 u16 宽度推出所有客户端支持 65535 字节。

认证 UUID 只接受 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` 的标准十六进制形式，大小写等价，不支持上游自定义字符串到 UUID 的派生。UUID 是凭据，Debug/错误/日志需脱敏。VLESS 本身没有负载加密，因此本入口必须配置 TLS 证书和匹配私钥。

## 使用

复制 `examples/vless.json` 后，将 UUID 占位值替换成随机 UUID，将证书链/私钥改成实际绝对路径。占位值故意不满足配置校验，避免误用共享示例凭据。

```sh
./target/release/dubhe check -c "examples/vless.json"
./target/release/dubhe run -c "examples/vless.json"
```

客户端选 VLESS、TCP、TLS、空 flow，校验服务器证书；不要启用 REALITY、Vision。若要复现本文件 2026-11-04 的基础/旧 XUDP 基线，客户端不要启用通用 TCP 复用，基础模式禁用 XUDP；需要旧 XUDP 时服务端设 `xudp:true`。当前命令 3 的完整 Mux 属单独待验收能力，见 [Mux 说明](mux.md)。具体配置由 `tests/reference_clients.rs` 生成，实际运行结果单独记录；Trojan 的已通过结果不证明 VLESS。

## 固定客户端的原生 UDP 配置差异

- **Mihomo v1.19.33**：[adapter/outbound/vless.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go) 的初始化逻辑在非 PacketAddr 模式下强制 XUDP；显式 `xudp:false` 仍不能得到原生固定目标 UDP。基础模式只验收 TCP，报告中 UDP 为 `unsupported_by_client_baseline`。Mihomo UDP 已通过独立 XUDP 模式实测，三家 XUDP TCP/UDP 及身份/信任负向测试结果见验收报告。
- **sing-box v1.14.4**：[option/vless.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/option/vless.go) 使用可选字符串；[protocol/vless/outbound.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/vless/outbound.go) 对省略/null 默认 XUDP，必须显式 `packet_encoding:""` 并禁用 multiplex。
- **Xray v26.10.31**：除禁用 mux 与 `xudpConcurrency:-1`，测试子进程还设置 `XRAY_CONE_DISABLED=true`。固定 [core/xray.go](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/core/xray.go) 读取对应平台环境项；[proxy/vless/outbound/outbound.go](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/outbound/outbound.go) 的 cone 路径可能将 UDP 转为 XUDP。该变量只给测试子进程，不修改全局环境或系统配置。

以上结论来自固定源码，配置生成单测只证明测试配置按预期生成；外部程序接受配置并实际转发仍需独立执行验收。

## 历史 UDP-only XUDP 基线（当前由完整 Mux 取代）

来源固定为 Xray 的 [Mux 帧](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/mux/frame.go)、[XUDP 读写器](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/xudp/xudp.go)，以及 Mihomo 所用 MetaCubeX/sing-vmess v0.2.5，commit `9b7fdbf462a5cf6366628631ef426c1a91f5df82` 的 [xudp.go](https://github.com/MetaCubeX/sing-vmess/blob/9b7fdbf462a5cf6366628631ef426c1a91f5df82/xudp.go) 和 [地址序列化定义](https://github.com/MetaCubeX/sing-vmess/blob/9b7fdbf462a5cf6366628631ef426c1a91f5df82/protocol.go)。标签 ref API 已确认对象类型为 commit。实现独立编写，未复制 Go 源码。

以下帧布局仍被完整 Mux 使用，但受理与拒绝规则已变化：命令 3 不再由 `xudp` 决定是否接受，TCP New 合法；`xudp` 只门控其中的 UDP 会话。下列各条中的旧行为说明仅记录 2026-11-04 历史基线，不再代表当前实现。

服务端设置 `xudp:true` 后，认证及空 addons 之后接受命令 3，不再读取基础目标字段。随后每帧为：

```text
metadata_length (BE u16，4..512，不含自身)
session_id (BE u16) | status (u8) | options (u8)
[network=2 | port (BE u16) | VLESS address]
[GlobalID (8字节，仅New+Data)]
[options含Data时：payload_length (BE u16) | payload]
```

- New=1 必须包含 network（1 TCP / 2 UDP）与目标。当前实现 TCP New 合法；历史 UDP-only XUDP 会终止承载。
- Keep=2 对 TCP 会话续传；对 UDP 可指定本报文目标，省略时使用该会话初始目标。End=3 关闭会话；KeepAlive=4 只作心跳，负载消费后丢弃。
- Data=1 表示载荷；Error=2 的 Keep 关闭会话、End 表示下行错误。未知 status/option/network、地址非法、截断帧或 `metaLen > 512` 以错误结束整条连接。
- 当前 Mux 中未知会话的 Keep 回 `End`（无 Error），重复 New 替换旧会话，均不终止承载；路由拒绝、关联名额、目标上限或超限载荷只结束该会话并回 `End+Error`。
- 回程发送相同编号的 Keep+Data；UDP 回程携带实际来源。GlobalID 是进程级去重键，后到连接复用关联并迁移 sink，旧会话收到 `End+Error`；最后一个会话结束后保留 1 分钟供跨承载续接，到期释放。历史“不同连接保持独立”的断言已过时。
- Mux UDP 会话占用一个全局 UDP 关联名额；目标映射按 `udp_idle_timeout_ms` 过期，会话本身不单独按空闲关闭。整条连接 60 秒无会话且无帧活动时关闭，停机/异常等待受追踪子任务释放。
- 空 UDP 数据报在当前 Mux 中保留边界并按 0 字节计量；历史 XUDP 会丢弃空回包。旧结论不推导当前行为。

客户端配置对应三个独立测试模式：

| 客户端 | XUDP 设置 | TCP 复用 |
|---|---|---|
| Mihomo | `udp:true`、`xudp:true` | `smux.enabled:false` |
| sing-box | `packet_encoding:"xudp"` | `multiplex.enabled:false` |
| Xray | 保留默认 cone；测试不设置 `XRAY_CONE_DISABLED`，目标端口避开53/443 | `mux.enabled:false` |

Xray 固定 [出站分支](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/outbound/outbound.go#L303-L320) 只把非53/443端口 UDP 请求改成命令3；普通 TCP 仍用命令1。内部覆盖多会话；外部已实际通过三家 XUDP 模式的 TCP、单 SOCKS UDP 关联中的两目标三报文、错误 UUID 拒绝和不受信任证书拒绝（错误信任仅 TCP）。构建与原始证据见 [验收报告](vless-acceptance.md)，不将这些结果扩大为当前 TCP Mux 或跨承载续接。当前 Mux 已接入 VLESS/VMess 及其传输包装，但状态仅为“已实现待集中验收、未测试”，见 [Mux 说明](mux.md)。
