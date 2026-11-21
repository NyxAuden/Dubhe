# Xray Mux.Cool 服务端

本文件描述 `src/mux.rs` 实现的服务端 Mux.Cool 复用层。实现以 Xray v26.10.31
`common/mux` 的线协议为准独立编写；Mux 帧只出现在已经完成 VLESS/VMess 认证的
字节流内部，本层不发送任何 VLESS/VMess 握手应答。

## 1. 连接建立

有两条入口：

- **命令 3（Mux）**：VLESS 命令 3 不携带目标字段，直接解析为 `Accepted::Mux`；
  VMess 命令 3 同样无目标（`address_end == 38`），解析为 `Mode::Mux`。命令 3
  的准入与 `xudp` 开关无关。
- **命令 1 + 目标 `v1.mux.cool`**：目标域名必须精确等于小写 `v1.mux.cool`，
  与 Xray 哨兵一致；大小写变体按普通目标处理。

两种入口最终都调用 `serve` / `serve_scoped`，并传入 `allow_udp`：命令 3 的
TCP 会话始终允许；Mux 内的 UDP New/GlobalID 仅在 `allow_udp == true`（即所属
入站 `xudp: true`）时准入。未开启时该 UDP 会话收到 `End + Error`，整条 Mux
连接保持可用。

调用方必须在把字节流交给本模块之前完成协议应答：VLESS 发送 `00 00`，
VMess 按其正常流程完成应答与正文层包装。本模块从第一条 Mux 帧开始读写。

Mux 连接上没有协议级握手；第一条由客户端发出的帧就是 New/Keep 等普通帧。

## 2. 帧格式

```text
+---------------------------+
| metaLen: u16 大端          |  仅元数据长度，不含其后的数据长度与数据
+---------------------------+
| meta: metaLen 字节         |
|   session id: u16 大端     |
|   status: u8               |
|   option: u8               |
|   （按 status 可选的目标字段与 GlobalID） |
+---------------------------+
| 若 option 含 0x01 Data：   |
|   dataLen: u16 大端        |
|   data: dataLen 字节       |
+---------------------------+
```

关键点：`metaLen` **只**覆盖元数据。Data 载荷在元数据之后另有一个 2 字节大端
长度前缀；TCP 与 UDP 会话都使用该前缀。Xray 的 `writeMetaWithFrame` 在写元
数据后立即写 `uint16(data.Len())`，随后写数据。`metaLen` 不包含这个长度字段，
也不包含载荷。

- `metaLen` 必须位于 `4..=512`。小于 4 无法容纳固定头；大于 512 直接以
  `InvalidData` 结束整条 Mux 连接。
- `dataLen` 上限由 u16 决定（65535）。UDP 载荷还受配置的
  `limits.max_udp_payload` 限制。
- 允许 `dataLen = 0`；空负载会作为空数据消费，不改变帧边界。

### 2.1 status

| 值 | 名称 | 服务端语义 |
| --- | --- | --- |
| `0x01` | New | 新建会话；剩余元数据按网络类型解析目标 |
| `0x02` | Keep | 向已有会话写入数据；可携带变化的 UDP 目标 |
| `0x03` | End | 关闭会话；若带 Data 则消费后丢弃 |
| `0x04` | KeepAlive | 心跳；若带 Data 则消费后丢弃 |

未知 status 视为畸形帧，立即结束整条 Mux 连接。

### 2.2 option

| 位 | 名称 | 说明 |
| --- | --- | --- |
| `0x01` | Data | 元数据后有 2 字节长度和负载 |
| `0x02` | Error | 错误标记；Keep+Error 关闭该会话；End+Error 仅用于下行错误通知 |

未知选项位视为畸形帧。`KeepAlive + Data` 的负载会被完整读取后丢弃，避免破坏
后续帧边界。

### 2.3 network 与目标地址

- `0x01` TCP
- `0x02` UDP

New 帧的元数据在 `status/option` 后依次为：

```text
network: u8
port: u16 大端
address: 1 字节类型 + 地址体
```

地址类型使用 Mux 自己的编号（不是 SOCKS5）：

| 类型 | 含义 | 地址体 |
| --- | --- | --- |
| `0x01` | IPv4 | 4 字节 |
| `0x02` | Domain | 1 字节长度（非 0）+ 域名 |
| `0x03` | IPv6 | 16 字节 |

域名必须是 ASCII graphic，长度 1..=255；与 VLESS 地址规则保持一致。

对于 `Keep + Data`：若元数据长度大于 4 且第 4 字节（network）为 `0x02`，则
元数据中同样携带 `network + port + address`，用于 UDP 会话的目标地址变化。
只有这种组合才会解析 Keep 的目标；TCP 会话忽略 Keep 中出现的 target。

服务端下行的 UDP 数据帧会在 Keep 元数据中携带实际 UDP 来源地址，Xray 的
`PacketReader` 依赖该字段标注数据报来源。

## 3. GlobalID

`GlobalID` 是 8 字节，只出现在 **New + UDP + Data** 帧的元数据末尾（目标地址
之后）。全零 GlobalID 视为未提供。

- 当前 `Context` 实例内的去重表上限 256；超过上限时新 GlobalID 的会话收到 `End + Error`。
- 同一 GlobalID 再次出现时复用已有 UDP 关联，并把回程 sink 迁移到新会话；
  旧会话收到服务端主动发送的 `End + Error`（`ForceEnd` 事件）。
- 最后一个会话结束后，关联进入 1 分钟宽限期：登记表持强引用保留 UDP 套接字
  与目标映射，期间新 Mux 连接可用同一 GlobalID 续接并恢复回程；到期由定时
  任务释放，登记表同时按需惰性清理失效/过期条目。宽限期内的关联不再计入
  `udp_associations` 统计。
- 没有会话持有的 `Active` 条目只保留 `Weak` 引用；强制取消等未经过正常关闭
  的路径不会进入宽限期，关联随最后一个 `Arc` 释放。
- 每个 UDP 关联按目标维护独立的 connected `UdpSocket`，回程数据报携带实际
  来源 IP 与端口。
- 没有 GlobalID 的 UDP 会话拥有只属于该会话的关联；会话关闭即释放。

与 Xray 的差异：Xray 的条目表无上限且由每分钟一次的扫描释放过期条目；本实现
沿用相同的 1 分钟宽限期语义，但表上限固定为 256，宽限期到点即释放并辅以惰性
清理。GlobalID 在单个 `Context` 实例内共享，不按用户或入站隔离；SIGHUP
原地热重载会创建新 `Context`，因此不跨热重载实例续接。Xray 的对应表是进程级
且无此处 256 项上限，这一范围差异不能写成完全等价。

## 4. 会话与资源上限

| 资源 | 上限 |
| --- | --- |
| 单条 Mux 连接的并发会话 | 256 |
| 每会话上行队列 | 64 个有界块 |
| 单条 Mux 连接排队字节 | 入站侧 256 KiB、出站写队列 256 KiB |
| `metaLen` | 512 |
| GlobalID 去重表（Context 实例级） | 256 |
| GlobalID 宽限期 | 最后一个会话结束后 60 秒 |
| UDP 目标映射 | 配置的 `limits.max_udp_targets` |
| UDP 关联名额 | 配置的 `limits.max_udp_associations` |
| 空闲关闭 | 连续 60 秒无会话且无帧活动 |

- 读、写、会话事件分别使用有界 `mpsc`；所有上行/下行写入经过单一 writer
  任务，保证帧不交错。
- 入站与出站队列另有字节预算，预算耗尽时通过等待施加背压，而不是无限缓存。
- 达到会话上限时，新会话收到 `End + Error`，整条 Mux 连接保持可用。
- 入站未开启 `xudp` 时，Mux 内的 UDP New/GlobalID 会话收到 `End + Error`；
  TCP 会话不受影响，整条 Mux 连接保持可用。**`xudp` 是本实现的入站准入字段**：
  Xray 的 XUDP 是客户端/Mux 行为，未发现等价的入站开关；因此库存 Xray 客户端
  入站 `xudp` 默认开启；显式 `xudp:false` 时 Mux UDP 被拒。
  这是比上游更严格的准入，不是协议帧差异。
- 未知 session id 的 `Keep + Data` 会收到 `End`（无 Error），负载被消费后
  丢弃，连接不中断。
- TCP 拨号失败向该会话发送 `End + Error`，不会结束整条 Mux 连接。
- 连续 60 秒既没有会话也没有任何帧活动时关闭整条连接。

## 5. TCP 会话

New 时调用运行层 `Context::connect_routed` 拨号；成功后按块双向桥接：

```text
客户端 Keep/New Data  --有界队列-->  上游 TCP 写端
上游 TCP 读端          --Keep+Data--> 客户端
```

启用顶层 `sniffing` 且该入站在范围内时，拨号前先在 `timeout_ms` 内累积子流
数据帧并尝试识别 TLS SNI / HTTP `Host`；识别成功则域名参与选路，已累积字节
在拨号成功后原序写回上游。`dest_override` 允许时用域名拨号，否则仍拨原始
目标。超过期限或不可识别时按未嗅探处理。

上游 EOF 时向客户端发送 `End`；读写错误发送 `End + Error`。客户端 End 时
直接中止会话任务并关闭上游连接。

## 6. UDP 会话

- 每个 Mux UDP 会话映射到一个 UDP association。
- New 的目标作为初始目标；Keep 未携带目标时沿用初始目标。
- 每个目标使用 connected UDP socket，回程只接受该目标的数据。
- 每个数据报的 QUIC Initial SNI 参与出站选择，实际发送目标不变（与共享
  `Association` 的 UDP 嗅探语义一致）。
- association 的空闲映射按 `limits.udp_idle_timeout_ms` 清理。
- UDP 会话关闭后不再接收回程数据；GlobalID 被接管时旧会话的回程 sink 失效。

## 7. 与 Xray 客户端的兼容边界

已实现、尚未集中验收：

- Xray / sing-box 常见的 New / Keep / End / KeepAlive 帧。
- New+Data 首包、New 无 Data 后跟 Keep、Keep+Data 的 TCP 和 UDP 形态。
- New+UDP+Data 的 8 字节 GlobalID。
- Keep+Data 且 network=UDP 的逐帧目标变化。
- 服务端下行 Keep+Data；UDP 下行携带实际来源地址。
- 未知会话 Keep 的 End 响应。
- 大于 512 的 metaLen 拒绝。

明确不支持或有限支持：

- **Reverse Mux（`v1.rvs.cool` / VLESS 命令 4）**：Portal 与 Bridge 均已实现，Mux 隧道支持 TCP/UDP 会话，见[反向 Mux 说明](reverse.md)。
- New 元数据中的客户端 source / local 地址（Xray 反向 Mux 使用）：不支持，
  非 GlobalID 的尾部字节会被忽略。
- 旧会话的静默迁移细节：GlobalID 被接管时旧会话通过 `End + Error` 结束，
  但旧连接若已无响应者，其本地状态依赖其自身空闲清理。
- XUDP 全锥（full-cone）NAT 的极端语义：本实现为每个目标使用 connected
  UDP socket，只接受该目标来源的回包；不尝试模拟 Xray 在 cone 模式下的全部
  NAT 行为。
- TCP Mux 与 UDP Mux 可以共存于同一连接；但不支持在同一 session id 上从
  TCP 切换为 UDP 或反向切换。
- 命令 3 的入口整合：协议层已把 VLESS/VMess 命令 3 解析为 Mux，运行层的
  明文/WS/XHTTP/HTTPUpgrade/gRPC、Vision/REALITY 与 VMess 路径均已接入；
  「命令 1 + 目标 `v1.mux.cool`」同样已接入。
- WS/XHTTP/HTTPUpgrade/gRPC 的 VLESS 命令 3 现在与上游一致，先发送 VLESS
  应答再进入 Mux；早期 XUDP 的“首帧合法后才应答”行为已不再保留。
- `xudp` 开关不再决定命令 3 是否可用，只决定 Mux 内 UDP 会话是否准入。
- 未复刻上游 Vision 账号在“请求 flow 为空”时窥探首帧并拒绝 TCP Mux 的
  `isMuxAndNotXUDP` 额外限制；本实现保持既有 flow 矩阵，命令 3 在原有允许
  的组合下继续允许。需要严格对齐该限制时应由集中验收决定是否追加。

## 8. 错误策略

- 畸形 `metaLen`/status/option/network/地址、截断的元数据或数据、读写超时：
  以 `io::Error` 结束整条 Mux 连接（fail-closed）。
- 单个会话的拨号失败、UDP 目标失败、队列满或上游 EOF：只影响该会话，通过
  End 帧通知客户端，不拖垮整条 Mux 连接。
- 所有数量与长度均有静态上限；不使用无界 channel。
