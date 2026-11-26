# AnyTLS 入站与出站边界（开发实现，待集中验收）

本页描述 `type: "anytls"` 入站与原生出站的**已实现行为与明确限制**。线协议以本地只读上游
`sing-anytls@v0.0.0-20260902142641-43bb1cbea74e`（`service.go`、`session.go`、
`stream.go`、`client.go`、`settings.go`、`padding.go`）为事实来源，不按名称或记忆推断。

> **证据状态：开发实现已编译并有本机回环证据。** 入站、padding 和会话池按批次分别记录；池收尾输入锁定离线全量1335通过、0失败、43忽略，完整结果与真实失败见[池开发记录](anytls-pool-development.md)，不得沿用旧输入的全量数字。已用固定 Mihomo v1.19.33 与 sing-box v1.14.4 客户端完成到本内核入站的 TCP 与 UoT v2 UDP 本机互通；macOS ARM64 Rust1.91/1.95 与 Linux ARM64 Rust1.95 全量已通过，官方上游客户端全矩阵、Linux x86_64/Windows 与可发布 release 验收未执行。

## 出站

`type:"anytls"` 出站使用 `password` 与必填 `tls`（显式 CA）。在 TLS 上先发送
32 字节 `sha256(password)`、握手 padding、`v=2` Settings、SYN 与携带目标的
PSH；随后按 AnyTLS 帧收发。

- 运行时出站默认启用正式空闲会话池；同一 TLS 仅一次身份前导与 Settings，各目标使用递增流 ID、SYN + 目标 PSH，TLS 会话与 padding 包计数不按流重置。TCP/UoT 共用同一出站池与方案，根和 TCP 链中间跳都先取池，池空才按原工厂拨号。
- 池按固定上游选最新空闲会话；不会因为协议支持多 ID，就擅自优先把所有并发业务塞到忙会话。正常并发可建立不同 TLS，会话层可同时持有多个独立 ID，关闭一 ID 不关闭其它 ID，旧 ID 的迟到 PSH/FIN 不串目标。
- 每出站独立共享 padding factory，默认握手实际填充30字节，Settings声明原文MD5，首批Settings/SYN/目标PSH按上游规则合并整形。运行时池持续后台读取控制帧，合法命令6作用于后续写及新握手，无效/超界更新保留旧方案；已停止整形的会话不因更新重启包计数。低层独立单流适配仍由用户读取驱动，不伪称该 API 已复用会话。
- 本地 FIN 关闭整条逻辑流，排空已接受写后只发送一次；peer FIN 不回送，已排队下行可读完再 EOF。若 peer FIN 到达时仍有未实际 flush 的已接受写或未确认屏障，`shutdown` 明确返回错误，不能把对端关闭当成发送完成。不是 TCP 半关闭，不承诺发 FIN 后仍可继续对端业务。非空 SYNACK 错误只终止相应 ID，非空 Alert/认证/传输/截断使整个会话失败；合法心跳/拒绝控制回复在有期限的有限队列中等待，暂满不立即关闭其它 ID。对端文本不作为业务或日志回显。
- 已获 ServerSettings v2 的会话，从第二次开流开始使用上游3秒看门狗，下一完整帧头到达即解除，不错误等待其全部 payload；失败不自动重放业务。
- 池参数可省略，默认检查/超时均30秒、最少保留0项；可选 `anytls` 对象见下表。最多64缓存项、每会话64流、每流4块读队列、64项写队列，慢流按上游施加背压。热替换退休旧池、关闭空闲项但保留旧活流；最终停机取消所有池任务并等待 socket 真实回收。
- 无原生 UDP 帧与 fallback；目标为 `sp.udp-over-tcp.arpa` / `sp.v2.udp-over-tcp.arpa` 时按协议层 UoT（v1/v2）处理，其余 UDP 目标失败关闭；出站 UDP 固定使用 UoT v2；
- 本机 `tests/outbound_protocols.rs` 与 `tests/anytls_pool.rs` 覆盖生产路径，独立对端另核前导/ID/控制帧；完整验证状态见[池开发记录](anytls-pool-development.md)，不等同官方客户端验收。

| 出站 `anytls` 字段 | 默认 | 说明 |
| --- | --- | --- |
| `disable_reuse` | `false` | 为 true 时流结束关闭会话；不禁用正式帧/认证/填充 |
| `idle_session_check_interval_ms` | `30000` | 显式值5001..86400000毫秒；本地拒绝≤5秒，不默默改成默认 |
| `idle_session_timeout_ms` | `30000` | 同上；按空闲检查周期回收，不是实时硬截止 |
| `min_idle_session` | `0` | 0..64，只保留已有会话，不主动预拨；禁用复用时必须0 |

模板：`examples/anytls-pool-outbound.json`。低层 `outbound::connect` 已接收一条承载，仍为独立单流握手；生产池复用通过 `Context` 工厂完成。新池不新增协议字段、依赖或 vendor 补丁，既有[padding 批记录](anytls-padding-development.md)的历史结果不覆盖后续输入。

## 入口与配置

AnyTLS 是**必须使用真实 TLS** 的独立入口，不与其他传输组合。

```json
{
  "type": "anytls",
  "tag": "anytls-in",
  "listen": "127.0.0.1:10447",
  "users": [{ "name": "u", "password": "REPLACE_WITH_A_RANDOM_PASSWORD" }],
  "certificate": "/absolute/path/to/fullchain.pem",
  "private_key": "/absolute/path/to/private-key.pem"
}
```

- `tag`、`listen`、`certificate`、`private_key` 必填；`users` 至少一项，`name` 与 `password` 均不得为空，且同一入口内 `name`、`password` 不得重复。
- 配置使用 `deny_unknown_fields`：传入上游存在但本实现未支持的 `fallbacks` 等字段会直接报错，而不是静默忽略。
- TLS 证书/私钥由运行器加载并校验匹配；支持 TLS 1.2/1.3，不启用客户端证书，不强制 ALPN。
- 运行时分派：连接 driver 在完成 TCP accept 与准入配额后交给 AnyTLS 模块；该模块自行完成 TLS 握手、认证、会话与流。`runtime` 不再走通用 `handle` 分支。
- 路由拒绝：单条流的目标拨号被路由拒绝时按流失败处理（协议版本 >= 2 时回带错误文本的 SYNACK，随后 FIN），不会终止整个 AnyTLS 会话；入口级错误仍计入拒绝统计。
- 模板：`examples/anytls.json`，其中密码与证书路径必须在部署前替换。

## 认证与握手填充

已从上游源码确认：

1. TLS 建立后，客户端先写 `sha256(password)` 的 32 字节原始摘要，随后写 **2 字节大端（BigEndian）握手填充长度**，再写该长度的零字节（`client.go: createSession`）。
2. 服务端读取 32 字节密码摘要，与每个用户的 `sha256(password)` 做常量时间比较；任一项命中即通过（`service.go: NewConnection/NewMultiService`）。
3. 认证通过后服务端读取 2 字节填充长度并**丢弃**对应字节（`service.go: serve`）。本实现同样只消费、不校验填充内容。
4. 填充长度来自客户端的 `GenerateHandshakePaddingSize()`：取填充方案中包序号 `0` 的第一个区间。上游默认方案为 `0=30-30`，因此正常客户端发送 30 字节（`padding.go`）。本实现按连接实际声明长度读取，不假设固定 30。
5. 认证失败时上游在未配置 fallback 的情况下直接关闭连接；本实现同样直接关闭，不发送任何业务帧。

**服务端 padding 方案更新（命令 6）**：客户端在 Settings 中发送 `padding-md5=`。服务端按上游默认方案（UTF-8、`\n` 分隔、无结尾换行，MD5 为 `75cff2ad89aadf5e257059ee571ebe11`）计算摘要；当客户端声明缺失或不一致时，在 `ServerSettings` 之前发送命令 6（流 ID 0），负载为方案原始字符串。帧头仍为 7 字节：命令 1 字节、流 ID 4 字节大端、长度 2 字节大端。

- 客户端 `newClientSession` 初始化 padding 并把 MD5 放进 Settings；`DialContext`/`writeRequestLocked` 不阻塞等待服务端确认。
- 客户端 `readLoop` 仅在收到命令 6 时替换 padding 工厂；缺少该帧不会导致状态机阻塞。
- 客户端仍会按自己的方案在**上行**插入 waste 帧；服务端必须全部正确跳过。
- 服务端可选`padding_scheme`原始字符串，省略为规范默认方案；配置阶段验证后按原始文本及MD5下发，不重排/补行。未知Settings键不回显、不猜测格式。自定义示例：`"padding_scheme":"stop=4\n0=30-30\n1=200-200\n2=400-400,c\n3=500-500"`。这仍使用既有cmd6/Waste帧，不是私有扩展。

## 帧格式与帧表

所有帧头固定 7 字节：

| 偏移 | 长度 | 含义 |
|---|---|---|
| 0 | 1 | 命令号 |
| 1 | 4 | 流 ID，大端 `u32` |
| 5 | 2 | 负载长度，大端 `u16`（0..=65535） |
| 7 | N | 负载 |

命令号以 `anytls.go` 常量为准：

| 命令 | 名称 | 方向 | 负载与语义 |
|---|---|---|---|
| 0 | Waste | 客户端 → 服务端（也允许任意方向） | 填充占位零字节；服务端读取后丢弃 |
| 1 | SYN | 客户端 → 服务端 | 官方客户端发送**长度 0**；目标地址不在 SYN 负载里。服务端要求此前已收到 Settings，否则回 ALERT 并结束会话 |
| 2 | PSH | 双向 | 流数据。SYN 后的第一个 PSH 负载以 SOCKS5 风格目标地址开头，剩余字节是业务数据 |
| 3 | FIN | 双向 | 关闭该流。服务端收到后丢弃该流；服务端在上游方向结束时发送 FIN，但对端已发 FIN 的流不再回送 |
| 4 | Settings | 客户端 → 服务端 | 文本，`key=value` 以 `\n` 连接；客户端按键名排序写入 `client=`、`padding-md5=`、`v=`。服务端使用 `v` 判断协议版本、用 `padding-md5` 决定是否更新 padding 方案；空负载不算已发送 Settings |
| 5 | Alert | 双向 | 服务端在 SYN 早于 Settings 时发送非空错误文本并结束会话；服务端收到**非空** Alert 结束整个会话，零长度 Alert 忽略 |
| 6 | UpdatePaddingScheme | 服务端 → 客户端 | 客户端 `padding-md5` 缺失或不等于服务端默认方案时发送，负载为方案原始字符串；若收到客户端发来的命令 6，按上游服务端行为直接丢弃负载 |
| 7 | SYNACK | 服务端 → 客户端 | 仅在客户端 `v>=2` 时发送。拨号成功为空负载；失败携带错误文本，随后 FIN |
| 8 | HeartRequest | 客户端 → 服务端 | 服务端丢弃负载后回复命令 9 |
| 9 | HeartResponse | 服务端 → 客户端 | 空负载，流 ID 沿用请求的流 ID |
| 10 | ServerSettings | 服务端 → 客户端 | 仅在客户端 `v>=2` 时发送，负载精确为 `v=2`（上游 `settings.Bytes()` 不追加换行） |

未知命令与命令 0/6 一样按长度丢弃，不会破坏后续帧边界。

## 流生命周期

1. 客户端在 TLS 上写认证摘要、填充长度与填充。
2. 客户端发送 Settings（官方实现会把 Settings 与首个流的 SYN/PSH 合并在同一批写入中）。
3. 每个流：`SYN(id, 长度 0)` 后紧跟 `PSH(id, 目标地址 [+ 初始数据])`。
4. 服务端从该流的**字节流**读取目标地址（不读取 SYN 负载）。目标地址类别码与 `sing/common/metadata` 的 `SocksaddrSerializer` 一致：`1`=IPv4、`4`=IPv6、`3`=域名（1 字节长度 + 域名），随后 2 字节大端端口。
5. 拨号成功：客户端版本 >= 2 时发送空 SYNACK，然后双向 PSH 中继。拨号失败：发送带错误文本的 SYNACK 与 FIN。地址解析失败同样按握手失败处理。
6. 任一方向发送 FIN 表示**关闭整条流**（不是 TCP 半关闭）。服务端收到 FIN 后立即终止该流的中继、关闭上游连接，并且不回送 FIN——对应上游 `closeByPeer`：关闭已关闭的流是空操作。服务端自身在上游方向结束时发送一次 FIN。该语义也避免迟到的 FIN 误关复用同一流 ID 的新流。
7. 同一流 ID 在关闭后可再次使用；重复的存活流 ID 的 SYN 被忽略；未注册流的 PSH 被丢弃。
8. 每会话最多 64 条并发流；超限的新 SYN 直接回 FIN（不建立流）。
9. 本地对解析目标地址做加固：域名必须为 1..255 个 ASCII 可见字符，端口不得为 0；这与上游“几乎不校验”的行为略有差异，属于拒绝无效目标的本地策略，不改变合法客户端的线格式。

## 资源上限

以下均为本地实现常量或既有全局限额，不是上游协议要求：

- 每会话并发流：64（`MAX_STREAMS`）；超限回 FIN。
- 每流排队帧：4（`STREAM_BUFFER`）；达到上限时暂停读取整个会话，形成背压。
- TCP 每流只有上行经过 64 KiB 字节缓冲；下行在会话队列有空位时直接编码 PSH。UoT 仍使用每方向最多 64 KiB 的双工桥（`BRIDGE_BUFFER`）。
- 会话下行队列：64 项，控制帧、PSH 和 flush 屏障共享；下行 PSH 每帧最多 16 KiB。TCP 流的 flush 在会话 writer 写完此前所有帧且底层 TLS flush 成功后才确认。
- 单个 PSH 负载上限：65,535 字节（帧头长度字段决定）。
- TLS 握手与认证前导共用 `limits.handshake_timeout_ms`。
- 连接与并发握手分别受 `limits.max_connections`、`limits.max_handshakes` 约束。
- 当前没有单次控制帧写超时；停机依赖运行器的 `shutdown_timeout_ms` 与 force 取消。

## 明确不支持

- **无原生 UDP**：AnyTLS 本身没有 UDP 帧；本入口只做 TCP CONNECT 语义，不实现 SOCKS5 UDP ASSOCIATE。兼容基于流的 UoT：目标为 `sp.udp-over-tcp.arpa`（v1）或 `sp.v2.udp-over-tcp.arpa`（v2）时进入共享 `udp::uot`，与 VLESS/VMess/Shadowsocks 的 UoT 共用预算与超时。
- **方案输入有公开安全上限**：原文≤65535字节、握手区间上界≤65535，单生成区间≤256KiB、每包最多128项/总有效项≤4096，单包最坏填充含Waste头≤1MiB。超界本地配置拒绝、远端更新保留旧值；不宣称所有上游无界输入都可用，详见[开发记录](anytls-padding-development.md)。
- **无 fallback**：认证失败或前导无效时直接关闭；配置没有 `fallbacks` 字段，声明该字段会被拒绝。
- **无服务端心跳发起**：仅被动应答 `HeartRequest`；不维护额外空闲超时。
- **不使用客户端元数据**：Settings 中的 `client=` 仅被解析时忽略，不进入日志或路由。
- 不提供显式 ALPN 绑定、会话迁移、跨连接复用或 UDP 扩展。
- 官方上游客户端全矩阵、Linux x86_64/Windows 与可发布 release 验收均未执行；Mihomo v1.19.33 与 sing-box v1.14.4 客户端 TCP + UoT v2 UDP 的有限本机互通已通过。

## 证据（本批状态）

已编写的本地回环用例位于 `tests/anytls.rs`：

- `authenticated_session_relays_a_stream`：认证、Settings、SYN+PSH、SYNACK 与回显。
- `independent_streams_are_multiplexed`：同会话两流并行。
- `wrong_password_closes_without_relaying`：错误密码直接关闭。
- `syn_before_settings_gets_an_alert`：SYN 早于 Settings 回 ALERT。
- `handshake_padding_is_consumed_before_frames`：30 字节握手填充被消费后帧仍对齐。
- `version_two_gets_server_settings_then_empty_synack`：ServerSettings 精确为 `v=2`，成功 SYNACK 为空。
- `version_one_gets_no_server_settings_or_synack`：v1 客户端不收 ServerSettings/SYNACK，直接收数据。
- `waste_frames_are_skipped_and_heartbeat_is_answered`：waste 帧跳过、心跳应答沿用流 ID。
- `peer_fin_is_not_echoed`：对端 FIN 后服务端保持静默，不回送 FIN。

`src/transport/anytls.rs` 内的单元测试覆盖：Settings 版本解析、7 字节帧头字段、ServerSettings 精确字节、目标地址 `1/4/3` 类别码与非法类别/空域名/端口 0 拒绝。

本机回环及模块验证已实际执行，包含自定义方案原文/MD5与合法更新应用；历史padding输入结果见[padding开发记录](anytls-padding-development.md)，随后会话池输入与当前验证进度见[池开发记录](anytls-pool-development.md)。官方上游客户端全矩阵、Linux x86_64/Windows、可发布release仍未执行，不由内核双方互测推导；Mihomo v1.19.33 与 sing-box v1.14.4 客户端 TCP + UoT v2 UDP 的有限本机互通另行记录。
