# 失败关闭证据矩阵（2026-11-14）

本矩阵把现有测试映射到“畸形输入、认证失败、重放、资源上限、取消/停机”五类失败路径。
它只列已有证据和缺口，不等于独立安全审计，也不把单个回环测试扩称为官方客户端矩阵。

## 进程级可用性：`accept()` 遇到可恢复错误不得退出

2026-11-24 实测发现并修复：`accept()` 返回 `EMFILE`（FD 耗尽）时，原实现
直接跳出 accept 循环，监听任务返回错误，主循环把整个 Server 停掉。

复现（`ulimit -n 128`，两个入站）：

| 版本 | 结果 |
|---|---|
| 修复前 | 118 条半开连接后，第二个入站 `ConnectionRefused`，进程 `EXIT=1` |
| 修复后 | 200 条半开连接进程仍存活；释放连接后第二个入站立即恢复响应 |
| Xray 26.10.31 对照 | 200 条后进程存活，第二个入站返回 503 |

含义：修复前**单个 IP 用一百多条半开连接就能让整台服务器上所有协议同时掉线**，
这是可被普通扫描器触发的拒绝服务。

现在的规则（`src/runtime/accept.rs` 的 `recoverable_accept_error`）：

| 错误 | 处理 |
|---|---|
| `EMFILE`(24) / `ENFILE`(23) | 计一次 `rejected`，退避 20ms 后重试 |
| `WouldBlock` / `Interrupted` / `ConnectionAborted` | 退避 20ms 后重试 |
| 其它（`PermissionDenied` / `AddrNotAvailable` 等） | 上报并停止 |

同时修正停机日志：两处 drain 循环原本都用 `"停止监听任务失败"` **覆盖**首个
错误，导致真正的根因（例如 `EMFILE`）从日志里消失；改为 `get_or_insert`，
保留首个错误。

仍未做：**按源 IP 的限速/失败退避**。现在只能靠全局 `max_connections` 与
每入口 `max_handshakes` 限制，单 IP 仍可占满这些名额（但不再能杀死进程）。

## 证据矩阵

| 入口/组件 | 畸形长度/截断 | 认证/重放 | 资源上限 | 取消/停机 | 主要证据 |
|---|---|---|---|---|---|
| SOCKS5 / HTTP / Mixed | 有 | 有 | 有 | 有 | `tests/integration.rs`、`tests/http_proxy.rs`、`tests/resources.rs` |
| VLESS / Vision / XUDP | 有 | 有 | 有 | 有 | `tests/vless.rs`、`tests/vision.rs`、`tests/xudp.rs`、`src/mux/tests.rs` |
| VMess AEAD / UDP | 有 | 有 | 有 | 有 | `tests/vmess.rs`、`tests/xudp.rs` |
| Trojan / TLS / WS / fallback | 有 | 有 | 有 | 有 | `tests/integration.rs`、`tests/httpupgrade.rs`、`tests/websocket_trojan.rs`、`tests/fallback.rs` |
| Shadowsocks AEAD/2022 | 有 | 有 | 有 | 有 | `tests/shadowsocks_udp_wire.rs`、`tests/shadowsocks_resources.rs`、`tests/shadowsocks_listener.rs` |
| REALITY / REALITY fallback | 有 | 有 | 有 | 有 | `tests/reality_inbound.rs`、`tests/reality_lifecycle.rs`、`tests/reality_boundaries.rs`、`tests/reality_fallback.rs` |
| WebSocket/WSS | 有 | 有 | 有 | 部分半关闭限制 | `tests/websocket_early.rs`、`tests/websocket_eof.rs`、`tests/websocket_alpn.rs` |
| gRPC / HTTP2 | 有 | 有 | 有 | 有 | `tests/grpc_inbound.rs`、`tests/grpc_library.rs` |
| XHTTP / HTTPUpgrade | 有 | 有 | 有 | 有 | `tests/xhttp.rs`、`tests/httpupgrade.rs`、`tests/xhttp_outbound_client.rs` |
| mKCP | 有 | 有 | 有 | 有 | `tests/kcp.rs`、`tests/kcp_outbound_client.rs` |
| Snell v4/v5/v6 | 有 | 有 | 有 | 有 | `tests/snell.rs`、`tests/snell_obfs.rs`、`tests/snell_reuse.rs` |
| Hysteria2 | 有 | 有 | 有 | 有 | `tests/hysteria2.rs` |
| TUIC v5 UDP/TCP | 有 | 有 | 有 | 有 | `tests/tuic.rs`、`tests/tuic_outbound_modern.rs` |
| ShadowTLS v3 | 有 | 有 | 有 | 有 | `tests/shadowtls.rs`、`tests/shadowtls_outbound.rs` |
| AnyTLS / UoT | 有 | 有 | 有 | 有 | `tests/anytls.rs`、`tests/anytls_pool.rs`、`tests/uot.rs` |
| Naive H1/H2/H3 | 有 | 有限 | 有 | 有 | `tests/naive.rs`、`tests/naive_h3.rs`、`tests/naive_outbound.rs` |
| WireGuard server | 有 | 有 | 有 | 有 | `tests/wireguard_server.rs` |
| NW3 Portal/Egress | 有 | 有 | 有 | 有限 | `tests/nw3.rs`、`tests/reverse_bridge.rs` |
| DNS / 路由 / 嗅探 | 有 | 不适用 | 有 | 有 | `tests/dns.rs`、`tests/sniffing.rs` |
| 管理 API | 有（400/401/405/404） | 有 | 有 | 有 | `tests/admin_api.rs` |
| TLS 证书/私钥加载 | 有 | 有（不匹配拒绝） | 不适用 | 有（重载） | `src/tls.rs` 单元测试、`tests/cert_reload.rs` |

“有”表示存在覆盖对应类别的回环测试；不代表已做独立审计、全平台或官方客户端矩阵。

## 明确缺口

1. **私钥/证书/配置文件权限**：`api.token_file` 与 TLS 私钥均已 fail-closed
   （0600，组/其他用户可读时拒绝启动）。**配置文件本身不在此列**：程序无法
   判断任意配置文件是否敏感（可能只含非机密字段），强制 0600 会破坏正常部署；
   该权限由部署层负责，属设计边界而非缺陷。若配置内含 `api.token` 明文或
   内联私钥，应改用 `token_file`/文件路径并确保 0600。
2. **完整握手 fuzz**：当前 fuzz 覆盖配置、Vision、SOCKS5/HTTP 数据报、XUDP、VLESS/
   Trojan/Snell/TUIC 解析、XHTTP/gRPC/VMess header；未覆盖 Shadowsocks AEAD/2022 EIH、
   REALITY、XHTTP 会话、gRPC stream、mKCP、TUIC 状态机、WireGuard、ShadowTLS 的完整
   握手/状态机。
3. **长时间/并发故障注入**：没有 72 小时 soak、网络黑洞、证书过期、磁盘满、管理 API
   不可用等生产故障演练。
4. **平台**：Linux x86_64 原生功能回归已完成（分批，test profile，静态 musl）；
   Windows、macOS x86_64 仍未完成。详见下方平台状态。
5. **独立审计**：没有第三方审计、渗透测试或正式的威胁模型评审结论。

## 平台状态

**Linux x86_64 原生功能回归已完成（分批，test profile，静态 musl）。**
测试产物在 macOS 交叉编译，在 Debian 11 x86_64、内核 `5.10.0-35-cloud-amd64`
的 1 vCPU VPS 上以非 root 身份原生执行。本轮主包 lib 与全部 82 个顶层集成
测试目标都有结果；按套件最终复验去重，**1709 通过、0 失败、91 忽略**。

- 分批执行：同套件以最后一次完整复验结果计入，首轮失败与复验映射保留在
  证据目录。因此「0 失败」指最终逐套件结果，**不是**「一次全量运行零失败」。
- 91 项忽略中有 81 项来自三个需官方对端的套件（`reference_clients` 79、
  `reality_official_outbound` 1、`reverse_official_bridge` 1）；其余 10 项是
  REALITY 系列的 Python cryptography/MLDSA 门禁、`resources` 与 lib 各 1 项。
  这些测试检测到依赖缺失后跳过，**不等于通过，也不算失败**。
- 本轮证据支持**默认功能回归**；官方对端互通与指定 release 工件冒烟另列下方两节。
- Windows、macOS x86_64 状态不变。

### release 工件冒烟（x86_64，单独一节）

> **验收绑定到具体 ELF，不是绑定到资产名。** Debian 11 x86_64 非 root 回环冒烟 7/7，
> 通过对象为静态 musl ELF，SHA-256
> `4641055bb4f9e2c6ddd8ef95cbb2b0fee0968935bac5d3d119492d29558a7e80`。
> 该记录**不覆盖**其他构建目标产生的包。后续发布资产按**包内二进制 SHA** 单独列示
> 验收结果；包内 SHA 不同即需对该 ELF 另行冒烟，不能沿用本条。

对 release profile 构建的静态 musl 工件做非 root 原生冒烟：

| 项 | 值 |
|---|---|
| 构建 | `cargo build --locked --release --target x86_64-unknown-linux-musl` |
| 大小 | 39,367,272 字节，ELF64 x86_64，静态 |
| SHA-256 | `4641055bb4f9e2c6ddd8ef95cbb2b0fee0968935bac5d3d119492d29558a7e80` |
| 执行身份 | `setpriv --reuid=65534`，`id -u` = 65534 |
| 结果 | **7 项全过，退出码 0** |

静态性以 ELF 属性确认，不只看 `file` 输出：`readelf -lW` 无 `PT_INTERP`、
`readelf -dW` 无 `DT_NEEDED`。该判据已用动态链接的 `/bin/ls` 做对照
（`INTERP` 1、`NEEDED` 2），确认具备区分能力，不是恒真判断。

覆盖：`version`、`config check`、启动监听、允许路径转发、出口拒绝生效（SOCKS
应答非 0）、拒绝目标未收到连接、SIGTERM 停机 `exit=0`。

两项断言的强度说明：

- **允许路径**要求目标先实际读到 `ping` 再回 `pong`，否则返回 `bad:<hex>`。
  故该断言同时证明「请求到达目标」与「响应返回客户端」两个方向。
- **拒绝目标**由监听器把结果写入文件，按 `no-connection` / `connection-received`
  / 空（未完成观察）三态判定；只有「观察窗口内 `accept` 超时」算通过。
  空文件与 `listen-failed`、`listener-error` 均判失败。另**单独做过一次放行对照**，
  确认监听器在规则放行时能报出 `connection-received`，以排除恒真断言。

> 早前版本的拒绝目标断言在收到连接与超时两种情况下退出码均为 0，属假通过；
> 已修正。放行对照为一次性验证，不随每次冒烟运行，也未纳入版本库。
>
> 长期作为 CI 门禁仍需加固：监听器目前靠 `sleep 1` 同步、8 秒观察窗独立计时，
> 请求发得过早或过晚都可能得到「SOCKS 非零应答 + 目标超时」。最小加固是让
> 监听器报告 `ready` 后再发请求，并确认拒绝应答在观察窗口结束前收到。

端口释放为单独探测：本次正常停机后**探测到端口可重新绑定**。该脚本为可选诊断，
其耗时数字**不作为验收值**；逐次原始输出见证据目录 `port-release-samples.log`。
早前版本「先发 SIGTERM 再取时、且未确认服务端已监听」，其 34 ms 属无效结果，
已作废。已改为：同一进程在发信号前取单调时间、写配置失败即退出、
并先确认被测进程已监听。本项不升级为发布门槛。

### 发布工作流的构建目标（待 CI 验证）

发布工作流此前用 `cargo build --locked --release`（无 `--target`），在
`ubuntu-24.04` 上产出的是 **glibc 动态链接**二进制，与上节冒烟的静态 musl ELF
**不是同一个工件**；资产名 `linux-x86_64` 会把 7/7 证据错误地转移过去。

已改为按 target 构建，并让打包路径随之变化：

| 资产 | target | 链接方式 |
|---|---|---|
| `linux-x86_64-musl` | `x86_64-unknown-linux-musl` | 静态（ELF 属性检查放行） |
| `linux-aarch64-gnu` | 宿主默认 | GNU 动态；运行基线与验证状态单列 |
| `darwin-arm64` | 宿主默认 | 平台惯用 |

同时新增两项门禁：打包前用 `readelf` 确认 x86_64 工件无 `PT_INTERP` / `DT_NEEDED`；
包内写入 `dubhe.sha256`，使验收结果可绑定到具体 ELF。

> **状态：改动未经 CI 验证。** 本机是 macOS，没有 `musl-gcc`，无法验证
> `musl-tools` 能否编过 `aws-lc-rs`、`ring`、`blake3` 等项目的原生依赖。
> 该链路须以首次干净 CI 构建结果为准；在此之前不得声称 CI 可产出静态 musl 工件。
> 另：`workflow_dispatch` 与 `v*` tag 是两次独立构建，演练包通过不代表 tag 包相同，
> 正式包仍需比对包内 ELF 的 SHA，不同则补验。

### 官方对端互通（x86_64，单独一节）

在同一台 VPS 上用 `--ignored` 显式运行 79 项官方客户端互通测试。三个客户端均为
linux-amd64，上游校验和已核对（mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31）。
运行身份为 root——该套件需 fork 外部客户端进程，nobody 环境下不可用。

| 客户端 | 实际互通通过 | 预期不支持 | 测试失败 | 合计 |
|---|---:|---:|---:|---:|
| Xray v26.10.31 | 20 | 7 | 0 | 27 |
| sing-box v1.14.4 | 23 | 2 | 1 | 26 |
| mihomo v1.19.33 | 8 | 3 | 15 | 26 |
| **合计** | **51** | **12** | **16** | **79** |

「预期不支持」指测试名含 `is_explicitly_skipped`、或 `result.json` 的
`status` 为 `unsupported` 的用例——它们验证「正确识别参考实现缺该能力」，
不等于互通通过。按唯一测试名去重后共 79 项。

sing-box 的唯一失败是 **Naive 在 `valid` 阶段客户端提前退出**，单列。

**16 项失败不能统一归因。** mihomo 的 15 项失败中，主日志明确标出 **3 项 `valid`**
（两项 Shadowsocks 连接重置：SS2022 AES-128-GCM EIH、SS ChaCha20-Poly1305 单用户；
一项 VLESS 裸 TCP 未观察到转发计量）、**7 项负向**（`wrong-uuid` 3、`wrong-password` 2、
`untrusted-certificate` 1、`wrong-identity-psk` 1）；余 **5 项**（ShadowTLS、Trojan、
TUIC、VLESS-WS、VMess）只落在公共 `read_exact` 助手并 `ConnectionReset` panic，
阶段未判明。加上 sing-box Naive 的 `valid` 阶段客户端提前退出，
**两客户端合计明确的正向失败 4 项**。故**不可**把失败整体描述为「负向时序问题」。

已用外部进程独立探测验证产品侧行为正确（仅覆盖所抽查的 VLESS 裸 TCP 与
HTTPUpgrade 错误凭据场景，不能替代正向失败、Naive 或其他协议的复验）：

- 错误凭据确实被拒绝并计入 `rejected`（裸 VLESS 与 httpupgrade 两种承载、
  3 秒与 10 秒两种握手超时、目标端口有监听与无监听，四组组合全部 `0 → 1`）；
- 客户端在 0.02 秒内收到 SOCKS 应答并观察到 EOF 关闭，无悬挂；
- 同一测试在 macOS 上连续通过（13.6–22.0 秒，valid/wrong-uuid/untrusted-certificate
  三阶段全部通过）。

负向场景的失败集中在测试的**进程内 `Running` 环境**且仅于 1 vCPU 上复现，
确切机制未定位；正向（`valid`）阶段的失败尚无任何归因。

本节结论：**x86_64 官方互通以 Xray 与 sing-box 为主证据（43 项实际通过、
sing-box 1 项失败待查）；mihomo 8 项通过、15 项失败，失败阶段混合，不可整体归因。**
不得宣称「mihomo 全部互通通过」；**16 项失败尚不能统一归因为产品缺陷或测试
设施问题**——既不将其算作已确认的产品缺陷，也不将其豁免为测试环境所致。

**互通矩阵状态（对外表述）：** x86_64 官方互通矩阵原轮共 79 项：51 项实际互通通过，
12 项预期不支持，16 项测试失败。失败项保留原始结果；后续已对 mihomo VLESS 裸 TCP
做定向复现，**根因未定位，本轮调查归档（暂停，非结案）**。若将相关组合设为 CI 门禁
或对外声明兼容，须在目标类环境按用例复验，并保留客户端退出原因及服务端观测。

**CI 门槛条件：** 16 项失败保留原始状态、根因未定位，部分负向场景已有外部探测
旁证。设为门禁或对外宣称兼容前，须按测试名区分 `valid`、负向与未判明阶段复验。

#### 后续定向复现（补充，不改变上表）

原轮 mihomo 的 3 项 `valid` 失败包括两项 Shadowsocks 连接重置，以及一项 VLESS 裸 TCP
未满足转发计量断言。后续仅对 VLESS 裸 TCP 重跑 18 次：据归档，3 次在 `valid` 读回显时
连接重置，另 3 次在 `valid` 通过后于负向场景超时。这 6 次失败均未报告正向统计断言失败，
不改变原轮 **3 项正向、7 项负向、5 项阶段未判明**的分类。

补充说明（不改上表）：该用例的 `valid` 读回显失败发生在 SOCKS 已返回成功、测试端已向
本地 SOCKS 流写入载荷之后，`read_exact` 收到 `ConnectionReset`；未确认目标收到载荷，
也未确认哪一端先关闭。负向场景的 3 次失败此前 `valid` 均为 `business=ok`，但仅凭
`deadline has elapsed` 无法区分是 `wait_rejected` 还是同为 20 秒的负向 SOCKS 等待，
需引用完整错误上下文才能判定。

同路径有成功对照：`tcp echo` 4–11 ms、`cleanup` 2–5 ms。`stats wait` 实测约 21 ms，
与一次 20 ms 轮询等待吻合；因成功路径未记录首读值，不能据此还原 `27/0 → 27/27`。

独立进程不复发：release 二进制 + `/stats`，20 次串行请求全部成功、`conn-reset=0`；
批末累计 `uplink=540 downlink=540`。该数为批末累计值，非逐连接快照，也不替代
进程内失败用例的复验；它支持「该 release、该配置、该批请求完成了预期转发与累计计量」，
不构成「产品整体稳定」的证明。

已撤回 5→20 秒的全局超时放宽：整次失败运行约 35 秒，分批样本未显示统一放宽超时
有收益。相同错误签名不足以补判另外 5 项未判明用例的阶段或根因。

**调查状态：暂停归档，根因未定位。** 失败项保留原始结果，既未修复也未获豁免。
若将相关组合设为 CI 门禁、对外声明兼容，或独立进程也出现同类重置，则重开调查；
届时先核对同一连接是否触发 `handshake_timeout_ms=3000`，拿到超时证据再做单变量对照。
保留的测试改动仅为：有界（2 秒）统计轮询、错误消息带首末快照、清理失败不覆盖
首个业务错误。均属测试采样与错误上下文，未改变产品行为。


## 后续测试顺序

1. TLS 私钥/配置文件权限 fail-closed，并补负向测试。
2. 为上述缺口增加内部握手 harness/fuzz；每个入口至少覆盖截断、错误凭据、重放、并发上限。
3. 在 Linux ARM64 做 1–4 小时 soak；x86_64 默认功能回归已完成，指定 release
   工件的非 root 原生冒烟已完成（7/7，见上）；仍缺 WAN、容量与长稳。
4. 把本矩阵与 `docs/fuzzing.md`、官方互通记录一起提交审计。

## 可对外使用的平台状态

> **Linux x86_64 原生默认功能回归已完成。** Debian 11 上分批执行静态 musl 的
> test-profile 工件，覆盖主包 lib 和 82 个集成测试目标；按套件最终复验去重，
> 1709 通过、0 失败、91 忽略。指定静态 musl release 工件（SHA-256
> `4641055b…`）另在目标平台完成非 root 回环冒烟，7/7 通过，含允许路径双向载荷、
> 拒绝应答及目标监听窗口内未收到连接、SIGTERM 正常退出。官方客户端矩阵已执行：
> 51 项实际互通通过、12 项预期不支持、16 项失败待查。

不得延伸至 glibc 工件、WAN、生产容量或长稳；**16 项失败尚不能统一归因为产品缺陷
或测试设施问题**——既不将其算作已确认的产品缺陷，也不将其豁免为测试环境所致。
