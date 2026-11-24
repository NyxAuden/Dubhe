# 构建与运行

已验收的基础组合包含 SOCKS5 CONNECT/UDP ASSOCIATE、Trojan over TCP+TLS 的有效认证 TCP/UDP 转发，以及 Direct/Reject、最小路由。VLESS v0 + 标准 TLS、Shadowsocks AEAD 六方法与两 AES 单层 EIH 已有外部互通证据。Vision、VMess、REALITY、WS/WSS、gRPC、XHTTP/HTTPUpgrade、HTTP/Mixed、Naive、fallback 子集、AnyTLS、UoT、Mux.Cool、Snell、Hysteria2、TUIC、ShadowTLS（含无目标出站 detour）、NW3 Portal/Egress 以及 WireGuard 出站均“已实现待集中验收”；macOS ARM64 当前全量为 1465 项通过、0 失败、42 项忽略；Linux ARM64 上次实测为 1389 项；官方客户端目前完成 sing-box v1.14.4（darwin/arm64）的 ShadowTLS v3 双向、Shadowsocks 2022 EIH 出站、Hysteria2 出站带宽协商、VLESS Vision、Trojan/TLS、Hysteria2（含 salamander/gecko obfs）/TUIC v5/AnyTLS/Snell v4/v6/Naive H2/H3 客户端到本内核入站的 TCP/UDP（部分为 UoT v2），以及 WireGuard endpoint（外层回环、内层 10.66.0.x、服务端 helper 目标改写）到本内核 WireGuard 入站的 TCP/UDP，Xray-core v26.10.31 的 VLESS/TLS、VLESS/WSS、Trojan/TLS、VMess/TLS、VLESS Vision、VLESS/VMess/Trojan REALITY（VLESS 含 Vision flow）、VLESS（single/multi）/VMess/Trojan gRPC/TLS（含 VLESS XUDP UDP）、VLESS/REALITY-over-gRPC、VLESS/XHTTP TLS 四模式（含 XUDP UDP）、VLESS/VMess/Trojan REALITY-over-gRPC/XHTTP、VLESS/HTTPUpgrade TLS（含 XUDP UDP）、mKCP（含 XUDP UDP）、VLESS Encryption（X25519/ML-KEM-768，含官方客户端 `.0rtt` 重连）双向本机互通，Mihomo v1.19.33 的 VLESS/TLS、VLESS Vision、VLESS/WSS、Trojan/TLS、VMess/TLS、Shadowsocks 2022、Hysteria2、TUIC v5、Snell v5、AnyTLS TCP/UDP 客户端及 ShadowTLS v3 插件 TCP 客户端到本内核服务端，以及 Nowhere v3.3.0 的 Vector→本内核 Portal、本内核 `nw3-vector`→官方 Portal 双向 TCP/UDP 与官方 Egress↔本内核 Portal、本内核 `nw3_egress`↔官方 Portal 的 TCP/UDP 交叉组合（morph=1、真实证书 pin）；其余官方客户端、Linux x86_64/Windows 平台、可发布 release 与生产容量/安全审计仍未执行；计数只覆盖当前输入。命令 3 是完整 Mux.Cool，旧 XUDP 结论不推导 TCP Mux。**不要将本版本当作完整 Xray/sing-box/Nowhere 替代品，也不要把旧 release 当作包含新模块。**

## 构建

```sh
cargo build --locked --release
./target/release/dubhe version
```

仓库 `rust-toolchain.toml` 固定 Rust 1.91.0，声明 MSRV 1.91；macOS ARM64 在精确 Rust 1.91.0 上的当前全量为 `cargo test --locked --all-targets` 1465 通过、0 失败、42 忽略，并完成 `cargo build --locked --release --bin dubhe`（版本 `0.1.0`）；Rust 1.95.0 的历史全量为 1383 通过、0 失败、42 忽略。Linux ARM64 已在 Colima（4 CPU / 8 GiB，ARM64）的 `rust:1.91-bookworm` 镜像中完成 `cargo check --locked --all-targets`、全量测试（上次实测 1389 通过、0 失败、42 忽略）与 release 构建（`0.1.0`，33,144,056 字节，SHA-256 `7ec912b1b93e6e8327fc814309c7bb0713f34674b0c4e8d2970b891e108f3405`）。Linux x86_64 的 check 已通过，但 QEMU 下全量测试的 cargo fork/exec 偶发死锁，未能取得可信全量结果，未构建 x86_64 release；Windows 与可发布 release 仍未验收。Shadowsocks与REALITY依赖要求AWS-LC原生工具链（C编译器及其构建依赖）；普通TLS仍局部ring，REALITY局部AWS-LC与精确rustls最小补丁。历史Shadowsocks验收输入已在Linux ARM64用精确Rust1.91.0及1.91.1完成全目标编译检查（含AWS-LC），三平台普通回归见[验收报告](shadowsocks-acceptance.md)；这些历史结果不覆盖新增Vision/VMess/REALITY/WS输入。项目许可证为 GPL-3.0-only（含 vendored Nowhere，原版权头保留）、Cargo `publish=false`；不要未经许可审查对外发布混入的上游代码。

## 检查与启动

```sh
./target/release/dubhe check -c "examples/socks5.json"
./target/release/dubhe run -c "examples/socks5.json"
```

## 生成客户端配置

服务端跑 dubhe，客户端用现成工具。一条命令生成四份可直接导入的配置：

```sh
dubhe export \
  --config /etc/dubhe/config.json \
  --host vpn.example.com \
  --output ./client
```

输出：

| 文件 | 用途 |
|---|---|
| `xray-client.json` | Xray-core 客户端 |
| `sing-box-client.json` | sing-box 客户端 |
| `mihomo-client.json` | Mihomo / Clash.Meta 客户端 |
| `anywhere-ajson.json` | Anywhere 的 AJSON 订阅（整份导入，支持全部协议） |

`--host` 是客户端实际连接的地址；配置里的 `listen` 通常是 `0.0.0.0`，不能直接用。
也可以用 `--to xray` 等只生成一种。

各目标格式的协议覆盖（2026-11 按官方文档 **并用实机加载验证**）：

| 协议 / 承载 | Xray | sing-box | Mihomo | Anywhere |
|---|---|---|---|---|
| VLESS + RAW / REALITY / Vision | ✅ | ✅ | ✅ | ✅ |
| VLESS + WS / gRPC | ✅ | ✅ | ✅ | ✅ |
| VLESS + HTTPUpgrade | ✅ | ✅ | ✅ | ✅ |
| VLESS + XHTTP | ✅ | — | ✅ | ✅ |
| VLESS + mKCP | ✅ᵈ | — | —ᵍ | — |
| VLESS + v2ray-HTTP | —ᵇ | ✅ | ✅ | — |
| VLESS + V2Ray QUIC | —ᶜ | ✅ | — | — |
| VMess（RAW / REALITY / WS / gRPC / HTTP） | ✅ | ✅ | ✅ | — |
| VMess + mKCP / QUIC | ✅ᵈ | 部分 | —ᵍ | — |
| Trojan（RAW / REALITY / WS / gRPC / HTTP） | ✅ | ✅ | ✅ | ✅ |
| Trojan + mKCP / QUIC | ✅ᵈ | 部分 | —ᵍ | — |
| Shadowsocks | ✅ | ✅ | ✅ | ✅ |
| Hysteria2（含 obfs 与带宽） | ✅ᶠ | ✅ | ✅ | ✅ |
| TUIC v5（含拥塞控制） | — | ✅ | ✅ | — |
| AnyTLS | — | ✅ | ✅ | ✅ |
| Snell v4/v5 | — | ✅ | ✅ | — |
| Snell v6 | — | ✅ | —ᵉ | — |
| Naive | — | ✅ | — | — |
| NW3 | — | — | — | ✅ |

ᵃ sing-box 没有 XHTTP 与 mKCP 传输。
ᵇ Xray v26 已移除 HTTP transport（文档仍列 `httpSettings`，实机拒绝）。
ᶜ Xray v26 已移除旧 QUIC transport，官方建议改用 XHTTP/3。
ᵈ 仅当目标是私有地址；Xray 禁止明文 VLESS/Trojan 指向公网。
ᵉ Mihomo v1.19.33 实测拒绝 Snell v6（文档写支持 1-6，与实机不符）。
ᶠ Xray v26.10.31 的 `hysteria` 出站用 `protocol: "hysteria"` +
`settings.version: 2` + `streamSettings.network: "hysteria"` +
`hysteriaSettings`，实测 `Configuration OK`。
ᵍ Mihomo v1.19.33 的 VLESS/VMess/Trojan 出站源码只有 ws/http(h2)/xhttp/grpc
分支，没有 kcp/quic；此前标 ✅ 是按旧版 Clash 文档写的，实测无法加载。

Anywhere 输出是 AJSON 订阅文档（`anywhere: 1`），每个代理带稳定 `id`，
客户端刷新后仍保持选中项；NW3 在 AJSON 里是 `nowhere` 协议，固定 TLS 1.3，
不携带 `security` 字段。

## 用真实内核校验导出结果

导出后可以用官方客户端校验配置能否加载（只检查，不启动代理）：

```sh
python3 -I tools/fetch_reference_clients.py      # 首次：下载固定版本的三个客户端
dubhe export -c config.json --host example.com -o ./client
python3 -I tools/verify_export.py ./client
```

分别调用 `xray run -test`、`sing-box check`、`mihomo -t`，任何一个返回非零即报告失败。
Anywhere 目前没有 macOS 端，只能按 AJSON 规范人工核对。

已用固定版本 Xray 26.10.31、sing-box 1.14.4、Mihomo v1.19.33 实跑验证：
28 个入站（覆盖 VLESS/VMess/Trojan 的全部承载、REALITY、SS、Hysteria2、TUIC、
AnyTLS、Snell、Naive、NW3）在公网与私有地址两种场景下导出，三份配置均通过
各自内核的加载检查。

Xray 输出按 v26 结构生成：

- `settings` 是**扁平**结构（`address`/`port`/`id`），没有旧版的 `vnext`/`servers` 数组。
- VLESS 的 `encryption` 必须显式写 `"none"`，该字段不能留空。
- REALITY 的公钥字段名是 `password`（`publicKey` 是旧名别名）；`fingerprint` 必填。
- 客户端发送 WS `host` 的优先级是 `host` > `headers` > `address`，导出用 `host`。
- Xray 的 REALITY 只能与 RAW/XHTTP/gRPC 组合；WS/HTTPUpgrade 组合会被报告并跳过。

生成规则：

- **每个入口只取第一个用户**；入口有多个用户时会输出提示，不会静默少人。
- Hysteria2 的 `obfs`（salamander/gecko 及 gecko 的分片长度）与 TUIC 的
  `congestion_control` 按各客户端字段拼写分别导出。
- TUIC 的 `alpn` 非空时按 sing-box `tls.alpn`、Mihomo 顶层 `alpn` 导出；
  服务端配置后客户端必须发送其一，不导出会握手失败。
- 目标格式不支持的协议会写进 stderr 报告并跳过，不生成半可用配置。
- VLESS Encryption（`decryption` 非 `none`）的客户端 `encryption` 由服务端配置
  **现场派生**：X25519 私钥 → 公钥是标量乘；ML-KEM-768 种子 → 封装公钥是确定性
  展开。`mode` 与 `padding` 原样保留，`time` 按服务端是否启用票据改写为
  `0rtt`/`1rtt`。四目标（Xray / sing-box / Mihomo / Anywhere）都会写入。
  已用 `xray vlessenc` + `xray x25519 -i` 的官方输出逐字节核对推导结果，
  并用官方 Xray v26.10.31 客户端实连完成双向回显。
- `socks5`/`http`/`mixed`/`dokodemo-door` 是本地或透明入口，`wireguard` 的客户端
  需要客户端自己的私钥，`shadowtls` 需与内层协议组合成两条出站；这六类都会按名字
  报告「不可导出」，不会静默消失。
- REALITY 的客户端公钥由服务端私钥现场派生，不需要手工填：
  `xray x25519 -i "<私钥>"` 是确定性的（同一私钥永远得到同一公钥），
  本项目的派生与之逐字节一致。注意 REALITY 的 `short_ids` 不可推导——
  它是配置里显式列出的一组字节，客户端必须拿到同样的值。
- 导出的配置里带凭据，属于敏感文件；写入时用 0600 权限，不要提交到仓库。

## 从 Xray 配置转换

```sh
./target/release/dubhe convert \
  --from xray \
  --input xray-config.json \
  --output dubhe-config.json \
  --report convert-report.txt
./target/release/dubhe check -c dubhe-config.json
```

支持范围是「入口/出站基本字段 + 静态路由」：VLESS、VMess、Trojan 的
`tcp`/`ws`/`grpc`/`xhttp`/`httpupgrade`/`kcp`/`reality` 组合，Shadowsocks、SOCKS、HTTP，
以及 `freedom`/`blackhole` 出站和 `domain`/`ip`/`port`/`inboundTag`/`network` 路由规则。

行为约定：

- 转换结果会再走一遍本项目校验，**不可能输出无法启动的配置**。
- `geosite:`/`geoip:` 引用会保留在 `domains`/`ip_cidrs` 并提示配置数据文件；
  `ext:` 规则集、`fallback`、`balancerTag`、XHTTP 的 `downloadSettings`、
  `sockopt.dialerProxy` 链式代理、TCP header 伪装、证书固定与客户端证书
  直接报错，不会静默丢弃（完整清单见 `docs/migration.md`）。
- 默认出口跟随 Xray：**配置里第一个出站**。按 tag 名猜 `proxy`/`direct` 会让
  `[{tag:"node"},{tag:"direct"}]` 这样的配置变成默认直连。
- 同一个 `domain` 数组内的 `domain:`/`keyword:`/`regexp:`/`full:` 是并集，
  转换后拆成多条同出站的相邻规则，保持并集语义。
- gRPC 的 `serviceName` 是服务名，客户端实际请求 `/<service>/Tun`；`convert`
  按 Xray 的规则补流名（新式 `/<service>/单流|多流` 只在最后一个 `/` 之后解析），
  `export` 写各客户端能用的形式：Xray / Mihomo / Anywhere 用完整路径，
  sing-box 用 `/<service>/Tun` 里的服务名。双路径服务导出成单流客户端即可用；
  单段路径与含 `%` 的路径按目标报不可导出。
- SOCKS/HTTP 出站的 `streamSettings.security = "tls"` 会保留；
  Shadowsocks 出站不支持 TLS，遇到直接报错而不是降成明文。
- 带 TLS 的出站必须用 `--ca-file` 指定信任锚 PEM；本项目不隐式信任系统根证书。
- 无认证的 SOCKS/HTTP 若监听非回环，转换会失败并提示，而不是替你打开
  `allow_insecure`。


日志级别由环境变量 `DUBHE_LOG` 控制（语法同 `RUST_LOG`），例如
`DUBHE_LOG=debug` 或 `DUBHE_LOG=dubhe=trace,quinn=warn`；未设置时保持 `info`。
`shadowsocks` 目标始终关闭（协议库原生日志可能包含 EIH/身份哈希）。
连接级日志包含对端 IP，但**默认不记录目标地址与载荷**（威胁模型 T14）；
需要目标时打开 `DUBHE_LOG=debug`。

`limits.per_ip_handshakes`（默认 8，`0` 表示不限制）限制**单个源 IP 同时占用的
在途握手数**。它不限制并发连接数：完成握手的连接立即释放名额。没有这一层时，
单个 IP 开满全局 `max_handshakes` 就能让该入口对其他所有 IP 不可用。

示例默认仅监听 `127.0.0.1:1080`。检查模式不绑定端口、不连接代理目标；它会验证配置以及 Trojan 证书/私钥。**端口是否真的可绑定（被其他进程占用）只在 run 阶段验证**；但两个入口之间的监听冲突由 `check` 静态判定并拒绝——同一 `(地址, 端口, TCP/UDP)` 只能有一个入口占用，通配地址（`0.0.0.0` / `::`）与其覆盖范围内的具体地址也算冲突。UDP 与 TCP 不互相冲突（例如 `socks5` + `hysteria2` 可共用端口号），端口 `0` 由内核分配、不参与冲突判定。CLI 的成功退出为 0、配置/运行错误为 1、参数用法错误为 2。

Trojan 使用 `examples/trojan.json` 作为模板，必须替换证书链、私钥的绝对路径及随机密码，再执行 check/run。VLESS 模板为 `examples/vless.json`，用户字段使用 `uuid`，须替换为随机标准 UUID，TLS 路径同样必填；命令 3 与目标 `v1.mux.cool` 进入完整 Mux.Cool（TCP 会话始终允许；UDP New/GlobalID 默认准入，`xudp:false` 可关闭），边界见 [Mux 说明](mux.md)。新增开发实现的Vision模板为 `examples/vless-vision.json`，仅用户级 `flow:"xtls-rprx-vision"` 开启，真正Vision请求要求TLS1.3；尚待官方/三平台集中验收，详见[Vision说明](vision.md)。VMess模板为`examples/vmess.json`（直承载）和`examples/vmess-tls.json`（成对可选TLS），四项扩展/弱化开关均默认false，须替换UUID，TLS模板另替换证书路径；详见[VMess边界及UDP大小公式](vmess.md)。REALITY采用独立`examples/vless-reality.json`及`vless-reality`入口，已实现待集中验收（21/29）；固定自持回环target、两层身份及有限模板边界见[REALITY说明](reality.md)，旧vless不能混入REALITY选项。REALITY 还可作为三协议 gRPC、XHTTP 的安全层：入口内配置 `reality` 后不得再配置 `certificate`/`private_key` 或 `allow_insecure_transport`，XHTTP/3 除外；gRPC 使用 h2。与上游一致，WebSocket/HTTPUpgrade 不组合 REALITY，配置阶段拒绝。WS/WSS另有`vless-ws`/`vmess-ws`/`trojan-ws`及六份独立回环占位模板（如`examples/vless-wss.json`），显式header/path early-data、严格路径/Host及关闭限制见[WebSocket说明](websocket.md)；新入口不会放松旧类型TLS契约。gRPC另有`vless-grpc`/`vmess-grpc`/`trojan-grpc`及六份独立回环占位模板（如`examples/vless-grpc.json`），`grpc.path`必填完整RPC路径，可选`multi_path`；VMess gRPC 必须真实TLS或REALITY，VLESS/Trojan明文须显式`allow_insecure_transport`。single/multiMode消息framing、1MiB上限、半关闭与资源边界见[gRPC说明](grpc.md)。TCP 复用由协议命令 3/`v1.mux.cool` 触发，不提供独立配置开关。仓库不附带生产证书和私钥。模板仅有明确占位值，不可直接作为公网部署配置。测试会用临时证书和凭据替换占位项后验证真实启动与转发。

按 Ctrl+C 或发送 SIGTERM：先停止新连接，最多等待 `shutdown_timeout_ms`，随后取消仍活跃的流，等待 UDP 子任务退出并释放套接字。Unix 下发送 SIGHUP：重新读取同一配置文件并完整校验，校验失败保持旧实例运行。若配置文件内容未变，只重新加载 TCP/TLS 入口的证书与私钥并原子替换，不重启监听：新连接使用新证书，已建立的连接继续使用握手时的证书，不中断业务。若配置内容变化，先尝试零停机热重载：入口、`limits`、API 与 NW3 Egress 均未变化且没有 UDP 监听器时，只原子替换路由、DNS、嗅探与出站配置（含重启 urltest 探测），不重启监听，已建立连接继续使用旧快照，新连接立即使用新配置。需要改监听器/limits、存在反向 portal 或 UDP 入口时，仍按旧流程停止旧实例后重新绑定新配置（含证书与 CA 文件），因此会有短暂停机；新实例绑定失败时重新绑定旧配置。QUIC、mKCP、REALITY 与 ShadowTLS 的证书轮换仍需完整重启。库用户使用 `Server::bind(config)`、`Server::run(CancellationToken)`；通过取消 token 请求有序停止，不能将直接 abort 顶层任务当作同样的停止完成保证。

不会自动修改系统代理、DNS、防火墙或安装系统服务。若主动改成公网监听，应自行配置强凭据、受信任证书、访问控制和主机网络策略。SOCKS5 密码本身不加密；无认证非回环地址默认拒绝，显式 `allow_insecure:true` 才允许，通常不应启用。

## 配置形态

JSON 根对象为 `version:1`、`inbounds`、`outbounds`、`route`，以及可选的 `limits`、`dns`、`api`、`sniffing`、`nw3_egress`、`reverse_bridges`。未知字段、未实现协议/扩展、重复标识、无效引用和不合法资源限制均拒绝，不静默忽略。监听端口 0 允许嵌入库与测试申请临时端口；普通 CLI 使用固定高端口。

路由字段为 `inbounds`、`networks`、`domains`、`domain_suffix`、`domain_keyword`、`domain_regex`、`ip_cidrs`、`ip_is_private`、`ports:[{"start":443,"end":443}]`、`invert` 和 `outbound`。不同字段 AND，同字段多个值 OR，首条命中；必须配置显式默认出站。`domains` 是精确匹配；`domain_suffix` 是后缀匹配（`example.com` 也命中 `a.example.com`）；`domain_keyword` 是子串匹配，`domain_regex` 是 RE2 正则（作用于小写域名，加载期编译，非法正则直接拒绝）。前三者忽略 ASCII 大小写与尾点。`ip_is_private` 匹配非公网地址，集合与 sing-box v1.14.4 的 `!IsPublicAddr` 逐条一致：RFC1918 与 `fc00::/7`、回环、组播、链路本地、IPv6 interface-local 组播、未指定地址；**不含** CGNAT `100.64.0.0/10`。`invert` 翻转整条规则的匹配结果，对应 sing-box `invert`，与 Xray 只否定 IP 条件的 `!` 前缀不等价，转换时对后者明确报告而不做有损映射。`route.domain_strategy` 默认为 `as-is`，CIDR 只匹配原始 IP；设为 `ip-if-non-match` 时，若域名目标没有任何规则命中且存在可能命中的 IP 规则，则先解析域名再重试一次，解析失败按未命中处理并回落到默认出站。

DNS 可用顶层 `dns` 覆盖：`{"servers": ["1.1.1.1", "[2606:4700:4700::1111]:53"], "hosts": {"example.test": ["192.0.2.1"]}}`。省略 `servers` 时沿用系统配置；`hosts` 总是先于远端查询，精确匹配域名。`servers` 还支持加密 DNS：`tls://1.1.1.1:853`（DoT，端口缺省 853）与 `https://1.1.1.1/dns-query`（DoH，端口缺省 443、路径缺省 `/dns-query`）；同一列表不得混用明文与加密服务器，加密服务器的主机必须是 IP 字面量（避免引导解析递归）。DoT/DoH 必须显式提供 `ca_file`，不使用系统根证书；`server_name` 可选，省略时按服务器 IP 校验证书。`dns.rules` 可按域名选择服务器：`{"rules": [{"domain_suffix": ["corp.example"], "servers": ["10.0.0.53"]}]}`，支持 `domains`（精确）、`domain_suffix`、`domain_keyword`，字段间 AND、同字段多值 OR，首条命中后只使用该条目的 `servers`；同一规则可设置 `"race": true`，并发查询该规则的多个服务器并采用首个成功结果（失败服务器不阻塞），未设置时按顺序回退；未命中时使用顶层 `servers`，`hosts` 始终优先。每个 `servers` 列表同样不得混用明文与加密服务器；任一规则使用加密服务器时同样要求 `ca_file`。加密查询缓存按规则分组隔离。解析有并发和超时限制；不承诺完整 NSS/mDNS/企业名称服务。TCP 顺序尝试 DNS 地址，有每地址和总拨号期限，不是 Happy Eyeballs。顶层 `sniffing` 可为流式入站启用 TCP 首包嗅探：在拨号前读取 TLS SNI 或 HTTP/1.1 `Host`，已读字节原样回放。嗅探域名默认只参与路由；仅当协议列入 `dest_override` 且未设置 `route_only` 时才用它拨号。默认期限 300ms，只覆盖 VLESS 明文 TCP、VMess TCP、Trojan TCP、SOCKS5 CONNECT 与 Shadowsocks TCP；UDP 关联另对 QUIC Initial 解出 SNI，但只用于选路、不改写发送目标。UoT 控制帧除外；Vision/REALITY、Mux.Cool 的 TCP 子流、xudp 数据报与 QUIC 合并包同样纳入嗅探，详见[嗅探说明](sniffing.md)。

SOCKS5/Trojan/VLESS/VMess及Shadowsocks2017 UDP每目标映射使用独立connected套接字，仅接受对应目标来源，保留报文边界和回程来源；Shadowsocks2022每会话共用稳定双栈unconnected套接字，使用实际已发送目标allowlist过滤来源。

## 默认资源限制

| 设置 | 默认值 |
|---|---:|
| `max_connections` | 1024 |
| `max_handshakes`（每入口） | 64 |
| `max_grpc_streams`（全局） | 256 |
| `max_grpc_streams_per_connection`（每连接） | 16 |
| `max_xhttp_sessions` | 256 |
| `max_udp_associations`（全局） | 256；**见下方「UDP 代理出站的配额影响」** |
| `max_replay_entries`（Shadowsocks全局精确salt记录） | 65536 |
| `max_vmess_replay_entries`（VMess独立池，两类记录合计；一正常会话两条） | 65536 |
| `max_reality_replay_entries`（REALITY独立精确CH池，同派生静态公钥跨入口共享） | 65536 |
| `max_udp_targets`（每关联） | 64；直连与代理目标合计 |
| `udp_queue_bytes`（全局排队载荷预算） | 262144 |
| `udp_queue_packets`（每队列） | 64 |
| `max_udp_payload` | 65507 |
| `max_dns_queries` | 64 |
| `handshake_timeout_ms` | 10000 |
| `dial_timeout_ms` | 10000 |
| `dial_attempt_timeout_ms` | 2000 |
| `dns_timeout_ms` | 5000 |
| `udp_idle_timeout_ms` | 60000 |
| `idle_timeout_ms`（TCP 中继双向空闲，0 表示不限） | 300000 |
| `shutdown_timeout_ms` | 5000 |
| `stats_interval_ms` | 30000 |

UDP 字节预算约束排队载荷以及Shadowsocks原生入口的排队密文，不代表整个进程内存上限；活动读取缓冲、socket 内核缓冲、TLS 状态及映射还有各自开销。关联/映射上限必须结合实际内存与文件描述符预算配置。普通 UDP 队列满或预算不足丢弃新数据报并计数，不无界堆积。Mux.Cool 入站/出站各使用每连接 256 KiB 字节预算与有界队列；预算不足时背压而非无界缓存。每个 Mux UDP 会话占用一个全局 UDP 名额，目标映射按 `udp_idle_timeout_ms` 清理，但 UDP 会话本身不单独按空闲关闭；KeepAlive 不会延长目标映射。GlobalID 为单个 `Context` 实例内的去重键，后到连接接管时旧会话收到 `End+Error`；热重载后不跨实例续接。整条 Mux 连接连续 60 秒无会话且无帧活动才关闭。详见 [Mux 说明](mux.md)。

### UDP 代理出站的配额影响

支持代理出站的 UDP 入站：SOCKS5、VLESS（含 UoT）、Trojan、dokodemo-door、
Mux.Cool、WireGuard，以及 2026-11-24 补齐的 **Hysteria2、TUIC、Snell、VMess**
（命令 2 与 packetaddr 两种模式）与 **Shadowsocks 2022**。

**Shadowsocks 2017 模式不支持代理出站**：它的回程需要关联自己的加密上下文，
选到代理时 fail-closed 返回 `Unsupported`，不会悄悄直连。链式部署请使用
2022 模式（`2022-blake3-*`）。

每个走代理的目标会额外占用一个 `max_udp_associations` 名额（`RoutedUdp` 内部
申请一个）。因此实际消耗是「UDP 会话数 + 代理目标数」，而不是单纯的会话数：

- 默认 `max_udp_associations=256`、`max_udp_targets=64`；
- 4 个各开 64 个代理目标的会话即可吃满全局名额（4 × 64 = 256）。

直连目标不额外占用。若链式部署下目标数较多，请上调 `max_udp_associations`。

回程地址的语义差异：直连时回程报头用 `recv_from` 得到的**真实源地址**；代理时
拿不到源地址（SOCKS5 只回 payload），只能用**原目标**。当目标域名解析到多个
IP、或上游从不同 IP 回包时，两者会不同。这是 UDP 中继的固有限制。

## 日志与计量

JSON 日志写到 stderr，后台队列最多 1024 条，满时允许丢日志；连接错误每入口最多每秒一条，累计拒绝/丢弃仍在统计中可见。记录入口标签、就绪、活动计数、上下行业务字节和停机强制关闭数量。不记录密码、摘要、私钥、业务载荷，默认不记录目标地址。

计量只计成功写出的业务载荷，代理头/TLS/UDP framing 不计入；不是财务计费系统。

## 当前限制

- 旧 `trojan` 入口支持 fallback 稳定子集；gRPC 使用独立 `trojan-grpc`（明文需显式 `allow_insecure_transport`），WS/WSS 使用独立 `trojan-ws`，均不改变旧 `trojan` 必填 TLS；未配置 fallback 时无效认证直接关闭。WS Close 不提供通用透明 TCP 半关闭，见[传输说明](websocket.md)与[fallback 说明](fallback.md)。
- SOCKS5 支持 BIND：只在控制连接的本机 IP 上监听，接受一次入站连接，请求中的 IP/端口作为期望对端过滤；ShadowTLS 内层 SOCKS5 不支持 BIND。**BIND 是本内核扩展**：Xray/sing-box 的 SOCKS 入站只实现 CONNECT/UDP ASSOCIATE，不提供 BIND。UDP FRAG 仍不支持，分片报文被丢弃。
- 反向 Mux 的 Portal 由 `{"type":"reverse","tag":"portal","domain":"v1.rvs.cool"}` 出站与 VLESS 命令 4 组成；Bridge 由顶层 `reverse_bridges` 引用一个标准 VLESS 出站主动拨入 Portal，普通流量路由到 `reverse` 出站即经隧道转发，见[反向 Mux 说明](reverse.md)。
- 上游代理出站支持 `socks5`（TCP CONNECT + UDP ASSOCIATE）、`http`（TCP CONNECT）、`vless`（可选 `xtls-rprx-vision` flow）、`vmess`（AEAD security 3/4）、`trojan`（必须 TLS 或 REALITY）、`shadowsocks`（AEAD，含 2022）、`anytls`、`hysteria2`、`tuic`、`wireguard`；TCP 可选到上游的 TLS（需显式 `tls.ca_file`）与 VLESS/VMess/Trojan 的 WebSocket/WSS、gRPC（single/multi）、HTTPUpgrade、XHTTP（h1/h2/h3）、mKCP 或 QUIC 包装（`transport`，见[出站说明](outbound.md)）；VMess 支持固定目标原生 UDP（每目标一条命令 2 隧道），VLESS/Trojan/Shadowsocks/VMess/AnyTLS(UoT)/Hysteria2/TUIC 出站支持 UDP；HTTP 的 UDP 失败关闭；WireGuard 出站的 UDP 已支持（固定目标 socket、按 MTU 分片限制，见[出站说明](outbound.md)）。出站组 `selector` 按 `default`/第一项静态选择，`urltest` 周期经成员拨号 `probe` 并按最低延迟与 `tolerance_ms` 切换；`urltest` 只测 TCP 可达性与延迟，UDP 复用同一选择，全部探测失败时保持当前成员。暂无出站 BIND、ACME、TUN、GUI。

可选管理/统计 API：`"api": {"listen": "127.0.0.1:9090", "token": "<至少16字节可见ASCII>"}`，或使用 `"token_file": "/etc/dubhe/api.token"` 从文件读取（文件必须为 0600，权限不安全时启动失败；token 与 token_file 二选一）。监听必须是回环地址，所有请求必须携带 `Authorization: Bearer <token>`；提供 `GET /healthz`、`GET /stats`（`telemetry::Snapshot` JSON）、`GET /stats/users`（按入口与用户的累计上下行字节）、`GET /metrics`（Prometheus 文本格式：活动连接/TCP/UDP/gRPC/XHTTP、上下行业务字节、丢弃与拒绝计数）、`GET /connections`（活动 TCP 连接列表：`id`/`inbound`/`outbound`/`network`/`host`/`port`/`started_ms`/`upload`/`download`，字节数为成功读写的业务载荷）、`DELETE /connections/{id}` 与 `DELETE /connections`（关闭单条/全部，返回 204）。连接在建立上游成功时登记，`Upstream` 丢弃时自动移除；只覆盖 TCP，不含 UDP 关联与 urltest 探测。列表包含目标地址，因此 API 只能回环监听并保持 token 机密。每个请求后关闭连接，不支持请求体与 HTTP/2，token 不写入日志；token 文件修改后需要重启进程。

`/stats/users` 的归因范围。

**先说结论：这个接口目前不能作为计费账本。** 下列清单里有几处已知不一致
（2026-11-24 由独立审查实测），计费场景请先在目标协议上验证。

可靠归因（实测等值：传 N 字节，用户计数即 N）：

- TCP 单流：SOCKS5 CONNECT、HTTP/Mixed、Naive H1/H2/H3、VLESS（含 Vision）、
  VMess、Trojan、Shadowsocks、Snell、AnyTLS、TUIC、Hysteria2
- Mux.Cool：**仅 VLESS 命令 3 的 TCP 子流**
- UDP：SOCKS5、VLESS、Trojan、UoT、Snell、Shadowsocks（仅 EIH 多用户会话）、
  Hysteria2 原生 DATAGRAM、TUIC 原生 DATAGRAM

已知不一致（**不要据此计费**）：

| 路径 | 现象 |
|---|---|
| VLESS 命令 3 的 **UDP** 子流 | 业务 5 字节，用户只记下行 0/5（漏上行） |
| VLESS 命令 1 `v1.mux.cool` | 外层承载与子流各计一次（5 字节记成 26/20） |
| VLESS 命令 3 + 入口嗅探 | 嗅探回放的首包只进全局数，用户记 0/5 |
| **反向 Mux**（`reverse_bridges` / Portal） | 全局计数正确，但**不产生按用户条目** |
| VMess + Mux | 静态核对发现同样先包装外层再交子流，未做线测 |

**未归因**：WireGuard（只有 peer 公钥，没有用户名）、Shadowsocks 单密钥
（没有用户身份）。这些路径只进全局计数。

### 用户计数的清零与配额

| 端点 | 作用 |
|---|---|
| `GET /stats/users` | 每个条目含 `uplink` / `downlink` / `since_ms` / `quota_bytes` / `expires_at_ms` |
| `POST /stats/users/reset` | 清零计数并把 `since_ms` 移到当前时刻；`?inbound=` / `?user=` 可缩小范围 |
| `POST /stats/users/limits` | 设置软配额与到期：`?quota_bytes=` / `?expires_at_ms=`（unix 毫秒） |

**配额准入**：

- `quota_bytes` / `expires_at_ms` 是**准入控制**：配额用尽或到期后拒绝该账户的
  **新连接**（返回 `PermissionDenied`），**不断开已建立的连接**。这与
  Xray/sing-box 把处置权留给面板的做法一致。
- 检查点在每个已认证业务的入口（`Stats::admit_counter` / `admit_user`），覆盖
  VLESS/Trojan/VMess/SOCKS5/HTTP/Mixed、AnyTLS、Hysteria2、TUIC、Sniff-TLS、
  Shadowsocks、Mux 子流。未认证路径和没有用户名的路径（WireGuard、单密钥
  Shadowsocks）不参与准入。
- 限额只对**已经出现过的用户**建条目；`POST /stats/users/limits` 在显式给出
  `inbound` 与 `user` 时会先建条目，因此在用户首次连接前设置限额仍然生效。
  只给 `user=` 或只给 `inbound=` 时只更新已存在的匹配条目。
- 计数不持久化，重启归零；配额与到期时间同样不持久化，重启后清空。生产环境
  应由面板在启动/重载后重新下发。
- 清零与并发累加之间有极小竞态（`store` 与 `fetch_add` 之间到达的字节可能
  丢失），与 Xray `StatsService` 的语义一致：重置是运维动作，不追求逐字节精确。
- 计数不持久化，重启归零。

此前所有带查询串的管理请求都会被 `parse()` 里的 `path.contains('?')` 直接
拒绝并返回 400；该限制已移除，现按「不含查询串的路径」路由。

- 真实外部客户端矩阵目前只覆盖报告指定的 macOS ARM64 构建；Linux 测试不自动等同所有 Linux 客户端已验证。
- Linux x86_64在ARM64 Colima中经QEMU运行，本批209项普通回归及vendor25项通过；AWS-LC构建使用编译器局部QEMU虚拟地址预留，有编译器家族探测及memcmp检查跳过警告，具体环境/原始证据见[验收报告](shadowsocks-acceptance.md)。不表示默认QEMU环境已修复，也不能拿其耗时作为原生x86_64性能结果。
- 三平台历史口径为 **macOS ARM64、Linux ARM64、Linux x86_64（QEMU）**，不含 Windows。2026-11-13 已按用户要求新建 Colima default 实例（2 CPU / 8 GiB / 30 GiB 稀疏磁盘，不切全局 Docker context），用固定 Rust 1.95 多架构镜像完成 Linux ARM64 check、全量与 release；Linux x86_64 的 check 通过，但 QEMU 下 cargo 的 fork/exec 偶发死锁，未能取得可信全量结果，x86_64 release 未完成。Windows 没有 target/工具链。Linux 结果不能自动外推到 Windows 或其他 libc/架构。

## 测试

```sh
# 首次使用固定工具链时安装组件：
rustup component add rustfmt clippy
cargo fmt --check
# 本项目代码零警告；vendor/ 内固定版本的上游源码不在门禁范围内。
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
# 需要已下载校验的官方客户端及回环运行授权：
cargo test --locked --test reference_clients -- --ignored --nocapture --test-threads=1
```

普通测试需要可执行的系统 `curl`，缺失会明确失败；当前 macOS 使用 PATH 中的 Homebrew curl，Linux 使用固定容器内的 curl。普通测试刻意忽略33项外部客户端测试（24项Shadowsocks及Trojan、基础VLESS、VLESS XUDP各三项），ignored不计通过。本批已另行显式执行完整33项并全部通过，87个场景及构建/平台范围见[验收报告](shadowsocks-acceptance.md)。其manifest路径可用`REFERENCE_CLIENTS_MANIFEST`指定。测试凭据、私钥、客户端配置保存在 gitignored 的 `.test-artifacts/`，不要对外发布整个目录。

Linux debug 构建下，`runtime::reality_tests::blocked_reality_udp_dns_bounds_queue_bytes_packets_and_force_joins_children` 的 Vision/REALITY 场景单次 poll 超过测试线程默认 2 MiB 栈；该测试现使用独立 8 MiB 测试线程并在注释中保留复现说明。生产代码未改，这不表示默认 2 MiB 测试线程可通过。Linux x86_64 全量另受 QEMU 下 cargo fork/exec 偶发死锁影响，未能取得可信结果。
