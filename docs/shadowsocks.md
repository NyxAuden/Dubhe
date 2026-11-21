# Shadowsocks

出站 UoT：`shadowsocks` 出站支持 `"udp_over_tcp": true`，在单条 Shadowsocks TCP 隧道上以 UoT v2 帧承载逐包目标；服务端同实现支持该魔数目标。本机回环通过。服务端只终止单层 EIH；出站可按 `iPSK:uPSK` 链连接上游；插件仍未实现。
 原生入口

本内核在同一进程中提供服务端TCP/UDP，不启动shadowsocks/Xray/sing-box外部内核。**六种单密钥方法及两种AES单层EIH模式，已通过 Mihomo v1.19.33、sing-box v1.14.4、Xray v26.10.31 的macOS ARM64官方构建互通，共24项、60个场景。** 结论仅限记录的版本、方法、身份模式和原生TCP/UDP组合，不扩大为客户端全部能力兼容。完整矩阵与当前平台状态见 [验收报告](shadowsocks-acceptance.md)，依赖维护见 [依赖门禁](shadowsocks-dependency-gate.md)。

## 算法与身份

| method | password | users |
|---|---|---|
| `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305` | 非空共享密码，经成熟库标准KDF派生 | 不接受 |
| `2022-blake3-aes-128-gcm` | 标准Base64编码的16字节随机PSK | 可选非空单层EIH用户 |
| `2022-blake3-aes-256-gcm` | 标准Base64编码的32字节随机PSK | 可选非空单层EIH用户 |
| `2022-blake3-chacha20-poly1305` | 标准Base64编码的32字节随机PSK | 不接受 |

2022仅接受规范标准Base64形式（含所需padding），不接受原始字符串回退、URL-safe形式、PSK链、截短或自动哈希纠正。AES EIH入口password为iPSK，users每项password为uPSK；同算法长度必须匹配，各PSK互异且用户名唯一。对应客户端使用单层 `iPSK:uPSK`，本内核服务端配置仍分字段保存，不能把链放入顶层password。

2017每入口只有一个共享密码，不依次尝试多个密码。当前不支持插件、TCP mux、多级EIH服务端终止、ChaCha EIH、旧流密码、额外算法或Shadowsocks代理出站；UoT 在出站与入站均已接入。未知字段明确报错。本批不需要TLS证书，不能据此认为TCP握手未认证。

## 示例与启动

模板：

- `examples/shadowsocks-2017.json`
- `examples/shadowsocks-2022.json`
- `examples/shadowsocks-eih.json`

**先替换所有 `REPLACE_WITH_...` 占位符**，再检查。2017占位字符串在类型上仍是非空密码，check无法判断其是否足够随机；不要原样使用。2022占位符故意不是有效PSK，替换前check失败。

可用本机密码学随机源生成凭据，例如：

```sh
# AES128 PSK：16字节；2017也应使用足够长的随机密码。
openssl rand -base64 16
# AES256/ChaCha2022 PSK；EIH的iPSK和每个uPSK分别独立生成。
openssl rand -base64 32
cargo build --locked --release
./target/release/dubhe check -c "examples/shadowsocks-2022.json"
./target/release/dubhe run -c "examples/shadowsocks-2022.json"
```

默认回环 `127.0.0.1:8388`。每入口在同地址同端口联合绑定TCP和UDP；端口0也共用同一实际端口。UDP冲突或后续任何入口准备失败时整体失败，不输出ready，前序资源释放。check只做静态配置/密钥准备，不探测双栈或绑定端口。2022在bind阶段要求可创建 `IPV6_V6ONLY=false` 的稳定双栈UDP出站socket；不支持时明确失败，2017不附加此要求。

## TCP行为

2017地址可跨认证chunk，明文块最多16383字节；2022最多65535字节，验证方向、时间偏差不超过30秒、变量头和padding。2022请求padding上限900字节，变量头含完整padding必须位于首认证chunk，零padding且空首载荷拒绝。响应绑定原请求salt，正常业务保留双向半关闭。

2022沿用SIP022的一次初始read要求：初始salt/可选EIH/固定头短读立即拒绝，不由适配器预读或补齐。失败、超时和取消在握手阶段采用zero-linger关闭；成功后恢复正常半关闭。客户端必须按规范合并首写，网络异常分段可能导致拒绝，不为提高通过率静默放宽协议。

## UDP会话与长度

- 2017按入口/客户端源端点隔离关联，每目标connected socket，只接收目标来源。
- 2022按入口/认证身份/client SID隔离，每会话一个双栈socket，跨IPv4/IPv6目标保持源端口；仅接受实际成功发送过的目标来源，目标数有界。
- 2022完整认证和窗口验证后才更新最新客户端端点；乱序新包可接受，重复及8192位窗口外的包拒绝。排队回程在真正发送时选择最新端点，不保存旧客户端地址。
- 所有方法统一采用 **65507字节密文上限**，包含地址、salt/nonce、EIH、padding和tag。`max_udp_payload`限制业务明文，不能当作最大可发送的业务长度；实际可用载荷必须减去相应协议开销。接收检查实际长度与MSG_TRUNC，回程加密后再次检查。SS自持监听及出站socket准备至少65507字节收发缓冲，以免macOS默认发送缓冲拒绝合法大报文；这只改变自持socket，不修改系统网络参数。
- 例如IPv4目标、不含UDP padding：2017请求开销为salt长度+7字节地址+16字节tag；2022 AES单用户请求开销50字节，AES EIH再加16字节，ChaCha2022再加24字节nonce。2022回程还绑定8字节client SID，且小载荷可能有随机padding，应以实际编码总长为准。
- 空业务UDP载荷允许，计量为0，不等同于空密文数据报。

## 重放、容量与停机

所有Shadowsocks入口共享有界精确salt池，`limits.max_replay_entries`默认65536、允许1..=1048576。入口/用户身份域隔离，2017收发及TCP/UDP在同域共享 **120秒** 窗口，2022 TCP入站salt保存 **60秒**。不是永久唯一保证：有限内存不可能永久记住全部salt。池满时拒绝，包括无法登记的2017回程；不提前驱逐有效保护或关闭检查。

2022 UDP使用独立server SID和单调packet ID，计数不回绕；会话至少保留 `max(udp_idle_timeout_ms,60000)`。局部关闭或发送计数耗尽后可释放转发socket，但保护记录及关联名额保留至保护期结束，不能马上用同SID新建窗口。

TCP共享全局连接许可和每入口握手许可；UDP共享全局关联/字节预算，入口密文及回程队列有界。每入口固定接收/顺序分派任务，不按未经认证包创建任务或SID持久缓存；顺序分派有受期限约束的队首阻塞取舍。字节预算不是总RSS上限，固定缓冲、密码对象、socket及目标索引另有开销。

停机按统一stop→有限排空→force→join/children等待，不在线删除保护状态来恢复容量。业务字节只计成功发送的明文，不计salt、EIH、地址、padding或tag；丢弃与拒绝有独立计数。

## 构建、日志和已知验收缺口

项目声明Rust1.91，当前普通回归使用1.95；Linux ARM64已实际通过精确Rust1.91.0与1.91.1全目标编译检查，包含AWS-LC原生构建，不等于MSRV全部运行测试。macOS ARM64、Linux ARM64及Linux x86_64（QEMU）普通回归各209项、vendor各25项通过；x86_64依赖编译器局部QEMU虚拟地址预留且有探测警告，不是无警告构建或原生性能证明，详见[验收记录](shadowsocks-acceptance.md)。AEAD功能新增AWS-LC及C/汇编原生构建成本，TLS仍为rustls/ring。本地MIT补丁保留来源、许可及可复现diff；密码学原语仍由成熟库提供，项目许可证未确定，不自动发布。

CLI过滤依赖库可能包含身份材料的原生日志，保留内核脱敏事件。嵌入lib的调用者若自建tracing subscriber，必须自行过滤相同依赖target，不可打印密钥、身份哈希或派生材料。

独立wire、本地功能与生命周期测试并不替代官方客户端。本批24组方法/身份模式及同一新构建旧九项已在完整显式矩阵中全部通过，共87个场景；正向包含二进制首载荷与原生UDP两目标三报文，负向核对内核拒绝/丢弃、零目标流量和零明文计量。当前平台结果与失败历史见[验收报告](shadowsocks-acceptance.md)，不将指定版本组合扩大为全部能力兼容。私有`.test-artifacts/`可能含测试凭据/私钥，禁止整体公开。
