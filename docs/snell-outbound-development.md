# Snell 正式出站对齐记录（2026-11-11）

变更：`align-snell-outbound`。本批能力单元为TCP记录承载上的TCP/UDP-over-stream出站，不包含QUIC、HTTP/TLS obfs或顺序连接池。不新增依赖，不修改vendor或密码原语。

## 固定上游

基线：`github.com/sagernet/sing-snell@v0.0.0-20260904135315-bc5a12ac736f`、sing-box v1.14.4。只读核查，不编译/运行上游。

| 文件 | SHA256 |
|---|---|
| `snellv4/client.go` | `f61e960d13881bd47653070b0d15495dd5c1747006e8138c1ecbec279b95d616` |
| `snellv6/client.go` | `2c40c0d1b5a04f266fe7ac77f95588d802519d985c3d2841f388a257b26bcc6c` |
| `snellv6/packet.go` | `6071286a1889cbca2785ecff143b0ac964e58892bba994637e63deb374107708` |

关键语义：

- TCP客户端不启用复用也发送 `CONNECT_V2 (5)`，client id为userkey，目标为长度前缀主机字符串及大端端口；IPv6字符串不加方括号。
- 服务端TCP `writeResponse(payload)` 可在收到目标首次下行后才发送 `ReplyTunnel + payload`。客户端必须允许先写业务、第一次读取再核应答，不能在connect时强制等待而让HTTP请求死锁。根SOCKS成功应答只说明承载请求已接受，不等于远端已认证/目标已收到。
- UDP命令6的正式客户端先校验隧道Reply，再按单记录收发数据报；v6首UDP包不得与请求同帧。
- UDP请求为 `1 + address + payload`；IP地址含前导0和地址族4/6，域名为非零长度前缀。回包来源为IP地址族4/6，不带前导0；空payload仍有地址头，不能当EOF。
- v4/v5单记录上限0x3fff；v6为0xffff。超限不截断、不私自分片。

## 实施

- 严格 `type:snell` + `snell:{psk,version,userkey?,mode?}`；PSK与userkey统一Secret脱敏。v6 PSK 12..255字节，v4/v5 1..4096；userkey可省略，显式值1..255；mode只允许v6 default/unshaped/unsafe-raw。
- 不混用根username/password、TLS、REALITY、任意transport或其他协议参数。未实现的obfs/quic/reuse字段明确拒绝。
- 复用现有Reader/Writer及成熟Argon2id/AES-GCM，客户端逻辑位于Snell子模块，不复制密码处理。
- TCP拥有读写future，首应答salt/头、记录读写游标跨Pending/取消保存；每次只接受有界记录，flush与FIN有实际完成语义，零块只发送一次，读方向继续排空。首请求通过既有单记录编码保持完整，避免较长userkey+主机名被shaped流chunk切开而无法认证；使用同一正式记录格式，不发明新的字段或扩展。
- UDP复用根Association逐目标worker，队列、目标、字节预算与空包约束沿用；固定IP/端口过滤错误来源，域名按单独会话和端口限定。写开始后取消使该会话不可复用，不在半帧后补FIN。
- v6 unshaped/raw及服务端UDP容量纠正为正式u16上限；raw读的header/payload保存在实例中，修复select取消后丢半帧。
- TCP可在SOCKS5链前/后；UDP经via仍失败关闭，不回落direct。无新独立后台线程或脱离所有者的任务。

## 验证状态与真实失败

本机macOS ARM64、Rust/Cargo 1.95.0；只用回环/内存测试。

- 首次集中全目标check发现独立raw对端测试的固定数组长度与字面字符串不符，编译失败；改为由字面量 `.len()` 推导。该失败不是测试通过，不隐去。
- 首轮定向：旧Snell 20项通过，新出站6项通过/2项失败。链式SOCKS5在读应答前未flush，使缓冲Snell承载中的握手未实际写出；为SOCKS5协商、认证与请求添加flush。大包回程的SOCKS5 UDP关联socket缺少本地缓冲准备，补逐socket准备，不改系统参数、不降低协议容量。修复后原有20项、新出站8项、客户端4项均通过；继续补边界后新出站为9项通过，`cargo test --lib snell` 为20项通过（含6项客户端、1项根预算测试及13项既有codec/配置测试），退出0。
- 新增边界验证：长userkey+域名首请求完整单记录、65535字节v6 unshaped/raw单记录、损坏AEAD应答零下行、4字节预算与1包队列、取消写后不复用/不追加FIN。最终集中检查已完成：
  - `cargo fmt --all -- --check`：退出0。
  - `CARGO_INCREMENTAL=0 cargo check --locked --offline --all-targets`：退出0；仍有既有unused/dead-code等警告，不声称零警告。
  - `CARGO_INCREMENTAL=0 cargo test --locked --offline`：**1224 passed、0 failed、43 ignored**，72个结果块，退出0；未设置全局 `RUST_MIN_STACK`。日志：本机 `/tmp/rpk-snell-outbound-validation.vo0G9H`。相较前批1208新增16项（6客户端、1根预算、9集成）。
- 构建统一 `CARGO_INCREMENTAL=0`。检查完成后仅清理本项目`target/debug/deps/*.rcgu.o`，1096个、逻辑5.62GiB，最终可用约38GiB；保留源码/vendor/库与测试二进制/证据/私钥，不碰系统缓存或容器。

官方Snell/Surge/sing-box客户端、三平台、精确MSRV、release、正式容量/安全验收未执行。本机双方互测与独立raw对端不等同官方兼容。不Git/归档/发布，不修改系统代理/DNS/路由/防火墙。
