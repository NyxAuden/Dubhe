# VMess AEAD 服务端：已实现，待集中验收

状态日期：2026-11-10。当前源码提供原生 Rust VMess AEAD 认证、TCP/可选标准 TLS、原生 UDP、命令 3 Mux.Cool（TCP + `xudp` 门控 UDP）和 packetaddr。独立密码金样及本机受控回环属于开发证据，**还不是 Mihomo/sing-box/Xray 官方客户端互通、三平台全量或新 release 验收**。不能用既有 Shadowsocks 构建的209/33结果覆盖本批。开发命令与输入摘要见 [开发记录](vmess-development.md)，依赖见 [门禁](vmess-dependency-gate.md)。

## 配置和运行

直承载模板为 `examples/vmess.json`，标准 TLS 模板为 `examples/vmess-tls.json`。先替换随机标准 UUID；TLS 另须替换证书链/私钥绝对路径。模板不含可用凭据，不可原样公网部署。

```sh
cargo build --locked
./target/debug/dubhe check -c "examples/vmess.json"
./target/debug/dubhe run -c "examples/vmess.json"
# TLS 模板替换完成后：
./target/debug/dubhe check -c "examples/vmess-tls.json"
```

这些命令用于重新构建当前源码。磁盘上旧 `target/release/dubhe` 不包含本批 VMess，不可拿旧二进制识别新字段的结果当当前实现结果。

入口字段为 `type:"vmess"`、`tag`、`listen`、`users:[{"name":"…","uuid":"…"}]`。每入口1..1024用户，用户名和解析后的UUID分别唯一；UUID大小写不产生新身份。可选 `certificate` 与 `private_key` 必须同时提供；显式null、空路径、半组均拒绝，check会验证证书/私钥但不监听或拨号。旧 Trojan/VLESS 的必填 TLS 语义不变。未知字段拒绝，不接受 `flow`、`alterId/alter_id` 等配置导入别名。

四个开关均默认 false：

| 开关 | 含义 |
|---|---|
| `xudp` | 门控命令 3 Mux 内的 UDP New/GlobalID；命令 3 的 TCP 会话始终允许，外层无目标地址 |
| `packetaddr` | 将cmd2精确控制域 `sp.packet-addr.v2fly.arpa` 解释为逐包IP目标 |
| `allow_insecure_body` | 显式准许无TLS承载上的security5明文正文；不建议开启 |
| `allow_authenticated_length` | 显式准许实验性认证长度；见下文跨方向nonce局限 |

## 认证、正文和客户端默认差异

只支持当前 AEAD 请求头认证；排除legacy认证、非零alterId和历史AES-CFB正文。wire security3为AES128-GCM、4为ChaCha20-Poly1305、5为无正文加密；请求头在三者中都仍然AEAD认证。无正文加密不等于legacy头认证，也不等于TLS。

- 3/4始终使用认证分块；C(0x01)可0/1，普通options允许0/1/4/5/12/13；P(0x08)必须同时有M(0x04)。未知位、连接复用位0x02拒绝。
- A(0x10)默认拒绝；显式允许后增加16/17/20/21/28/29。18字节认证长度与正文认证独立。
- 5在**实际完成标准TLS握手**后可用，直承载默认拒绝。TCP与Mux正文options0为裸流、1为普通u16分块；cmd2只允许1。M/P/A拒绝，不静默忽略。
- 固定源码显示Xray默认3/4+0x0d，sing-vmess普通默认0x05；sing-box TLS+auto可选择wire5（TCP options0、原生UDP options1）。这是源码事实和开发测试目标，尚非官方客户端实跑结论。Xray当前配置名none/zero不能据此推断wire5；Mihomo矩阵应显式选cipher。
- **wire security 5 不是 Xray v26.10.31 上游能力**：固定版本的配置层把 none/zero 归一为 auto，正文编解码只接受 3/4。本仓库接受 5 属于为 sing-box/显式客户端保留的扩展，不能用于声称与固定 Xray 服务端/客户端互通 security 5。
- TCP半关闭后仍可接收反向业务，server-first不依赖客户端先发正文。完整空认证块先验证tag再终止；边界传输EOF允许，半帧、坏tag和TLS截断错误不会变成成功EOF。

### 必须保留的安全边界

**authenticated-length双向沿用request key/IV，确实跨方向复用长度key/nonce。** 本实现按固定wire兼容，但默认关闭，不能宣称“全连接nonce唯一”。不会擅自添加方向域或偏移以假装兼容。普通默认0x05/0x0d不依赖此扩展。

正文nonce含16位计数；每方向最多65536次认证操作，不回绕。服务端发送最多65535个业务块，预留最后一次给认证终止块；额度耗尽关闭，需要重连。默认TCP写块上限16KiB，不代表接收上限；不能把这项安全约束解释为无限流量长连接保证。

后置随机padding不在正文AEAD标签覆盖中；篡改padding字节不一定被拒绝。业务明文只在其正文tag成功后交付。

## 三种 UDP 编码

1. **原生cmd2**：固定请求目标，一个解密chunk恰一数据报，不插入VLESS数据报长度、不跨块拆并。空chunk是终止，不能表达空UDP业务。
2. **packetaddr**：只在显式开启后接受精确保留控制域。每chunk为 `01|IPv4[4]|portBE16|payload`（7字节头）或 `02|IPv6[16]|portBE16|payload`（19字节头），没有域名类型。回程编码真实来源IP；完整地址头可携带空业务。短头/未知类型/端口0拒绝，不从下一chunk补头。关闭开关仍拦截保留域，绝不普通DNS解析；真实逐包目标走路由。
3. **Mux.Cool/cmd3**：正文作为字节流直接接完整 Mux，不发送 VLESS 的 `00 00`；命令 3 的 TCP 与 UDP 会话都可使用。UDP New/GlobalID 默认准入，`xudp:false` 时该会话收到 `End+Error`，承载保持。多会话/逐包目标/End/Keep/KeepAlive 按 Mux 语义处理；GlobalID 为进程级去重，后到连接接管时旧会话收到 `End+Error`，最后一个会话结束后保留 1 分钟供跨承载续接。零长度 UDP 边界保留，空载荷按 0 字节计量。详见 [Mux 说明](mux.md)。

### 数据报大小不是统一65507

原生和packetaddr每个chunk不可拆分。设padding为p（0..63，无P时0），packetaddr头h为7或19，原生h=0，配置业务上限为L（默认65507）：

| 模式 | 单包业务最大值 |
|---|---|
| 3/4普通长度 | `min(L, 65535 - 16 - p - h)` |
| 3/4认证长度 | `min(L, 65535 - p - h)`；正文密文可达65551字节 |
| 5普通长度 | `min(L, 65535 - h)`，不允许padding |

达到配置上限不保证能装进当前wire块。回程超出单块上限会丢弃并计drop，不拆包或改变序列；所有模式同时受实际IP/UDP栈上限约束。Mux 另有自身会话地址/帧及公共 payload 上限，走字节流可跨 VMess 块，不能套用上述单 chunk 数据报公式；Mux UDP 会话本身不按 `udp_idle_timeout_ms` 单独关闭，只有目标映射过期。

## 重放、资源和计量

`limits.max_vmess_replay_entries`默认65536，范围1..1048576；不改变Shadowsocks的`max_replay_entries`。同一Server实例内各VMess入口共享池；正常请求占AuthID、正文key/IV两条，因此不是65536个完整会话。key使用原始UUID，不能换入口绕过。候选有效后立刻提交AuthID，后续失败/取消不撤销；完整头验证后再提交会话材料；满额拒绝、不驱逐有效项。

接受非负±120秒时间窗；保护期241秒，保存完整亚秒锚点并结合单调时间避免回退重开窗口。系统时间严重错误可能拒绝正常客户端。重放池仅内存且有限窗口，不承诺跨进程、跨重启或永久历史防复用。

复用共享TCP连接、每入口握手、全局UDP关联/排队字节、每队列包数、目标/DNS限额及有期限停机。公共UDP关联新建目标socket时复用已有缓冲准备逻辑，使macOS默认9216字节发送缓冲不再拒绝合法大包；只调整本进程自持socket、不改系统参数、不缩小已有缓冲。UDP独立tracked reader避免select取消吞半帧；force后join并等待children实际退出。TCP在业务写接口成功`Ok(n)`处、UDP在实际业务发送/接受处计量，不含头/AEAD/padding/地址封装，也不代表远端收讫或财务计费保证。尚无新增用户级计费系统。

## 当前不包含

WS/gRPC/XHTTP、REALITY、历史废弃模式、各家配置/订阅格式导入。VMess 出站已实现 AEAD TCP（命令 1）与固定目标原生 UDP（命令 2）；出站 packetaddr/xudp 模式未实现。命令 3 的完整 Mux（TCP + `xudp` 门控的 UDP）已接入但属“已实现待集中验收”，相关测试本批未运行，不能由本文件的开发测试推导官方兼容。后续协议和传输按独立变更连续开发，不因本模块完成开发就宣称整体内核目标完成。完整官方/三平台/MSRV/release为本变更第6–8组待验收任务，不自动运行或沿用旧权限。
