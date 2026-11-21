## Context

固定上游 `sing-shadowtls@v0.2.2-0.20260928201441-a9c0127d5c99` 的 v3 客户端是
无业务目标的 TCP 连接器：真实 TLS 到 ShadowTLS 服务器，inner 记录由下游代理
协议自己写入；它没有 UDP。项目已有 v3 服务端记录层与 aws-lc HMAC-SHA1，
rustls 已有 `BuildsSessionId` SID hook，但该 hook 当前拒绝 HRR/ECH/early data。
用户已确认采用独立 `shadowtls` detour，并批准最小 rustls HRR 扩展。

## Goals / Non-Goals

**Goals:**

- 移植 v3 客户端记录层、SID、握手期 XOR/HMAC、双向链和首 ServerHello/HRR seed。
- 以真实标准 TLS 连接，支持显式 CA/SNI；HRR 对等；内层流可被现有 `via` 链使用。
- 终端/UDP/非法链失败关闭；测试真实 SS-over-ShadowTLS 回环与资源回收。

**Non-Goals:**

- 不实现 UDP、ECH、TLS1.3 early data、TLS1.2 会话恢复、ShadowTLS v1/v2 或自研密码原语。
- 不改变 ShadowTLS 服务端、其它出站或现有 `via` 链的正常语义；不做官方客户端/平台/MSRV/release 验收。

## Decisions

1. 新增 `OutboundKind::ShadowTls`，配置 `endpoint`、`password`（1–4096 字节）、
   `tls`（显式 `ca_file`，`server_name` 必填 DNS；共享现有 TLS1.3-only 构建）；
   version 固定 3。配置阶段拒绝无 endpoint/password/tls、非法 SNI、UDP 相关组合。
   客户端固定 strict TLS1.3：TLS1.2 无法完成 v3 应用数据 HMAC 证明，握手后仍失败关闭。
2. `ProxyOutbound` 增加已构建 `shadowtls: Option<Arc<ShadowTlsClient>>`。`is_proxy`
   视为代理连接器，但 `connect_selected`/`connect_prepared` 作为最终目标时返回
   Unsupported；只有作为另一出站的 `via` 且下游 endpoint 与 ShadowTLS endpoint
   完全一致时才允许，禁止多个 ShadowTLS 跳。
3. `via` 链在 `tunnel_factory` 特判 `previous.kind == ShadowTls`：打开
   `previous()` 的 TCP 流后调用 `ShadowTlsClient::connect` 完成 TLS/v3，返回内层
   流；`proxy_transport_factory` 对 ShadowTLS 跳过普通 TLS/transport，避免二次
   TLS。下游代理接着在其内层流上执行原有 TLS/协议握手。
4. ShadowTLS 客户端作为 `src/transport/shadowtls/client.rs` 子模块，复用父模块
   常量、`read_record`、`kdf`、`xor`、HMAC 原语；实现 `ShadowTlsIo` 记录边界
   包装、rustls `BuildsSessionId`、首 ServerHello/HRR seed、握手期 application_data
   校验/XOR、`Verified` 方向链与 16KiB 记录。
5. 外层 rustls 配置从 `ClientTls` 克隆，安装 SID hook；不启用 ECH/early data，
   显式禁用 resumption。HRR 支持通过 `reality::Config::new_allow_hrr` 放行：
   ECH/early data 继续拒绝，CH2 不重建 SID；客户端记录包装仍自行从首个
   ServerHello/HRR 取 random。vendor 只做该最小加性变更并更新补丁元数据。
   外层 ClientTls 使用 TLS1.3-only；运行时再检查 is_tls13，防止回落路径被误认。
6. 记录层校验失败/非法类型发随机 alert 后关闭；远端 reset/EOF 失败关闭；内层
   不做目标寻址。取消/停机由现有 TaskTracker/child 与 `via` 链超时回收；连接
   不进入空闲池，不重放。
7. 测试使用现有 ShadowTLS 服务端 + 一个内层 Shadowsocks 服务端做真实
   SS-over-ShadowTLS 回环；独立构造 TLS 记录/HMAC 参考断言 SID、握手期 XOR、
   HRR（服务端强制不同 KX group）、终端/UDP/链不匹配拒绝；不调用生产客户端
   codec 生成答案。

## Risks / Trade-offs

- [rustls 预读吞掉内层首记录] → 记录包装在 rustls 之下，握手后服务端等待客户端
  内层首记录；测试专门验证首记录与 EOF；必要时采用`controlled`记录驱动模式。
- [HRR SID/seed 不一致] → hook CH2 保留 CH1 SID，客户端首个 ServerHello/HRR 一次
  seed；真实 HRR 回环测试。
- [via 语义误用] → 只允许 endpoint 一致的单 ShadowTLS detour，终端/UDP/多跳
  配置阶段或运行期拒绝。
- [vendor 治理] → 最小 HRR 开关默认关闭，REALITY 行为不变；更新 PATCHED.json/
  REALITY-SOURCE 并由独立空目录复现门禁确认。

## Migration Plan

既有服务端/出站/`via` 链不变；新增 `shadowtls` 出站必须显式配置。无效组合在配置
阶段失败关闭。历史结果不覆盖本批输入，完成集中回归后再记录证据。
