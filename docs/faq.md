# 故障排查

## 启动失败

**`配置检查通过` 但 `run` 立即退出**

看 stderr 的 JSON 日志，字段 `event="fatal"` 与 `reason` 是脱敏后的分类。常见原因：

| 现象 | 原因 | 处理 |
|---|---|---|
| `api.token_file 不可读取` | 路径不存在或运行用户无权限 | `sudo -u dubhe test -r <path>` |
| `api.token_file 权限必须为 0600` | 文件允许组或其他用户读 | `chmod 0600`，属主改为运行用户 |
| `TLS 私钥权限` 报错 | 私钥权限过宽 | `chmod 0600` |
| `Address already in use` | 端口被占用或上次实例未退出 | `ss -lntup` 查端口；`systemctl status dubhe` |
| `明文 VLESS 不支持 Vision flow` | flow 与无 TLS 组合 | 加 TLS 或去掉 `flow` |

## 客户端连不上

按链路从外到内排查：

1. **端口与防火墙**：`ss -lntup | grep dubhe`，确认监听地址不是 `127.0.0.1`。
2. **TLS 证书**：客户端必须信任服务端证书；自签名证书要用客户端自己的信任配置，
   不要用 `skip-cert-verify` 掩盖问题。
3. **身份字段**：VLESS 用 `uuid`（标准 36 字符），Trojan/AnyTLS/SS 用 `password`，
   Snell 用 `userkey`。字段填错时服务端只会拒绝，不会提示"用户名不存在"。
4. **REALITY**：客户端 `publicKey`、`shortId`、`serverName` 必须与服务端一致；
   `serverName` 必须出现在 `server_names` 里。
5. **传输层**：WS 的 `path`、`Host`，gRPC 的 `grpc.path`，XHTTP 的 `mode`/`path`
   必须两端一致。不一致时通常表现为握手成功但连接立即断开。
6. **无认证入口**：SOCKS/HTTP 非回环且没有 `users` 时默认拒绝启动；需要显式
   `"allow_insecure": true`，但通常不应该这样部署。

## 配置改了不生效

- `SIGHUP` 只有在**配置内容未变**时才做证书轮换。
- 配置变化时，只有「入口、`limits`、API、NW3 Egress 未变且没有 UDP 监听器」
  才走零停机热重载；其余情况会完整重启，短暂断连。
- QUIC、mKCP、REALITY、ShadowTLS 的证书变更需要 `systemctl restart`。
- 管理 API 的 `token_file` 内容改动需要重启进程。

## 统计看起来不对

- `/stats` 与 `/metrics` 是全局计数；`/stats/users` 只覆盖文档列出的路径。
- **UDP 流量在部分协议下不计字节**：以 `docs/usage.md` 的归因范围为准。
- WireGuard 与 Shadowsocks 单密钥没有用户名，只进全局计数。
- 计数在写入成功后才累加，部分写入不计入。

## 日志

- 默认 JSON 写 stderr，由 journald 收集：`journalctl -u dubhe -f`。
- 日志不包含密码、私钥、业务载荷和目标地址；不要为了排障把完整配置贴进工单。
- `shadowsocks` crate 的日志被显式关闭，避免 EIH 身份哈希进入日志。

## 需要报告问题时

带上：`dubhe version`、平台、客户端与版本、最小配置（去掉凭据）、复现步骤、
脱敏后的日志。安全问题是私密渠道，见 [SECURITY.md](../SECURITY.md)。
