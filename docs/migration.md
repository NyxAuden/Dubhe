# 从 Xray / sing-box 迁移

本项目不兼容上游配置 schema，但提供一次性转换命令，其余字段按本文手工补。

```sh
dubhe convert --from xray --input xray.json --output dubhe.json --report report.txt
dubhe check -c dubhe.json
```

转换器只覆盖「入口/出站基本字段 + 静态路由」；报告里会列出被跳过或无法转换的项。
**转换结果不会被直接信任**：它只是起点，必须手工核对后再上线。

## 先理解三个差异

1. **出站 TLS 必须显式信任锚**。本项目不隐式信任系统根证书，出站的 `tls` 需要
   `ca_file`。转换器要求 `--ca-file`，否则报错。
2. **未知字段直接拒绝**。上游配置里常见的 `sniffing`、`allocate`、`mux` 等字段
   本项目的对应位置不同，写错不会被静默忽略。
3. **规则集不解析**。`geosite:` / `geoip:` / `ext:` 需要外部数据，本项目不实现；
   转换器会跳过并写进报告。

## Xray 字段对照

### 入站

| Xray | 本项目 | 说明 |
|---|---|---|
| `protocol: "vless"` + `security: "none"` | `type: "vless"` | 无证书为明文 VLESS |
| `protocol: "vless"` + `security: "tls"` | `type: "vless"` + `certificate`/`private_key` | |
| `protocol: "vless"` + `security: "reality"` | `type: "vless-reality"` + `reality` | |
| `network: "ws"` | `type: "vless-ws"` 等 | 传输层是类型的一部分，不是独立字段（见下方「与出站不一致」） |
| `network: "grpc"` | `type: "vless-grpc"` + `grpc.path` | `path` 必填完整 RPC 路径 |
| `network: "xhttp"` | `type: "vless-xhttp"` + `xhttp` | 四种模式；`downloadSettings` 直接拒绝 |
| `extra` 里的 `downloadSettings` | **拒绝转换** | 会改变下行语义，需手工配置 |
| `network: "httpupgrade"` | `type: "vless-httpupgrade"` + `httpupgrade` | |
| `network: "kcp"` | `type: "vless-kcp"` + `kcp` | mKCP 自带认证层，不需 `allow_insecure_transport` |
| `listen` + `port` | `listen: "HOST:PORT"` | 本项目是一个 SocketAddr 字符串 |
| `settings.clients[].id` | `users[].uuid` | 标准 36 字符 UUID |
| `settings.clients[].email` | `users[].name` | 同时是统计归因的键 |
| — | — | **入站与出站的表达方式不同**：出站是 `type: "vless"` + `transport: {"type": "ws"}`（与上游一致的正交设计）；入站把承载写进类型名（`vless-ws`）。三种协议 × 九种承载 = 27 个入站类型值，没有 `transport` 字段。这是已知的结构债，见 `docs/architecture.md` 的「入站结构」一节 |
| `settings.clients[].flow` | `users[].flow` | 仅支持 `xtls-rprx-vision` |
| `settings.decryption` | `decryption` | `none` 省略；VLESS Encryption 原样保留 |
| `streamSettings.tlsSettings.certificates[]` | `certificate` / `private_key` | 只取第一组 |
| `realitySettings.dest` | `reality.target.host` + `.port` | |
| `realitySettings.privateKey` | `reality.private_key` | |
| `realitySettings.shortIds` | `reality.short_ids` | |
| `realitySettings.serverNames` | `reality.server_names` | 必须包含客户端 SNI |

### 出站

| Xray | 本项目 |
|---|---|
| `protocol: "freedom"` | `type: "direct"` |
| `protocol: "blackhole"` | `type: "reject"` |
| `protocol: "vless"` + `vnext[]` | `type: "vless"` + `endpoint`/`uuid`/`flow` |
| `protocol: "vmess"` + `vnext[]` | `type: "vmess"` + `endpoint`/`uuid`/`security` |
| `protocol: "trojan"` + `servers[]` | `type: "trojan"` + `endpoint`/`password` |
| `protocol: "shadowsocks"` | `type: "shadowsocks"` + `method`/`password` |
| `protocol: "socks"` | `type: "socks5"` + `endpoint`/`username`/`password` |
| `protocol: "http"` | `type: "http"` + `endpoint`/`username`/`password` |
| `streamSettings.network: "ws"` | `transport: {"type":"ws","path":...,"host":...}` |
| `streamSettings.network: "grpc"` | `transport: {"type":"grpc","path":"/Service"}`（`multiMode` → `multi: true`） |
| `streamSettings.network: "xhttp"` | `transport: {"type":"xhttp",...}` |
| `streamSettings.network: "httpupgrade"` | `transport: {"type":"httpupgrade",...}` |
| `streamSettings.network: "kcp"` | `transport: {"type":"kcp"}` |
| `streamSettings.security: "tls"` | `tls: {"ca_file": "...", "server_name": "..."}` |
| `streamSettings.security: "reality"` | `reality: {"public_key":...,"short_id":...,"server_name":...}` |
| `proxySettings.tag` 链式 | `via: "<上一跳 tag>"` |

### 路由与 DNS

| Xray | 本项目 |
|---|---|
| `routing.domainStrategy: "IPIfNonMatch"` | `route.domain_strategy: "ip-if-non-match"` |
| `routing.rules[].domain: ["example.com"]` | `route.rules[].domains` |
| `domain:example.com` | `domain_suffix` |
| `keyword:ads` | `domain_keyword` |
| `regexp:` | **不支持** |
| `geosite:` / `geoip:` | **不支持**，需要自己展开 |
| `routing.rules[].ip` | `ip_cidrs` |
| `routing.rules[].port: "80,443-445"` | `ports: [{"start":80,"end":80},{"start":443,"end":445}]` |
| `routing.rules[].inboundTag` | `inbounds` |
| `routing.rules[].network: "tcp,udp"` | `networks: ["tcp","udp"]` |
| `routing.balancers` | **不支持**；改用 `selector` / `urltest` 出站组 |
| `dns.servers`（字符串或对象数组） | `dns.servers`（字符串数组，见 [usage](usage.md)） |
| `dns.hosts` | `dns.hosts` |

## sing-box 字段对照

| sing-box | 本项目 |
|---|---|
| `inbounds[].type: "vless"` | `type: "vless"`（无 TLS）或加 `certificate` |
| `inbounds[].listen` + `listen_port` | `listen: "HOST:PORT"` |
| `inbounds[].users[]` | 同名 `users[]`；VLESS 用 `uuid`，Trojan/AnyTLS 用 `password` |
| `inbounds[].tls.enabled` | 配置 `certificate`/`private_key` 即启用 TLS |
| `inbounds[].tls.reality` | 独立类型 `vless-reality` + `reality` |
| `inbounds[].transport.type: "ws"` | 独立类型 `vless-ws` + `websocket` |
| `inbounds[].transport.type: "grpc"` | 独立类型 `vless-grpc` + `grpc.path` |
| `outbounds[].type: "direct"` | `type: "direct"` |
| `outbounds[].type: "block"` | `type: "reject"` |
| `outbounds[].server` + `server_port` | `endpoint: "HOST:PORT"` |
| `outbounds[].tls.enabled` | `tls: {"ca_file": "..."}` |
| `outbounds[].tls.reality` | `reality: {...}` |
| `outbounds[].transport.type: "ws"` | `transport: {"type":"ws",...}` |
| `route.rules[].domain_suffix` | `route.rules[].domain_suffix` |
| `route.rules[].rule_set` | **不支持**，需要展开成具体域名/IP |
| `route.final` | `route.default` |
| `dns.servers[].type: "local"/"udp"/"tls"/"https"` | `dns.servers` 字符串写法 |

## 常见配置示例

VLESS + REALITY 入站：

```json
{
  "type": "vless-reality",
  "tag": "reality",
  "listen": "0.0.0.0:443",
  "users": [{"name": "alice", "uuid": "<uuid>", "flow": "xtls-rprx-vision"}],
  "reality": {
    "target": {"host": "www.example.com", "port": 443},
    "private_key": "<private-key>",
    "server_names": ["www.example.com"],
    "short_ids": ["ab"]
  }
}
```

Trojan over TLS 入站：

```json
{
  "type": "trojan",
  "tag": "trojan",
  "listen": "0.0.0.0:8443",
  "users": [{"name": "alice", "password": "<strong-password>"}],
  "certificate": "/etc/dubhe/cert.pem",
  "private_key": "/etc/dubhe/key.pem"
}
```

到上游 VLESS + TLS 的出站（注意 `ca_file`）：

```json
{
  "tag": "proxy",
  "type": "vless",
  "endpoint": "upstream.example.com:443",
  "uuid": "<uuid>",
  "tls": {"ca_file": "/etc/dubhe/upstream-ca.pem", "server_name": "upstream.example.com"}
}
```

## 迁移检查清单

- [ ] `dubhe check` 通过
- [ ] 报告里每条「已跳过」都确认过影响
- [ ] 出站 TLS 的 `ca_file` 是真实信任锚，不是系统根证书的复制品
- [ ] 客户端使用的 UUID / 密码 / shortId 与服务端一致
- [ ] `domain` 规则没有把需要直连的流量误路由
- [ ] 先用一个入口灰度，确认无误后再切其余入口
