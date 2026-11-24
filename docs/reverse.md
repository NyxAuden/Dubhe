# 反向 Mux（Portal 与 Bridge）

状态：**已实现待集中验收**。

本实现对应 Xray 的 **VLESS 命令 4** 反向隧道（`RequestCommandRvs = 0x04`），
也就是官方文档《VLESS Reverse Proxy Examples》描述的 `users[].reverse` 机制，
**不是** `app/reverse` 的 `tunnel` 入站机制——后者是另一套并存实现
（固定域名 `v1.rvs.cool`，在 Xray v26.10.31 中仍存在且未标记弃用）。

两者的差别（2026-11-23 核对）：

| | `app/reverse` | 命令 4 / 本项目 |
|---|---|---|
| 声明方式 | `tunnel` 入站 + Portal/Bridge | `users[].reverse` 或 `reverse_bridges` |
| 目标域名 | 固定 `v1.rvs.cool` | 同左（命令 4 的固定目标） |
| Xray 状态 | 存在，无弃用警告 | 官方文档推荐 |

本实现覆盖 **Portal** 与 **Bridge** 两种角色：Portal 接收 Bridge 主动拨入的
命令 4 并登记反向隧道；普通流量经 `reverse` 出站回到 Bridge 的 Mux 服务端。
Bridge 使用顶层 `reverse_bridges` 引用一个标准 `vless` 出站，连接断开后按
`reconnect_ms` 重连。

配置格式：项目**同时支持两种写法**。

Portal 侧（接收 Bridge 拨入）推荐 Xray 写法，可以直接照搬：

```json
{
  "inbounds": [{
    "type": "vless",
    "users": [{"uuid": "…", "reverse": {"tag": "portal"}}]
  }],
  "outbounds": [
    {"type": "reverse", "tag": "portal", "domain": "v1.rvs.cool"}
  ]
}
```

`users[].reverse.tag` 在**配置解析阶段**校验：tag 格式必须有效、必须指向存在的
出站、且该出站的 kind 必须是 `reverse`。写错会立即报错，不会拖到运行期。

**未声明 `reverse.tag` 的账户默认不能建立反向隧道**（返回 `PermissionDenied`）。
这是 Xray 的语义：Portal 载体的归属必须由账户显式声明，否则任何已认证账户只要
命中指向 `reverse` 出站的路由，就能注册成载体。

旧配置若依赖「命令 4 的固定域名 `v1.rvs.cool` 被路由到 `reverse` 出站」来定
归属，需要显式打开顶层开关：

```json
{ "reverse_route_fallback": true }
```

打开后回落行为与从前一致，但**任何已认证账户都能注册载体**，只应在这种受控
部署里使用。该开关默认关闭，且不持久化到运行期以外的任何地方（它就是普通配置
字段）。

Bridge 侧仍用顶层 `reverse_bridges`（Xray 的对应写法是给 `vless` 出站加
`settings.reverse.tag`）。

## 配置

```json
{
  "outbounds": [
    { "type": "reverse", "tag": "portal", "domain": "v1.rvs.cool" },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "default": "direct",
    "rules": [
      { "domains": ["v1.rvs.cool"], "outbound": "portal" },
      { "inbounds": ["socks-in"], "outbound": "portal" }
    ]
  }
}
```

- `reverse` 出站只接受 `domain`（ASCII，1–253 字节），不能配置 endpoint、
  凭据、TLS、`transport` 或 `via`，也不能作为 `selector`/`urltest` 成员。
- **当前实现中 `domain` 只参与配置校验与展示，不参与隧道匹配**：VLESS 命令 4
  的固定目标始终是 `v1.rvs.cool`，必须用路由规则把该域名指向 `reverse` 出站。
  把 `domain` 配成其它值不会创建另一条匹配路径。

Bridge 配置：

```json
{
  "outbounds": [
    { "type": "vless", "tag": "portal-link", "endpoint": "portal.example:443",
      "uuid": "REPLACE_WITH_PORTAL_UUID",
      "tls": { "ca_file": "/etc/ssl/private/portal-ca.pem", "server_name": "portal.example" } },
    { "type": "direct", "tag": "direct" }
  ],
  "reverse_bridges": [
    { "tag": "bridge", "outbound": "portal-link", "reconnect_ms": 5000 }
  ],
  "route": { "default": "direct" }
}
```

- `reverse_bridges[].outbound` 必须引用本配置中已存在的 `vless` 出站；该出站的
  endpoint、TLS、`flow`（含 Vision）、`transport`、VLESS Encryption 与 `via` 链
  全部复用标准出站校验。
- `tag` 是 Bridge 的本地 Mux 服务端 inbound tag，参与 Bridge 侧路由匹配。
- `reconnect_ms` 范围 100–600000，默认 5000；连接正常结束或失败后统一重连。
- 配置了任一下 reverse bridge 时 SIGHUP 走完整重启，不做零停机 Context 热替换。
- 第一条规则把 VLESS 命令 4 的固定目标 `v1.rvs.cool` 交给 portal；第二条
  规则示例把普通入站流量也交给 portal。

## 工作方式

1. Bridge 用 VLESS 连接到 Portal，发送 **命令 4**（无地址字段）。
2. Portal 返回 VLESS 应答后，在该连接上运行 **Mux 客户端**，并把隧道登记到
   对应 portal；每条隧道最多 256 个并发会话，每个 portal 最多 64 条隧道。
3. 普通连接被路由到 `reverse` 出站时，Portal 在最近的可用隧道上打开一个
   Mux 会话（New 帧携带真实目标），由 Bridge 的 Mux 服务端拨号。
4. 数据使用标准 Mux.Cool Keep 帧；End 帧关闭会话。会话读取过慢时丢弃该
   会话而不是阻塞整条隧道。
5. 每 5 秒在目标 `reverse` 的控制会话上发送 protobuf `Control` 心跳，匹配
   Xray Bridge 的 worker 空闲回收逻辑。

隧道连接消失或写入失败时，其上所有会话读到 EOF；没有可用隧道时，路由到
`reverse` 出站的 TCP 连接立即失败关闭，不会回落到直连。

## 边界

- Portal 与 Bridge 均已实现，命令 4 的 Mux 隧道支持 TCP 与 UDP 会话（UDP 目标随数据报携带）；
  Xray 的 account 级“禁止反向用户正向代理”安全限制未实现。
- Portal 侧命令 4 支持 VLESS 明文、标准 TLS、Vision 与 REALITY；Bridge 引用标准
  VLESS 出站，因此支持明文/TLS/Vision、WS/gRPC/HTTPUpgrade/XHTTP/mKCP/QUIC、
  VLESS Encryption 与 REALITY。REALITY 出站已接入，Bridge 可以引用带 `reality`
  的 VLESS 出站主动拨入 REALITY Portal；该组合尚未做本机回环或官方互通验证。
- 本机 `tests/reverse_bridge.rs` 4 项通过：明文 VLESS TCP、Vision 命令 4、
  Mux UDP（2048 字节载荷）与非法引用拒绝；测试使用本内核 Portal + Bridge 完成真实回环。
- 不参与管理接口的连接列表与按连接关闭；会话不登记到 TCP 连接注册表。
- 官方 Xray Bridge/Portal 互通、三平台、MSRV 与 release 验收尚未执行。
