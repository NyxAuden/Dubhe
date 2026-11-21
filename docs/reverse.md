# 反向 Mux（Portal 与 Bridge）

状态：**已实现待集中验收**。本实现覆盖 Xray `app/reverse` 的 **Portal** 与 **Bridge** 两种角色：
Portal 接收 Bridge 主动拨入的命令 4 并登记反向隧道；普通流量经 `reverse` 出站回到
Bridge 的 Mux 服务端。Bridge 使用顶层 `reverse_bridges` 引用一个标准 `vless` 出站，
连接断开后按 `reconnect_ms` 重连。

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
