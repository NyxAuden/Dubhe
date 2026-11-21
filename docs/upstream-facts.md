# 上游事实核对

本页只记录**可复核的事实**，以及**由事实直接得出的差距**。每条都标证据等级，
不写推测。

固定基线：

| 上游 | 版本 | commit |
|---|---|---|
| XTLS/Xray-core | v26.10.31 | `a4a3dff5b20c2faae567b742c172c7b95e75c083` |
| SagerNet/sing-box | v1.14.4 | 见 `docs/reference-clients.md` |
| SagerNet/sing | `v0.9.7-0.20261023115459-5dc452e537bf` | sing-box v1.14.4 的 `go.mod` 指定 |

## 证据等级

| 等级 | 含义 |
|---|---|
| **A** | 读过固定 commit 的源码，本页附文件路径与关键片段 |
| **B** | 只读过官方配置文档，未读源码 |
| **C** | 用固定版本二进制实际运行并记录输出 |

本页不再出现未标注等级的断言。凡未核实的问题集中放在最后一节。

---

## 一、已对齐项的依据

### 1. 连接空闲超时 `limits.idle_timeout_ms`

**A** `features/policy/policy.go`，`SessionDefault()`：

```go
Timeouts: Timeout{
    Handshake:      time.Second * 60,
    ConnectionIdle: time.Second * 300,
    UplinkOnly:     time.Second * 1,
    DownlinkOnly:   time.Second * 1,
},
```

`ConnectionIdle` 字段注释原文：`Timeout for connection being idle, i.e., there is
no egress or ingress traffic in this connection.`

本内核：`limits.idle_timeout_ms`，默认 `300000`，`0` 不限制；判定为「双向均无
字节流动」。

**C** `idle_timeout_ms=1000` 时，客户端每 0.3 秒收发一次、持续 4.2 秒，连接存活；
停止收发后连接关闭，日志 `{"event":"connection_closed","reason":"TimedOut"}`。

**差距（A）**：上游另有 `UplinkOnly`/`DownlinkOnly`（各默认 1 秒），语义是
「单向已关闭后等待另一方向的时长」。本内核无对应配置。

### 2. 路由 `ip_is_private`

**A** `route/rule/rule_item_ip_is_private.go`：

```go
func (r *IPIsPrivateItem) Match(metadata *adapter.InboundContext) bool {
	if r.isSource {
		return !N.IsPublicAddr(metadata.Source.Addr)
	}
	...
	return !N.IsPublicAddr(metadata.Destination.Addr)
}
```

**A** `github.com/sagernet/sing` 的 `common/network/addr.go`：

```go
func IsPublicAddr(addr netip.Addr) bool {
	return !(addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsUnspecified())
}
```

**A** Go `net/netip/netip.go` 的 `IsPrivate` 仅覆盖 `10.0.0.0/8`、
`172.16.0.0/12`、`192.168.0.0/16`、`fc00::/7`。

完整集合（上式为真即「非公网」）：

| 条件 | IPv4 | IPv6 |
|---|---|---|
| `IsPrivate` | 10/8、172.16/12、192.168/16 | fc00::/7 |
| `IsLoopback` | 127.0.0.0/8 | ::1 |
| `IsMulticast` | 224.0.0.0/4 | ff00::/8 |
| `IsLinkLocalUnicast` | 169.254.0.0/16 | fe80::/10 |
| `IsInterfaceLocalMulticast` | — | ff01::/16 |
| `IsUnspecified` | 0.0.0.0 | :: |

**CGNAT `100.64.0.0/10` 不在集合内**，上游视为公网。

本内核已按此修正（`src/route.rs` 的 `is_private_ip`）。此前版本把 CGNAT 算作
私有、且漏掉 multicast，属实现 bug，非需求问题。

**注**：Xray 的 `geoip:private` 是 `geoip.dat` 数据文件里的预定义标签
（**B**），本轮未读取该数据文件内容，因此不声称两者集合相同。本内核字段命名
参照 sing-box。

### 3. 路由 `invert`

**A** `route/rule/rule_default.go`：

```go
rule := &DefaultRule{
	abstractDefaultRule{
		invert: options.Invert,
		action: action,
	},
}
```

`LogicalRule` 同样接收 `invert: options.Invert`。`route/rule/rule_abstract.go`
在匹配流程中对整条规则结果取反。

**结论**：`invert` 作用于**整条规则**，不是否定单个条件。

### 4. 路由 `domain_regex`

**A** `route/rule/rule_item_domain_regex.go`：

```go
func (r *DomainRegexItem) Match(metadata *adapter.InboundContext) bool {
	var domainHost string
	if metadata.Domain != "" {
		domainHost = metadata.Domain
	} else {
		domainHost = metadata.Destination.Fqdn
	}
	if domainHost == "" {
		return false
	}
	domainHost = strings.ToLower(domainHost)
	for _, matcher := range r.matchers {
		if matcher.MatchString(domainHost) {
			return true
		}
	}
	return false
}
```

已在匹配前统一小写，与本内核一致。编译失败在 `NewDomainRegexItem` 返回错误，
即配置期失败，也与本内核一致。

### 5. 规则集确实是一等能力

**A** `route/rule/rule_default.go`：

```go
if len(options.RuleSet) > 0 {
	...
	item := NewRuleSetItem(router, options.RuleSet, matchSource, false)
	rule.ruleSetItem = item
	rule.allItems = append(rule.allItems, item)
}
```

`route/rule/` 下另有 `rule_set.go`、`rule_set_local.go`、`rule_set_remote.go`，
即本地与远程两种来源。本内核没有对应能力。

**同时确认（A）**：`geosite`/`geoip` 在 sing-box 已移除：

```go
if len(options.Geosite) > 0 {
	return nil, E.New("geosite database is deprecated in sing-box 1.8.0 and removed in sing-box 1.12.0")
}
```

### 6. Xray 的负载均衡策略

**A** `app/router/config.go`，`BalancingRule.Build`：

```go
switch strings.ToLower(br.Strategy) {
case "leastping": ...
case "roundrobin": ...
case "leastload": ...
case "random": fallthrough
case "": ...
default: return nil, errors.New("unrecognized balancer type")
}
```

策略集合：`random`（默认）、`roundRobin`、`leastPing`、`leastLoad`。本内核只有
单成员 `selector` 与 `urltest`。

### 7. Xray 路由没有 `invert` 概念

**A** `app/router/config.go` 的 `BuildCondition()`：逐条 `conds.Add(...)` 后
`ConditionChan.Apply` 是全部条件的 AND；没有整条规则取反的入口。`SourceIp`
存在（`NewIPMatcher(rr.SourceIp, MatcherAsType_Source)`），IP 的否定通过
`geodata.IPMatcher` 的文法处理，不在条件层。

**结论**：Xray 的 `!` 前缀与 sing-box 的 `invert` 不是同一层语义，
`dubhe convert` 对其明确报告不转换是正确的。

### 8. 中继缓冲默认值

**A** `features/policy/policy.go`：

```go
func readDefaultBufferSize() int32 {
	const defaultValue = -17
	size := platform.NewEnvFlag(platform.BufferSize).GetValueAsInt(defaultValue)
	switch size {
	case 0:
		return -1 // For pipe to use unlimited size
	case defaultValue:
		switch runtime.GOARCH {
		case "arm", "mips", "mipsle":
			return 0
		case "arm64", "mips64", "mips64le":
			return 4 * 1024
		default:
			return 512 * 1024
		}
	default:
		return int32(size) * 1024 * 1024
	}
}
```

**注意**：该值写入 `Buffer.PerConnection`，字段注释为
`Size of buffer per connection, in bytes`。但**它由 `ContextWithBufferPolicy`
注入，实际生效路径未逐行核对**（见第四节）。

---

## 二、核查后确认「上游也不做」的项

| 项 | 证据 | 结论 |
|---|---|---|
| 配置期监听端口冲突检测 | **C** `sing-box check` 对两个入口监听同一端口 exit 0；`xray run -test` 输出 `Configuration OK` | 上游把冲突留给运行期。本内核 `check` 通过、`run` 报 `AddrInUse`，一致 |
| 内建日志轮转 | **B** Xray 只有 `log.access`/`log.error` 文件路径；sing-box 只有 `log.output` | 均无轮转实现 |
| 按源 IP 的握手限速 | **A** Xray `policy.levels.*` 只有 `Handshake`/`ConnectionIdle`/`UplinkOnly`/`DownlinkOnly`/`BufferSize`，按用户等级而非源 IP；**A** sing-box 规则项列表无握手限速字段 | 上游无此功能。若本内核要加，只能称自身安全加固 |

---

## 三、上游有、本内核没有

| 项 | 等级 | 具体事实 | 本内核现状 |
|---|---|---|---|
| `UplinkOnly`/`DownlinkOnly` | A | 各默认 1 秒 | 无配置项 |
| 规则集 | A | `RuleSetItem` + local/remote 两种来源 | 无 |
| 负载均衡策略 | A | 4 种 | 仅 `selector`/`urltest` |
| 路由 `source_ip_cidr` | A | `NewIPCIDRItem(true, ...)` 挂在 `sourceAddressItems` | 源 IP 未进入选路调用链 |
| 出站 Mux 复用 | A | `route.go` 明确：`global multiplex is deprecated since sing-box v1.7.0, enable multiplex in Inbound fields instead`，即复用配置在 Inbound/Outbound 的 `multiplex` 段 | 无 |
| UDP NAT 映射/过滤模式 | B | `shared/udp-nat` 文档有 `udp_mapping`/`udp_filtering`/`udp_nat_max` | 分协议不同：`src/udp.rs:543-548` 每目标 connected（对称型）；**TUIC 是 full-cone**（`tuic.rs:1099-1113` bind 通配 + `send_to`/`recv_from`），符合 TUIC SPEC |
| FakeIP | A | `route.go` 的 `prepareMatchMetadata` 有 `FakeIP().Store().Lookup(...)` 与 `newFakeIPNATPacketConn` | 无 |

**已从本表删除**：此前把「中继缓冲 512 KiB」列为差距，但生效路径未核实，
不足以作为需求依据（见第四节）。

---

## 四、仍未核实的问题

以下问题本轮没有取得源码级证据，不得作为决策依据：

1. `Buffer.PerConnection` 的 512 KiB 是否覆盖普通 TCP 中继路径，还是仅
   Mux/gRPC 等多路复用路径。`ContextWithBufferPolicy` 的调用点未读完。
2. sing-box 的 `udp_mapping`/`udp_filtering` 默认值与逐条语义（只读到文档）。
3. Xray `geoip:private` 的实际地址集合（未读 `geoip.dat`）。
4. 上游 `ConnectionIdle` 的生效层：本内核只在 `forward::relay` 与 ShadowTLS
   fallback 实现，WireGuard 隧道内中继未覆盖。
