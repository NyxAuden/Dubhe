# 地理数据集（geosite / geoip / mmdb / rule-set）

状态：**已实现，本机端到端测试通过**。

## 边界（先读这一段）

内核**只读取、不内置、不下载、不校验**用户提供的数据文件。

数据正确性由数据源负责，本项目不为任何第三方列表背书：`geosite.dat` 里的
域名列表每周都在变，内核无法验证其完整性。因此：

- 不打包任何数据文件进二进制
- 不实现自动下载或更新
- 数据文件路径由用户在配置里显式给出

## 支持的数据源

| 配置字段 | 格式 | 谁在用 | 匹配方式 |
|---|---|---|---|
| `geo.geosite` | Xray/Mihomo `geosite.dat`（protobuf） | Xray、Mihomo | **加载期展开**成域名规则 |
| `geo.geoip` | Xray/Mihomo `geoip.dat`（protobuf） | Xray、Mihomo | **加载期展开**成 CIDR |
| `geo.mmdb` | MaxMind `mmdb` | Mihomo（IP）、sing-box | **运行期**按 IP 查国家码 |
| `geo.rule_sets` | sing-box rule-set **source JSON** | sing-box | **加载期展开** |

### 为什么 mmdb 是运行期匹配

`maxminddb` 0.33 **提供** `Reader::networks()` 可以遍历全部网段（实测存在于
`maxminddb-0.33.0/src/reader.rs`）。本项目**选择**运行期按 IP 查询，而不是
启动时全库遍历展开：后者要把整库读一遍再按国家筛选，启动更慢、内存更大，
而单次查询本身很便宜。

这是实现取舍，不是格式限制。

### 为什么不支持 `.srs` 二进制

`.srs` 是 sing-box 的编译产物，其格式从 1.8 到 1.14 已演进 5 个版本。
本项目只吃 **source JSON**（就是普通 JSON，用 `sing-box rule-set compile`
的输入文件）。误指 `.srs` 会得到明确提示，而不是笼统的「不是合法 JSON」。

## 配置

```json
{
  "geo": {
    "geosite": "/etc/dubhe/geosite.dat",
    "geoip": "/etc/dubhe/geoip.dat",
    "mmdb": "/etc/dubhe/GeoLite2-Country.mmdb",
    "rule_sets": [
      {"tag": "ads", "path": "/etc/dubhe/ads.json"}
    ]
  },
  "route": {
    "default": "direct",
    "rules": [
      {"domains": ["geosite:openai"], "outbound": "proxy"},
      {"domains": ["rule_set:ads"], "outbound": "reject"},
      {"ip_cidrs": ["geoip:cn"], "outbound": "direct"},
      {"ip_cidrs": ["mmdb:CN"], "outbound": "direct"}
    ]
  }
}
```

`domains` 与 `ip_cidrs` 都同时接受具体值和数据集引用：

- `domains: ["example.org", "geosite:cn", "rule_set:ads"]`
- `ip_cidrs: ["10.0.0.0/8", "geoip:cn", "mmdb:CN"]`

## 匹配语义

### 域名组

`domains` 数组里的普通域名与地理引用（`geosite:` / `rule_set:`）属于
**同一个 OR 组**：任一命中即算域名条件成立。展开出的 `Full` / `Domain` /
`Substr` / `Regex` 也都在这个组里取并集——这与 Xray 的 `domain` 数组语义一致。

`domain_suffix` / `domain_keyword` / `domain_regex` 是本项目自己的独立字段，
与域名组之间仍然是 AND。

### IP 组

`ip_cidrs` 数组里的具体 CIDR、`geoip:<code>` 展开项、`mmdb:<code>`、以及
`ip_is_private` 之外的 IP 条件同属 **一个 OR 组**；`ip_is_private` 是独立
布尔字段，与该组 AND。

### 多地址目标：同一地址必须满足全部 IP 条件

域名解析出多个地址时，`ip_is_private` 与 `ip_cidrs`（含 `geoip:` / `mmdb:`）
**由同一个地址同时满足**才算命中。两个条件各自由不同地址满足不算。

例：`ip_is_private: true` + `mmdb:CN`，目标解析到 `[127.0.0.1, 223.5.5.5]`
时**不命中**——没有单个地址既是私网又属于 CN。

> 这一条与两家上游都不一致：Xray 把 `geoip:private` 当作普通数据分类并入
> 并集，sing-box 的 `ip_is_private` 与 `ip_cidr` 也是 OR。dubhe 采用的是
> 「一条规则描述目标的全部属性」这一更严格的契约。
>
> 选路仍看整组答案；直连再用每个候选地址单独执行同一套路由规则，只保留
> 仍命中同一条规则（或仍回落到默认）的地址。没有地址通过复核则拒绝。

### `invert` 与未解析的 IP

目标域名尚未解析时，依赖 IP 的条件视为**未知**，`invert` 不会把它翻成命中。
因此 `invert: true` 的 IP 规则不会在「还不知道地址」时就选中出站，也不会
遮蔽它后面的明确域名规则。

上述「未知」只适用于未解析的初选。转发时只要目标可能受 IP 条件约束，
即使 `as-is` 也需要取得实际目标的 IP 证据；解析失败或无地址则拒绝。
`ip-if-non-match` 的可选解析失败不改变初选，但不豁免这项检查。

只选路的嗅探不改实际地址，也不以嗅探域名的 DNS 结果授权；若实际目标本身可能
受 IP 条件约束，直连还要通过实际目标的规则检查。这不是给原目标的纯域名规则
追加一次否决权；显式 `dest_override` 生效时，改写后的目标才是实际目标。
IPv4-mapped IPv6 按映射后的 IPv4 匹配，落在 `::ffff:0:0/96` 内的规则前缀也换算
成 IPv4；普通 IPv6 前缀不匹配 IPv4。未指定地址不能作为直连目的地址。
适用 IP 规则的业务不交给代理或 reverse：本地结果不能证明
远端最终发包地址。该约束不是进程外防火墙，也不撤销已经建立的连接或固定目标映射。

### 与端口等条件

域名组、IP 组、端口等不同维度之间是 AND：下面这条要求「命中 geosite:cn」
**且**「目标是 443 端口」。

```json
{"domains": ["geosite:cn"], "ports": [{"start": 443, "end": 443}], "outbound": "direct"}
```

> 曾经把展开项按类型塞进 `domains` / `domain_suffix` 等独立字段，而这些
> 字段之间是 AND。以 `geosite:google` 为例（239 条 Full + 839 条后缀），
> 一条规则就要求目标同时满足两个集合，绝大多数域名都匹配不上——但这不是
> 「逻辑上永不可能」：`Full(www.example.com)` 与 `Suffix(example.com)`
> 可以同时成立。现在展开项与 `domains` 合成一个 OR 组，并有回归测试
> `geosite_mixed_full_and_suffix_are_or_combined` 与
> `domains_array_is_union_of_plain_and_geo`。

## 失败行为

配置层面的错误**失败关闭**，且在 `dubhe check` 阶段就能发现（不需要真正启动）：

| 情况 | 行为 |
|---|---|
| 规则引用了 `geosite:` 但没配 `geo` 段 | 报错，指出缺少 geo 段 |
| `geosite:xxx` 在数据里不存在 | 报错，含具体 code |
| `geoip:` 写在 `domains` 里（或反之） | 报错，指出应该用哪个字段 |
| 数据文件不是合法 protobuf / 为空 | 报错，含文件路径 |
| `rule_sets` 指向 `.srs` 二进制 | 报错，提示改用 source JSON |
| `ip_cidrs` 里的字符串不是已知前缀 | 报错，不回显原文（避免泄露敏感输入） |
| 空分类（`geosite:x` / `geoip:x` 存在但无条目） | 视为「永不匹配」，不会退化成匹配一切 |
| rule-set 含 `invert: true` / `type: logical` / `port` / `network` 等条件 | 报错并点名该字段，不静默丢弃 |
| rule-set 的字段类型错误（如 `"domain": 42`） | 报错；不会当成「字段不存在」 |
| rule-set 只含 IP 却用在 `domains` 里（或反之） | 报错，否则阻断规则永不命中 |
| rule-set 的 `version` 缺失或不在 1..=5 | 报错 |
| 数据文件超出读取预算，或展开量超出预算 | 报错，指出文件/规则序号与配额名 |
| `geo.rule_sets` 标签重复（忽略大小写） | 报错 |

**不保证失败关闭的一处**：mmdb 查询或解码出错时按「未命中」处理（`Ok(None)`
与「库损坏」不区分）。如果规则用途是阻断，这可能导致回落直连。数据文件损坏
属于本地运维问题，内核不做额外校验。

## 资源预算

数据文件的读取与规则展开都有固定上限，**超限报错，不截断**（截断会改变规则
集合，反向规则的含义会随之改变）：

| 预算 | 上限 |
|---|---|
| 单个数据文件 | 128 MiB |
| 一次加载的累计读取（四个数据源合计） | 256 MiB |
| 加载后的条目数（分类 + 域名/CIDR 项） | 300 万项 |
| 一次路由编译的累计展开项 | 200 万项 |
| 展开出的文本累计 | 128 MiB |

- 预算**跨规则累计**，不按规则重置：同一分类被十条规则引用就扣十次。
- 读取用同一文件句柄限量读，不先查 `metadata.len()` 再无界读；解码的输入因此
  有字节上界。条目限额在解码**之后**检查，限制的是留存量，不是解码瞬时峰值。
- 这些阈值是**兼容现有数据集（`geoip.dat` 约 106 万条 CIDR、`geosite.dat`
  约 53 万条域名项）的起点，不是 RSS 保证**。解码临时对象、正则编译、热重载
  期间新旧路由并存都需要额外内存。
- 超限时 `dubhe check` 失败；热重载失败时旧配置继续运行。

## 与 Xray / Mihomo 的写法差异

| Xray | 本项目 |
|---|---|
| `"domain": ["geosite:cn"]` | `"domains": ["geosite:cn"]` |
| `"ip": ["geoip:cn"]` | `"ip_cidrs": ["geoip:cn"]` |
| `geoip:private` | 用 `ip_is_private: true`（不需要数据文件） |

`dubhe convert` 会把 `geosite:` 保留到 `domains`、`geoip:` 保留到 `ip_cidrs`，
并提示需要配置对应的 `geo` 数据文件；`geoip:private` 映射为 `ip_is_private`。
`ext:`（第三方 dat）没有等价字段，转换直接失败——丢弃它会让规则少匹配一批
地址，流量改走默认出口。

Xray 同一个 `domain` 数组内的各类前缀是**并集**，而 dubhe 的 `domains` 与
`domain_suffix` / `domain_keyword` / `domain_regex` 之间是**交集**。`convert`
按种类把同一个数组拆成多条同出站的相邻规则，语义仍是并集；
`geoip:private` 与其它 `ip` 项混写无法这样表达，会报错并要求拆成多条规则。

## 测试

`tests/geo_routing.rs` 的数据集全部由测试现场生成（按 proto 定义手写 protobuf
编码、按 rule-set source 格式写 JSON），不依赖任何外部文件：

- `geosite:` 整域命中被拒绝，同入口的其它域名仍正常转发
- `geoip:` CIDR 命中被拒绝
- `rule_set:` 后缀命中（含子域）
- 缺少 `geo` 段 / 缺 code / 类型放错字段时在 `check` 阶段报错

`src/geo.rs` 另有单元测试覆盖解析层（含 SRS 二进制的可操作报错）。

### 真实数据集用例

`tests/geo_routing.rs` 里另有 4 项用**真实数据集**验证归属判断
（`geosite:google` 的后缀语义、`geoip:cn`、`mmdb:CN`，以及
`ip_cidrs` 里 CIDR 与 mmdb 的并集）。

其余语义断言走 **Router 选路结果**（`Router::select_outbound`），不走网络：
`stats.rejected` 对 SOCKS 入口而言任何 handler 错误都会加一，无法区分
「规则拒绝」与「拨号失败」。只有 2 项端到端用例用**可达的本机 echo**
证明规则确实接进了转发路径。

获取数据：

```bash
./tools/fetch_geodata.sh
```

脚本里的版本是**钉死**的（`V2RAY_RULES_TAG` / `MAXMIND_GEOIP_TAG`），
不用 `latest`——数据每周在变，`latest` 会让结果无法复现。

注意两点：脚本对**已存在的非空文件直接跳过**（不会校验内容），且允许用环境
变量覆盖版本。所以「钉死」保证的是 CI 首次下载的资产固定，不是本地目录里
实际文件的哈希——本项目不为第三方数据的完整性背书。要更新数据时改这两个
变量、同步 CI 缓存 key，并重跑全部用例。

没有对应文件时相关用例会 `eprintln!` 后 `return`，在 libtest 里仍记为通过。
**所以「跳过」不等于「已验证」**：真实数据证据只在本机下载过数据时成立。
CI 的 `geo-real` 会先下载数据再跑，缺文件时下载步骤会失败，因此 CI 上不会跳过。

CI 有独立的 `geo-real` job（仅 ubuntu，缓存数据文件）跑整套集成用例：下载失败
就让 job 失败，而不是跳过。数据与平台无关，不必在三平台矩阵里重复。

### 真实数据暴露过的一个缺陷

`regex` 默认特性关闭时缺 `unicode-perl`，而真实 `geosite.dat` 里有
`^cdn\d-epicgames-\d+\.file\.myqcloud\.com$` 这类 Perl 字符类，
整份数据会因此加载失败。这个只有在真实数据上才会暴露——手造样本永远
发现不了。已在 `Cargo.toml` 里显式启用该特性并注明原因。
