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

MaxMind 数据库的 API 是「输入 IP → 查国家码」，**无法反向列出某个国家的全部
网段**。所以 `mmdb:CN` 不能像 `geoip:cn` 那样预先展开成 CIDR 列表，只能在
匹配时逐 IP 查询。这是数据格式决定的，不是实现取舍。

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

## 失败行为

全部**失败关闭**，且在 `dubhe check` 阶段就能发现（不需要真正启动）：

| 情况 | 行为 |
|---|---|
| 规则引用了 `geosite:` 但没配 `geo` 段 | 报错，指出缺少 geo 段 |
| `geosite:xxx` 在数据里不存在 | 报错，含具体 code |
| `geoip:` 写在 `domains` 里（或反之） | 报错，指出应该用哪个字段 |
| 数据文件不是合法 protobuf / 为空 | 报错，含文件路径 |
| `rule_sets` 指向 `.srs` 二进制 | 报错，提示改用 source JSON |
| `ip_cidrs` 里的字符串不是已知前缀 | 报错，不回显原文（避免泄露敏感输入） |

## 与 Xray / Mihomo 的写法差异

| Xray | 本项目 |
|---|---|
| `"domain": ["geosite:cn"]` | `"domains": ["geosite:cn"]` |
| `"ip": ["geoip:cn"]` | `"ip_cidrs": ["geoip:cn"]` |
| `geoip:private` | 用 `ip_is_private: true`（不需要数据文件） |

`dubhe convert` 会把 `geosite:` 引用原样保留并提示需要配置 `geo.geosite`；
`geoip:` 与 `geoip:private` 会做对应映射。

## 测试

`tests/geo_routing.rs` 的数据集全部由测试现场生成（按 proto 定义手写 protobuf
编码、按 rule-set source 格式写 JSON），不依赖任何外部文件：

- `geosite:` 整域命中被拒绝，同入口的其它域名仍正常转发
- `geoip:` CIDR 命中被拒绝
- `rule_set:` 后缀命中（含子域）
- 缺少 `geo` 段 / 缺 code / 类型放错字段时在 `check` 阶段报错

`src/geo.rs` 另有单元测试覆盖解析层（含 SRS 二进制的可操作报错）。

### 真实数据集用例

`tests/geo_routing.rs` 里另有 3 项用**真实数据集**验证归属判断
（`geosite:google` 的 Full 与后缀语义、`geoip:cn`、`mmdb:CN`）。

获取数据：

```bash
./tools/fetch_geodata.sh
```

脚本里的版本是**钉死**的（`V2RAY_RULES_TAG` / `MAXMIND_GEOIP_TAG`），
不用 `latest`——数据每周在变，`latest` 会让结果无法复现。要更新数据时
改这两个变量，并同步 CI 的缓存 key，然后重跑全部用例。

没有数据时这 3 项会打印「跳过：未下载真实数据集」并返回——**不静默通过**。

CI 有独立的 `geo-real` job（仅 ubuntu，缓存数据文件）跑这 3 项：下载失败
就让 job 失败，而不是跳过。数据与平台无关，不必在三平台矩阵里重复。

### 真实数据暴露过的一个缺陷

`regex` 默认特性关闭时缺 `unicode-perl`，而真实 `geosite.dat` 里有
`^cdn\d-epicgames-\d+\.file\.myqcloud\.com$` 这类 Perl 字符类，
整份数据会因此加载失败。这个只有在真实数据上才会暴露——手造样本永远
发现不了。已在 `Cargo.toml` 里显式启用该特性并注明原因。
