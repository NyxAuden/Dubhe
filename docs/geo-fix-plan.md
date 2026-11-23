# geo 路由语义：三项待修的设计与取舍

状态：三项均已实施。第 1、2 项见提交 `fdc9fc5`，第 3 项与本文件同批提交。
下面保留的是决策时的完整说明（收益与代价），不是待办清单。

本文件记录 Astra 第二轮审查后仍存在的三项问题的修法、收益与代价。**收益与代价
必须一起看**：三项都会改变既有行为，没有一项是纯增益。

---

## 第 2 项：`invert` 在域名未解析时提前翻转

### 现状

- `CompiledRule::matches` 返回 `bool`，`resolved: Option<&[IpAddr]>` 表示域名
  的解析结果。
- 目标是域名且 `resolved` 为 `None` 时，IP 条件按「不匹配」处理。
- `invert` 在最外层翻转整条规则的结果。
- `Router::select_with` 首轮用空 `resolved` 选路，**一旦某条规则命中就停止**；
  只有首轮无命中且策略为 `ip_if_non_match` 时才解析并重试
  （`src/forward.rs`）。

于是 `invert: true` + IP 条件的规则，在域名尚未解析时会「因为不匹配而命中」，
并且因为命中而不再解析。

### 问题

1. **没有地址证据就选中出站**。例如 `invert: true` + `ip_cidrs: ["geoip:cn"]`
   的规则，对 `example.com` 在未解析时就命中，即使它实际解析到 CN 地址。
2. **压过后续明确规则**。规则按顺序求值，这条在前的 invert 规则会让后面
   明确写出的域名规则永远不被考虑。

### 改法

引入内部三值：

```rust
enum RuleMatch { Hit, Miss, NeedIp }
```

求值顺序：

| 情况 | 结果 |
|---|---|
| `matches_base` 为假 | `Miss` |
| IP 组恒假（引用了地理集合但展开为空） | `Miss` |
| 没有任何 IP 条件（且非 `ip_is_private`） | `Hit` |
| 有 IP 条件，目标是字面 IP 或已有解析结果 | 按谓词得 `Hit` / `Miss` |
| 有 IP 条件，目标是域名且未解析 | `NeedIp` |

`invert` **只交换 `Hit` 与 `Miss`，`NeedIp` 保持不变**。

`select_with` 跳过 `NeedIp`；`has_ip_candidates` 改为复用同一求值函数，
返回「是否可能存在 `NeedIp`」。这样两处条件不会各自漂移。

不做的事：

- `as-is` 策略下**不发起任何 DNS**，`NeedIp` 直接视为不命中。
- 不改变「首轮有确定命中就不解析」的既有优化。
- DNS 失败或空答案仍走默认出站，不当作「已证明不是该集合」。

### 收益

- 消除「无地址证据即选路」。
- invert 规则不再遮蔽后面的明确域名规则。
- `as-is` 下行为完全确定：不解析、不依赖网络。

### 代价

- **行为变更**：此前依赖 `invert` + IP 条件「捕获所有未解析域名」的配置，
  将不再匹配。必须在 CHANGELOG 与 `docs/geo.md` 点名。
- 需要把 `matches` 的返回值从 `bool` 改为三值，并同步
  `select_outbound` / `select_with` / `has_ip_candidates` 与相关测试。
- 纯域名 invert、字面 IP invert 行为不变。

### 测试

- `inverted_ip_rule_waits_for_address`：同一域名首轮无命中；解析到集合内则
  不命中，解析到集合外则命中，两次出站必须不同。
- `deferred_ip_does_not_shadow_domain_rule`：第一条反向 IP，第二条精确域名；
  第二条命中且 DNS 调用为 0。
- `inverted_base_miss_is_decisive`：端口已不符时取反已确定为真，DNS 调用为 0。
- `unknown_is_not_non_member`：`as-is`、DNS 失败、空答案三种情况都不选反向 IP 规则。

---

## 第 1 项：`ip_is_private` 与 `ip_cidrs` 要求同一地址

### 现状

`matches` 里私网判断与 IP 组是两次独立遍历：

```rust
(!self.ip_is_private || self.matches_private(target, resolved))
    && self.matches_ip(target, resolved)
```

### 问题

域名解析到多个地址时，两个条件可以由**不同地址**分别满足。例如
`ip_is_private: true` + `mmdb:CN`，解析到 `[127.0.0.1, 223.5.5.5]` 时整体命中，
但没有任何一个地址同时是私网且属于 CN。

### 改法

把私网判断并入 `matches_ip` 的单地址谓词：

```text
group_has_items = !ip_cidrs.is_empty() || !mmdb_codes.is_empty()

geo_ip_used && !group_has_items        → IP 条件恒假
!ip_is_private && !group_has_items     → IP 条件恒真
其他 → 对每个候选 ip：
         (!ip_is_private || is_private_ip(ip))
         && (!group_has_items || cidr_hit(ip) || mmdb_hit(ip))
```

### 收益

- 规则命中时一定存在一个同时满足所有 IP 条件的地址，「命中」有可指认的依据。
- 与「一条规则描述目标属性」的直觉一致。

### 代价

- **正向规则由命中变不命中**（多地址分别满足时），反向规则相反。
- **这一改法不与任何一家上游对齐**，属于 dubhe 自有契约的收紧：
  - Xray 的 `geoip:private` 只是一个数据分类，与其它 geoip 分类合并成同一并集；
  - sing-box 的 `ip_is_private` 与 `ip_cidr` 也是 OR。
  - 若目标是「对齐 sing-box」，正确做法是把 `ip_is_private` 并入 OR 组，
    那会让规则**更容易**命中，方向相反。
- 只保证选路有依据，**不保证实际拨号到该地址**：`forward.rs` 交给拨号层的是
  原目标，不是匹配到的 IP。

### 测试

- `resolved_ip_conditions_require_same_address`：`private` + `223.5.5.5/32`
  对标述地址列表不命中（两种顺序都测）；换成 `private` + `127.0.0.0/8` 命中。
  必跑用例用 CIDR，真实数据用例再换 `mmdb:CN`。

---

## 第 3 项：加载与展开没有预算

### 现状

整文件读取、整体解码；每次引用再复制条目；每条规则各自展开；没有字节数或
条目数上限。

实测规模：

| 数据 | 大小 | 条目 |
|---|---|---|
| `geoip.dat` | 16.5 MB | 1,060,307 条 CIDR |
| `geosite.dat` | 11.5 MB | 532,925 条域名项 |

### 问题

- 只限文件大小，管不住「小分类被大量规则重复引用」；
- 只限展开条数，挡不住未被引用的大文件在加载时分配；
- 截断会改变规则集合，反向规则的含义会随之改变，**不能截断**。

### 改法

在 `geo::load` 与 `Router::new` 各加一道预算，超限返回错误。

| 落点 | 限额（起点值） |
|---|---|
| 单文件读取 | 128 MiB |
| 每次加载累计读取 | 256 MiB |
| 解码条目合计 | 300 万项 |
| 展开项数 | 200 万项 |
| 展开文本累计 | 128 MiB |

要求：

- 用同一文件句柄**限量读取**，不能先查 `metadata.len()` 再无界 `read`。
- mmdb 用 `Reader::from_source(bytes)`，避免读两遍。
- 预算由整个 `Router::new` 共用，不按规则重置。
- 出错时指出文件或 `route.rules[index]`、配额名与上限。

### 收益

- 启动与热重载的内存有明确上界，错误可解释。
- 沿用既有路径：`Server::check` 已编译 Router；热重载先构建成功再替换，
  超限时旧服务继续运行。

### 代价

- 阈值是**起点值，不是 RSS 保证**：解码临时对象、正则编译、重载期间新旧
  Router 并存都需要额外内存。
- 需要改四条读取路径与展开路径，改动面最大。
- 合法的超大型部署会首次收到明确的 `check` 失败，需要调高阈值或拆分数据。
- 新增用户可见的错误类型，属于兼容性代价。

### 测试

- `geo_read_limit_is_inclusive`：恰好上限通过，多一字节失败。
- `geo_total_budget_spans_files`：两个各自合法的文件合计超限仍失败。
- `expansion_budget_spans_rules`：总预算只够一次引用，第二次必须失败。
- `geo_budget_reload_preserves_old_route`：重载失败后旧规则仍生效。
- 用现有真实数据验证默认预算能加载。
