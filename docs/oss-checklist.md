# 开源项目补齐计划

面向「能被别人试用、能接受贡献」的社区项目定位，不承诺生产 SLA。
对照结论来自主流代理内核（Xray-core、sing-box、shadowsocks-rust、hysteria、
mihomo、v2ray-core、tuic）的公开实践。

## 已定的项目规则

| 项 | 规则 |
|---|---|
| 定位 | 社区项目：能自建、能推荐、出问题有人修；不承诺生产 SLA |
| 许可 | GPL-3.0-only（`vendor/nowhere` 强制），README 说明原因 |
| 维护 | 接受 PR，但四个门禁全绿才评审：fmt、clippy `-D warnings`、全量测试、`cargo deny` |
| 兼容 | 线协议兼容；配置兼容通过独立 `dubhe convert` 命令，不做运行时双 schema |
| 转换深度 | 只做入口/出站/静态路由与 DNS；高级语义显式报错；固定上游版本 |
| 未支持字段 | 生成丢弃报告并警告；影响流量路径的字段直接报错 |
| 实验性能力 | 只靠文档隔离：README 主表只列已验收，其余进 `docs/experimental.md` |
| 验收期限 | 主推协议 60 天，次要协议 180 天；到期降级 |
| 安全 | 私密 Advisory + 7 天确认；`cargo deny` 进 CI；不宣称审计 |
| 文档语言 | README 英文为主并链到中文细节；深度文档保持中文 |

## 验收判定（六列全绿才算通过）

| 列 | 判据 |
|---|---|
| 上游版本 | 写死，例如 Xray v26.10.31 / sing-box v1.14.4 |
| 方向 | 客户端→本内核 / 本内核→服务端 / 双向 |
| 业务载荷 | 真实请求，不是只连端口 |
| 负向用例 | 错误密码、证书、UUID 必须失败关闭 |
| 平台 | 至少 macOS ARM64 与 Linux x86_64 实跑 |
| 构建 | release 二进制 + 校验和 |

缺任何一列，不得写「已验收」。

## 清单

### 已完成

- [x] 版本控制与线性提交历史
- [x] CI 三平台（Linux x86_64 / Linux ARM64 / macOS ARM64）fmt + clippy + 测试 + release 构建
- [x] `deny.toml` 无 ignore，`cargo deny` 作为独立 job
- [x] Clippy `-D warnings` 清零
- [x] SBOM 本地生成（CycloneDX）
- [x] 可复现构建记录（macOS ARM64 双目录比对）
- [x] SECURITY.md
- [x] CONTRIBUTING.md
- [x] Issue / PR 模板
- [x] Dependabot（cargo 主包、fuzz、GitHub Actions）
- [x] tag 触发的 release 工作流（三平台二进制 + sha256）
- [x] 文档状态口径统一到兼容矩阵与生产可用性评估
- [x] Dockerfile + GHCR 发布工作流
- [x] fuzz 定时任务（每周一次，不进 push/PR）
- [x] `dubhe convert --from xray`（入口/出站基本字段 + 静态路由 + 七种承载，输出经本项目校验）
- [x] 公共 helper 收敛：`fnv1a`、单字节 hex、`read_http_head` 统一到 `src/util.rs`
- [x] `dubhe export`：生成 Xray / sing-box / Mihomo / Anywhere 客户端配置
- [x] 导出结果用真实内核校验：`tools/verify_export.py`，Xray 26.10.31 / sing-box 1.14.4 / Mihomo 1.19.33 全部通过
- [x] 按用户统计：`GET /stats/users`，覆盖 11 条 TCP 路径与 7 条 UDP 路径（见 docs/usage.md）
- [x] 配置参考补全：`api`/`sniffing`/`nw3_egress`/`reverse_bridges` 与三个 limits 字段
- [x] 实验能力清单：`docs/experimental.md`
- [x] 故障排查：`docs/faq.md`
- [x] 架构概览：`docs/architecture.md`
- [x] 迁移指南：`docs/migration.md`（Xray / sing-box 字段对照）

### 上游事实与对齐状态

能力是否该做、上游到底怎么实现，统一记在
[上游事实核对](upstream-facts.md)，每条带证据等级（源码 / 文档 / 实测）。
本清单不再复制那张表，避免两处口径不一致。

概览：

- 已对齐：`limits.idle_timeout_ms`（Xray `ConnectionIdle` 默认 300 秒）、
  路由 `invert`、`ip_is_private`、`domain_regex`，以及 `dubhe convert` 的对应映射。
- 核查后确认上游也不做、不再作为需求：端口冲突检测、日志轮转、
  按源 IP 的握手限速。
- 上游有、本内核没有：`UplinkOnly`/`DownlinkOnly`、规则集、负载均衡策略、
  `source_ip_cidr`、出站 Mux 复用、UDP NAT 模式、FakeIP。
  是否要做需单独决策，`upstream-facts.md` 不评估工作量。
- 仍未取得源码级证据的问题同样列在该文件第四节，不得作为决策依据。

### 明确不做

- 二进制 GPG 签名（对照 7 个项目，0 个签二进制）
- 官方 APT/DNF 仓库（只有 sing-box 做，维护成本高）
- 覆盖率门禁与 benchmark（协议内核的行覆盖率噪音大）
- 运行时兼容 Xray/sing-box 配置（会把严格校验变成双 schema 维护）
- LTS 分支（对照项目里 0 个提供）
