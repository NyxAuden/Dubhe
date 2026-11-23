# 本机参考客户端

核查日期：2026-11-04。目标平台：macOS / darwin-arm64。

当前Shadowsocks批次复用下列固定官方二进制，逐场景启动前重新验证摘要；24项Shadowsocks及同一新构建旧九项显式回归全部通过，共87场景，见[本批验收](shadowsocks-acceptance.md)。下文保留最初下载/版本准备历史，不把版本命令当协议互通。

本轮用户已授权从三个官方 GitHub 仓库下载、校验并受控运行参考客户端。准备阶段仅执行版本命令，不启动代理监听、不安装服务、不修改系统代理、不操作 Docker。二进制及下载归档保留在 `.test-artifacts/reference-clients/`，供本轮后续本机互操作测试使用。

## 固定发布与源码 commit

| 客户端 | 固定发布 | 官方 darwin-arm64 资产 | 版本命令 |
| --- | --- | --- | --- |
| Mihomo | [v1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33) | `mihomo-darwin-arm64-v1.19.33.gz` | `mihomo -v` |
| sing-box | [v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) | `sing-box-1.14.4-darwin-arm64.tar.gz` | `sing-box version` |
| Xray | [v26.10.31](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31) | `Xray-macos-arm64-v8a.zip` | `xray version` |

Mihomo v1.19.33 来自本次查询的 [GitHub latest stable API](https://api.github.com/repos/MetaCubeX/mihomo/releases/latest)，发布于 2026-10-21。脚本将本次结果固定为 v1.19.33，再次运行不会自动升级。sing-box 与 Xray 使用本项目研究选定的固定版本；三个 release 的 `draft`、`prerelease` 均为 false。

固定 tag 当前指向的完整 commit 如下，已同步补充到 `source-research.md`；本轮未验证从源码构建可复现，也未固定该文档引用的 Nowhere-Protocol 规范仓库。

| 仓库与 tag | commit | 查询来源 |
| --- | --- | --- |
| SagerNet/sing-box `v1.14.4` | [`c005f35300ce76427dc285481ec5695f5b179cd2`](https://github.com/SagerNet/sing-box/commit/c005f35300ce76427dc285481ec5695f5b179cd2) | [tag ref API](https://api.github.com/repos/SagerNet/sing-box/git/ref/tags/v1.14.4) |
| XTLS/Xray-core `v26.10.31` | [`a4a3dff5b20c2faae567b742c172c7b95e75c083`](https://github.com/XTLS/Xray-core/commit/a4a3dff5b20c2faae567b742c172c7b95e75c083) | [tag ref API](https://api.github.com/repos/XTLS/Xray-core/git/ref/tags/v26.10.31) |

上述两个 ref 的对象类型均为 `commit`，无需解引用 annotated tag。GitHub tag 可以移动，源码定位应使用这里记录的完整 commit；发布资产与源码 commit 的构建对应关系未通过可复现构建验证。

## 校验信息

下列 SHA-256 来自官方仓库 release asset API 的 `digest` 字段，校验对象为下载归档。

| 客户端 | 归档 SHA-256 | API 来源 |
| --- | --- | --- |
| Mihomo | `060b64b0f2c9a310831db0fe4adb2878de67bfa606c311813c1f13966aa504b6` | [release API](https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.33) |
| sing-box | `0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838` | [release API](https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.14.4) |
| Xray | `0a05dca3bd311b0bc5a89c7ce56350cab1e829e131e4b2bcd48eb304fac07e9a` | [release API](https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.10.31) |

`upstream_checksum_verified` 表示归档的本地 SHA-256 与官方 API digest 一致，不表示验证了发布者数字签名。`sha256` 是解压后二进制的本地 SHA-256，`archive_sha256` 才是与 API digest 比较的归档摘要。`signature_verified` 为 false。本轮采用 API digest，未另外下载 Xray 的 `.dgst` 文件。若后续资产没有 API digest，脚本会明确记录仅有本地 SHA-256，不能据此声称上游校验或签名验证成功。

## 下载、解压与执行方式

脚本位于项目 `tools/`，与下载位置分离。运行方式如下。

```sh
cd $PROJECT_ROOT
python3 -I tools/fetch_reference_clients.py
```

每次运行创建新的 `run-*` 目录；每个归档下载到独立、全新、空的 `download-*` 目录，每个归档另用一个全新、空的 `extracted-*` 目录。脚本只使用 HTTPS 官方发布链接及其 HTTPS 重定向，不需要 GitHub CLI 认证。下载大小与 release 元数据核对，API digest 不匹配会停止该客户端的准备。

ZIP/TAR 在写出成员前检查全部条目，拒绝绝对路径、`..`、Windows 路径、符号链接、硬链接、特殊文件及重复路径；仅手动写出普通文件和目录，不调用归档内脚本。Gzip 单文件的内嵌文件名被忽略，目标文件名由固定客户端列表提供。解压设置大小上限，运行前确认二进制是**当前平台**的本地可执行文件：macOS 校验
64 位 Mach-O 与 CPU 类型，Linux 校验 64 位小端 ELF 与 `e_machine`（x86_64 / aarch64）。
平台不在已钉住的范围内时脚本直接退出，不猜测资产名。

执行时使用二进制绝对路径，以项目目录作为工作目录；单独创建版本检查用的 HOME，并使用最小环境。每个二进制仅传入表中的版本参数，设置 15 秒超时，检查退出码、产品名与固定版本，并确认执行前后二进制摘要一致。所有读取下载内容的 Python 均使用 `-I`，不在下载或解压目录内启动解释器或构建工具。

归档安全检查已覆盖绝对路径、目录穿越、Windows 路径、ZIP/TAR 符号链接拒绝，以及合法可执行文件测试条目的解压。它们验证脚本的边界处理，不代表代理协议兼容性测试。

## 在 CI 里运行

`tests/reference_clients.rs` 的互通用例全部是 `#[ignore]`，因此**不进 push/PR**。
`.github/workflows/ci.yml` 有一个独立的 `interop` job：

- 触发条件：`workflow_dispatch` 或每周定时（与 `fuzz-smoke` 相同）
- 平台：`ubuntu-24.04` 与 `macos-14`
- 步骤：先跑本脚本下载并校验三/四个官方客户端，再
  `cargo test --test reference_clients -- --ignored`
- 失败时上传 `interop.log`

下载脚本任何一步失败都会让 job 失败，不会静默跳过——「跳过」不等于「通过」。

## 结果与后续使用

本轮三个客户端均为 `ready`，归档校验全部通过，版本命令退出码均为 0，无阻塞。实际输出首行如下。

```text
Mihomo Meta v1.19.33 darwin arm64 with go1.26.10 Wed Oct 21 16:44:27 UTC 2026
sing-box version 1.14.4
Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 darwin/arm64)
```

sing-box 的 `Revision` 输出为 `c005f35300ce76427dc285481ec5695f5b179cd2`，与固定 tag commit 一致；Xray 输出的 `a4a3dff` 与对应 commit 前缀一致。Mihomo tag 另解析为 `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`，已写入 manifest。以上仍是发布元数据和二进制自报版本的核对，不构成源码构建溯源证明。

机器可读结果在 [reference-clients.json](../.test-artifacts/reference-clients.json)。每个客户端记录绝对二进制路径、固定版本、官方资产来源、归档及二进制 SHA-256、上游校验状态、tag commit、版本命令、原始版本输出及准备状态。`status: ready` 才表示该客户端完成下载、解压和版本验证；`status: blocked` 会记录具体错误，脚本不会替换为其他版本。

互通测试从 manifest 的 `clients[].path` 读取二进制路径；路径属于本机临时测试产物，不应作为跨机器固定路径。重新运行脚本会创建新目录并更新 manifest，同时保留之前的二进制。版本命令只验证产品与版本报告，不能单独证明代理互通；后续实际运行的结果见 [interop-report.md](interop-report.md)。manifest 的 `execution_scope` 只描述下载脚本的版本检查阶段，不是后续运行授权或互通结果。
