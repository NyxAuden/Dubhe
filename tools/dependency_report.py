#!/usr/bin/env python3
"""从 Cargo 锁定元数据生成依赖许可清单，不对许可兼容性作法律结论。"""
import argparse
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
data = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version", "1"], text=True))
root = next(p for p in data["packages"] if p["id"] == data["resolve"]["root"])
direct = {d["name"] for d in root["dependencies"]}
lines = ["# 锁定依赖许可清单", "", "由 `python3 -I tools/dependency_report.py --output docs/dependency-baseline.md` 从 Cargo.lock 对应元数据生成。", "", "包含全部目标平台和开发依赖，不代表它们都链接到每个发布产物。SPDX 来自包元数据，非完整法律审计；分发时需保留选用许可及相关声明。项目自身 `publish=false`、许可证为 GPL-3.0-only。未移植Xray/sing-box/Nowhere实现代码；MIT Shadowsocks协议依赖的本地缓存/严格校验/操作预算补丁及来源见 vendor/shadowsocks/PATCH.md 和 UPSTREAM.json，原许可原样保留。", "", "工具链：`rust-toolchain.toml` 固定 Rust 1.91.0；声明 MSRV " + root["rust_version"] + "，依赖解析按该版本约束。声明门槛不等于实际构建验证，具体平台/MSRV结果见对应验收报告；Shadowsocks组合已用Linux ARM64精确Rust1.91.0及1.91.1分别执行all-targets check（含AWS-LC原生编译），编译检查不等于该工具链全部运行测试；各平台结果见shadowsocks-acceptance.md。", "", "直接库选择：Tokio、Serde、rustls/ring、Hickory 0.26、SHA-2/subtle及Shadowsocks协议层。后者显式关闭默认features，只启用AEAD2017/2022和本地UDP缓存禁用feature，新增AWS-LC不替换TLS的ring。workspace全量元数据包含可选/开发/跨平台包，不代表生产启用它们；以 cargo tree -p dubhe -e features 的实际特性树为准。依赖公告门禁见 deny.toml 与 tools/supply-chain.sh；仍需独立做漏洞和更新审查。", "", "| 包 | 版本 | 类别 | 声明许可 | 声明 Rust 版本 |", "|---|---|---|---|---|"]
for package in sorted(data["packages"], key=lambda p: (p["name"], p["version"])):
    kind = "项目" if package["id"] == root["id"] else "直接（含开发）" if package["name"] in direct else "传递"
    lines.append(f'| {package["name"]} | {package["version"]} | {kind} | {package.get("license") or "未指定"} | {package.get("rust_version") or "未声明"} |')
lines += ["", "首批协议依据：[SOCKS5 RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)、[用户名密码 RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)、[Trojan 协议说明](https://trojan-gfw.github.io/trojan/protocol)。上游固定提交另见 `reference-clients.md`。", ""]
args.output.write_text("\n".join(lines))
print(f"Recorded {len(data['packages'])} packages to {args.output}")
