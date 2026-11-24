#!/usr/bin/env python3
"""用真实客户端内核校验 `dubhe export` 生成的配置能被加载。

只调用各客户端的配置检查命令，不启动代理、不建立网络连接：
  xray run -test -c <file>
  sing-box check -c <file>
  mihomo -t -d <dir> -f <file>

用法（从项目根目录）：
  python3 -I tools/verify_export.py <export-dir>

依赖 `.test-artifacts/reference-clients/` 下已下载的固定版本客户端，
见 tools/fetch_reference_clients.py。
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENTS = ROOT / ".test-artifacts" / "reference-clients"

# 目标格式 -> (可执行文件名, 参数模板)
#
# mihomo 需要一个可写的 home 目录；用临时目录避免读用户配置。
CHECKS = {
    "xray-client.json": ("xray", ["run", "-test", "-c", "{file}"]),
    "sing-box-client.json": ("sing-box", ["check", "-c", "{file}"]),
    "mihomo-client.json": ("mihomo", ["-t", "-d", "{home}", "-f", "{file}"]),
}


def find_binary(name):
    for candidate in CLIENTS.rglob(name):
        if candidate.is_file() and candidate.stat().st_mode & 0o111:
            return candidate
    return None


def main():
    if len(sys.argv) != 2:
        print("用法: python3 -I tools/verify_export.py <export-dir>", file=sys.stderr)
        return 2
    export_dir = Path(sys.argv[1]).resolve()
    if not export_dir.is_dir():
        print(f"导出目录不存在: {export_dir}", file=sys.stderr)
        return 2

    failed = 0
    skipped = 0
    checked = 0
    for filename, (binary_name, args) in CHECKS.items():
        path = export_dir / filename
        if not path.is_file():
            print(f"跳过 {filename}：文件不存在")
            skipped += 1
            continue
        binary = find_binary(binary_name)
        if binary is None:
            print(f"跳过 {filename}：未找到 {binary_name}（先运行 tools/fetch_reference_clients.py）")
            skipped += 1
            continue
        home = export_dir / f".{binary_name}-home"
        home.mkdir(exist_ok=True)
        command = [str(binary)] + [
            arg.format(file=str(path), home=str(home)) for arg in args
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        checked += 1
        if result.returncode == 0:
            print(f"通过 {filename}（{binary_name}）")
        else:
            failed += 1
            print(f"失败 {filename}（{binary_name}）返回 {result.returncode}")
            output = (result.stdout + result.stderr).strip()
            for line in output.splitlines()[:20]:
                print(f"    {line}")

    print()
    print(f"结果：失败 {failed}，执行 {checked}，跳过 {skipped}")
    if failed:
        return 1
    if checked == 0:
        # 空目录或缺少全部客户端时，退出码不能让调用方以为校验通过。
        print("没有执行任何检查；请先导出配置或安装参考客户端", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
