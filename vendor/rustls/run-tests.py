#!/usr/bin/env python3
"""使用项目唯一 Cargo.lock 构建和执行 vendor TLS 定向测试，不修改 workspace。"""
import argparse
import json
import pathlib
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--root", type=pathlib.Path, required=True)
args = parser.parse_args()
root = args.root.resolve()
command = ["cargo", "build", "--manifest-path", str(root / "Cargo.toml"), "--locked", "--offline", "-p", "rustls", "-p", "rcgen@0.13.2", "-p", "ring", "--message-format=json"]
result = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, check=True)
libs = {}
all_libs = {}
for line in result.stdout.splitlines():
    item = json.loads(line)
    if item.get("reason") != "compiler-artifact":
        continue
    name = item["target"]["name"]
    for filename in item["filenames"]:
        if filename.endswith(".rlib"):
            all_libs[name] = filename
            if name in {"rustls", "rcgen", "ring"}:
                libs[name] = filename
if set(libs) != {"rustls", "rcgen", "ring"}:
    raise RuntimeError("缺少精确 Cargo 构建工件")
output = root / "target" / "vendor-rustls-tests"
output.mkdir(exist_ok=True)
command = ["rustc", "--edition=2021", "--test", str(root / "vendor/rustls/tests/reality.rs"), "-L", f"dependency={root / 'target/debug/deps'}", "-o", str(output / "reality")]
for name, filename in libs.items():
    command += ["--extern", f"{name}={filename}"]
subprocess.run(command, cwd=root, check=True)
subprocess.run([str(output / "reality"), "--nocapture"], cwd=root, check=True)
# 发布 crate 排除了上游 testdata，且不是 workspace member。因此额外用
# 同一锁解析的依赖直接验证 rustls feature 关闭的 ring/std/tls12 构建。
command = ["rustc", "--edition=2021", "--crate-name", "rustls", "--crate-type", "rlib", str(root / "vendor/rustls/src/lib.rs"), "-L", f"dependency={root / 'target/debug/deps'}", "-o", str(output / "librustls_no_reality.rlib")]
for feature in ("ring", "std", "tls12"):
    command += ["--cfg", f'feature="{feature}"']
for name in ("once_cell", "ring", "subtle", "zeroize"):
    command += ["--extern", f"{name}={all_libs[name]}"]
command += ["--extern", f"pki_types={all_libs['rustls_pki_types']}", "--extern", f"webpki={all_libs['webpki']}"]
subprocess.run(command, cwd=root, check=True)
