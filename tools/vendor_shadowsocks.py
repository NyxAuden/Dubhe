#!/usr/bin/env python3
"""从已核验发布来源建立vendor，或生成/验证最小补丁；不执行发布包代码。"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "vendor/shadowsocks"
EXPECTED = {"shadowsocks": "e2065b026dbe4f47048eca384adf07f693bf901050d80abd3adb7b2422709b2d", "shadowsocks-crypto": "b404a62ebea5003f44b9a2748dee7555c5f9ae39896508e466a2a91ee6fa5df5"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--diff", action="store_true")
    args = parser.parse_args()
    data = json.loads(args.manifest.read_text())
    packages = {p["name"]: p for p in data["packages"]}
    for name, checksum in EXPECTED.items():
        item = packages[name]
        if item["sha256"] != checksum or digest(ROOT / item["archive"]) != checksum:
            raise ValueError("发布来源不符合固定摘要")
    original = ROOT / packages["shadowsocks"]["source"]
    if not args.diff:
        DEST.parent.mkdir(exist_ok=True)
        shutil.copytree(original, DEST)  # 目的目录必须不存在。
        records = []
        for item in packages.values():
            records.append({k: item[k] for k in ("name", "version", "sha256", "archive_url", "index_url", "vcs")})
        provenance = {"modified": True, "purpose": "禁用2022 UDP派生密码缓存、严格2022 TCP变量头校验及每方向固定AEAD操作预算；补丁见upstream.patch", "packages": records,
                      "original_files": {str(p.relative_to(original)): digest(p) for p in sorted(original.rglob("*")) if p.is_file()}}
        (DEST / "UPSTREAM.json").write_text(json.dumps(provenance, ensure_ascii=False, indent=2) + "\n")
        print("已创建 vendor/shadowsocks，保留发布包全部文件及MIT许可")
        return
    changes = []
    provenance = json.loads((DEST / "UPSTREAM.json").read_text())
    for relative, checksum in provenance["original_files"].items():
        upstream = original / relative
        if digest(upstream) != checksum:
            raise ValueError(f"原始解包文件改变: {relative}")
        modified = DEST / relative
        if digest(modified) != checksum:
            changes.extend(difflib.unified_diff(upstream.read_text().splitlines(True), modified.read_text().splitlines(True),
                                                fromfile=f"a/{relative}", tofile=f"b/{relative}"))
    known = set(provenance["original_files"]) | {"UPSTREAM.json", "PATCH.md", "upstream.patch"}
    for path in sorted(DEST.rglob("*")):
        if path.is_file() and str(path.relative_to(DEST)) not in known:
            relative = str(path.relative_to(DEST))
            changes.extend(difflib.unified_diff([], path.read_text().splitlines(True), fromfile="/dev/null", tofile=f"b/{relative}"))
    patch = "".join(changes)
    (DEST / "upstream.patch").write_text(patch)
    print(f"已生成可复现diff: {len(patch.splitlines())}行，SHA256={digest(DEST / 'upstream.patch')}")


if __name__ == "__main__":
    main()
