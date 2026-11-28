#!/bin/bash
# 收集某批次编译产物，压缩待传。
# 用法: pack-batch.sh <tag>
set -u
tag="$1"
json="/tmp/art-$tag.jsonl"
out="/tmp/out-$tag"

rm -rf "$out"
mkdir -p "$out"

python3 - "$json" "$out" <<'PY'
import json, pathlib, shutil, sys
src, dest = sys.argv[1], pathlib.Path(sys.argv[2])
seen = set()
for line in open(src):
    try:
        m = json.loads(line)
    except Exception:
        continue
    if m.get("reason") != "compiler-artifact" or not m.get("executable"):
        continue
    name = m["target"]["name"]
    if name == "dubhe":
        continue  # 主程序单独传一次
    p = pathlib.Path(m["executable"])
    if not p.exists() or p.name in seen:
        continue
    seen.add(p.name)
    shutil.copy2(p, dest / p.name)
print(f"packed {len(seen)} executables into {dest}")
PY

du -sh "$out"
tar -czf "/tmp/batch-$tag.tar.gz" -C "$out" . 2>/dev/null
ls -lh "/tmp/batch-$tag.tar.gz" | awk '{print "compressed:", $5}'
sha256sum "/tmp/batch-$tag.tar.gz" | cut -d' ' -f1 > "/tmp/batch-$tag.sha256"
cat "/tmp/batch-$tag.sha256"
