#!/usr/bin/env python3
"""复核精确官方归档、原始文件摘要和全部补丁；仅在指定新空目录展开。"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--archive", type=pathlib.Path, required=True)
parser.add_argument("--empty-dir", type=pathlib.Path, required=True)
args = parser.parse_args()
vendor = pathlib.Path(__file__).resolve().parent
metadata = json.loads((vendor / "UPSTREAM.json").read_text())
archive = args.archive.resolve()
if hashlib.sha256(archive.read_bytes()).hexdigest() != metadata["archive_sha256"]:
    raise RuntimeError("原始归档 SHA256 不匹配")
destination = args.empty_dir.resolve()
if destination.exists():
    if not destination.is_dir() or any(destination.iterdir()):
        raise RuntimeError("复现目录必须是全新空目录")
else:
    destination.mkdir(parents=True)
seen = set()
with tarfile.open(archive) as source:
    for member in source.getmembers():
        parts = pathlib.PurePosixPath(member.name).parts
        if not (member.isfile() or member.isdir()) or not parts or parts[0] != "rustls-0.23.46" or ".." in parts:
            raise RuntimeError("归档存在非常规文件或越界路径")
        relative = pathlib.Path(*parts[1:])
        path = destination / relative
        if member.isdir():
            path.mkdir(parents=True, exist_ok=True)
            continue
        content = source.extractfile(member).read()
        name = relative.as_posix()
        if hashlib.sha256(content).hexdigest() != metadata["original_files_sha256"].get(name):
            raise RuntimeError("原始文件摘要不匹配")
        if name in seen:
            raise RuntimeError("归档文件重复")
        seen.add(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
if seen != set(metadata["original_files_sha256"]):
    raise RuntimeError("归档文件列表不匹配")
manifest = json.loads((vendor / "PATCHED.json").read_text())
if hashlib.sha256((vendor / "upstream.patch").read_bytes()).hexdigest() != manifest["patch_sha256"]:
    raise RuntimeError("补丁 SHA256 不匹配")
subprocess.run(["patch", "--batch", "-p1", "-d", str(destination), "-i", str(vendor / "upstream.patch")], cwd=vendor.parent, check=True)
for name, expected in manifest["patched_files_sha256"].items():
    for root in (destination, vendor):
        path = root / name
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"受补丁文件摘要不匹配: {name}")
actual = {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()}
if actual != set(manifest["patched_files_sha256"]):
    raise RuntimeError("复现结果文件集合不匹配")
print(f"来源与补丁复现通过：{len(actual)} 个文件；归档 SHA256 {metadata['archive_sha256']}")
