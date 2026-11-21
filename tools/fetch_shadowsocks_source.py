#!/usr/bin/env python3
"""核验固定依赖发布包；只解包普通文件，不执行下载代码。用 python3 -I 运行。"""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (
    ("shadowsocks", "1.25.0", "e2065b026dbe4f47048eca384adf07f693bf901050d80abd3adb7b2422709b2d", "ab388c7466d21f979430e33cc9ef10e22fb05955"),
    ("shadowsocks-crypto", "0.8.0", "b404a62ebea5003f44b9a2748dee7555c5f9ae39896508e466a2a91ee6fa5df5", "2ac3f4f6194476ff7b7be2a43c3a83e33510663b"),
)


def fetch(url):
    request = Request(url, headers={"User-Agent": "dubhe-dependency-audit/0.1"})
    with urlopen(request, timeout=60) as response:
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024:
        raise ValueError("下载超出固定上限")
    return data


def main():
    artifacts = ROOT / ".test-artifacts"
    run = Path(tempfile.mkdtemp(prefix="ss-source-", dir=artifacts))
    results = []
    for name, version, expected, commit in PACKAGES:
        # 归档与解包各用一个新的空目录；不在其中启动解释器或构建工具。
        download = Path(tempfile.mkdtemp(prefix=f"{name}-archive-", dir=run))
        extracted = Path(tempfile.mkdtemp(prefix=f"{name}-extracted-", dir=run))
        index_url = f"https://index.crates.io/{name[:2]}/{name[2:4]}/{name}"
        entries = [json.loads(line) for line in fetch(index_url).splitlines()]
        entry, = [item for item in entries if item["vers"] == version]
        if entry["cksum"] != expected or entry.get("yanked"):
            raise ValueError(f"{name}: 索引摘要或发布状态不符合固定基线")
        url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
        data = fetch(url)
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise ValueError(f"{name}: 发布包摘要不一致")
        archive_path = download / f"{name}-{version}.crate"
        archive_path.write_bytes(data)
        prefix = f"{name}-{version}"
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = archive.getmembers()
            if sum(member.size for member in members) > 64 * 1024 * 1024:
                raise ValueError("归档展开超出上限")
            seen = set()
            for member in members:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or ".." in path.parts or not path.parts
                        or path.parts[0] != prefix or path in seen):
                    raise ValueError("归档含不安全路径或重复条目")
                seen.add(path)
                target = extracted.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(member) as source, target.open("xb") as output:
                        output.write(source.read())
                    target.chmod(0o644)
                else:
                    raise ValueError("归档只允许普通文件和目录")
        source = extracted / prefix
        vcs = json.loads((source / ".cargo_vcs_info.json").read_text())
        if vcs["git"]["sha1"] != commit or vcs["git"].get("dirty", False):
            raise ValueError(f"{name}: 发布提交不符合基线")
        results.append({
            "name": name, "version": version, "sha256": digest,
            "registry_checksum_verified": True, "index_url": index_url,
            "archive_url": url, "archive": str(archive_path.relative_to(ROOT)),
            "source": str(source.relative_to(ROOT)), "vcs": vcs,
            "registry_entry": entry,
        })
    manifest = run / "manifest.json"
    manifest.write_text(json.dumps({"packages": results}, indent=2) + "\n")
    print(manifest.relative_to(ROOT))


if __name__ == "__main__":
    main()
