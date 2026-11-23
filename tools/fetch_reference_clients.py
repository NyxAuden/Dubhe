#!/usr/bin/env python3
"""Fetch pinned official clients for this platform; execute only version commands.

Run with python3 -I tools/fetch_reference_clients.py from the project directory.
Archives and extraction destinations each get a separate new, empty directory.
"""

import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / ".test-artifacts"
API = "https://api.github.com"
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_EXTRACTED = 512 * 1024 * 1024
# Mihomo was resolved from /releases/latest on 2026-11-04, then pinned here.
# 资源文件名按平台展开：`{platform}` 由 detect_platform() 给出。
CLIENTS = (
    ("mihomo", "MetaCubeX/mihomo", "v1.19.33", "mihomo-{platform}-v1.19.33.gz", "mihomo", "-v"),
    ("sing-box", "SagerNet/sing-box", "v1.14.4", "sing-box-1.14.4-{platform}.tar.gz", "sing-box", "version"),
    ("xray", "XTLS/Xray-core", "v26.10.31", "Xray-{xray_platform}.zip", "xray", "version"),
)

# 上游对同一平台的命名不一致：sing-box 用 linux-amd64，Xray 用 linux-64。
PLATFORM_NAMES = {
    ("Darwin", "arm64"): ("darwin-arm64", "macos-arm64-v8a"),
    ("Darwin", "x86_64"): ("darwin-amd64", "macos-64"),
    ("Linux", "x86_64"): ("linux-amd64", "linux-64"),
    ("Linux", "aarch64"): ("linux-arm64", "linux-arm64-v8a"),
}


def detect_platform():
    """返回 `(平台标识, {占位符: 值})`，不认识时明确失败。"""
    key = (platform.system(), platform.machine())
    try:
        sing_box_name, xray_name = PLATFORM_NAMES[key]
    except KeyError:
        supported = ", ".join(f"{system}/{machine}" for system, machine in PLATFORM_NAMES)
        raise SystemExit(
            f"不支持的平台 {key[0]}/{key[1]}；已钉住的上游资源只覆盖: {supported}"
        )
    # 规范化标签必须与 Rust 侧 `platform_tag()` 完全一致：
    # `macos`→`darwin`，`aarch64`→`arm64`，`x86_64` 保持。
    # 不能直接用 `platform.machine()`（Linux ARM64 上它是 `aarch64`）。
    os_name = "darwin" if key[0] == "Darwin" else key[0].lower()
    arch = "arm64" if key[1] == "aarch64" else key[1]
    return f"{os_name}-{arch}", {
        "platform": sing_box_name,
        "xray_platform": xray_name,
    }


def api_json(url):
    if not url.startswith(API + "/repos/"):
        raise ValueError("Unexpected API URL")
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "dubhe-reference-client-fetcher",
    })
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("API response too large")
    return json.loads(data)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_limited(source, destination, limit):
    written = 0
    with destination.open("xb") as output:
        while chunk := source.read(1024 * 1024):
            written += len(chunk)
            if written > limit:
                raise ValueError("File exceeds size limit")
            output.write(chunk)
    return written


def download(asset, repo, tag, run_dir):
    name = asset["name"]
    if Path(name).name != name or "\\" in name:
        raise ValueError("Invalid release asset filename")
    expected = f"https://github.com/{repo}/releases/download/{tag}/{name}"
    if asset["browser_download_url"] != expected:
        raise ValueError("Asset URL is not in the official release")
    directory = Path(tempfile.mkdtemp(prefix="download-", dir=run_dir))
    path = directory / name
    # curl permits HTTPS redirects only; the output directory contains this file alone.
    subprocess.run([
        "curl", "--fail", "--location", "--silent", "--show-error",
        "--proto", "=https", "--proto-redir", "=https",
        "--connect-timeout", "20", "--max-time", "240",
        "--max-filesize", str(MAX_ARCHIVE), "--output", str(path), expected,
    ], cwd=ROOT, check=True, timeout=250)
    if path.stat().st_size != asset["size"] or path.stat().st_size > MAX_ARCHIVE:
        raise ValueError("Downloaded size does not match release metadata")
    digest = sha256(path)
    upstream = asset.get("digest")
    if upstream and not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", upstream):
        raise ValueError("Unsupported or malformed upstream digest")
    if upstream and digest != upstream.split(":", 1)[1].lower():
        raise ValueError("Official GitHub release asset SHA-256 mismatch")
    return path, digest, bool(upstream)


def member_target(name, directory):
    # Reject traversal, absolute/Windows paths, and ambiguous separators before normalization.
    if (not name or "\x00" in name or "\\" in name or name.startswith("/")
            or PureWindowsPath(name).drive or ".." in name.split("/")):
        raise ValueError(f"Unsafe archive path: {name!r}")
    parts = PurePosixPath(name).parts
    if not parts:
        raise ValueError("Empty archive member path")
    target = directory.joinpath(*parts)
    if not target.resolve().is_relative_to(directory.resolve()):
        raise ValueError("Archive path escapes extraction directory")
    return target


def validate_members(members, directory):
    seen = set()
    total = 0
    for name, size, kind in members:
        target = member_target(name, directory)
        if kind not in ("file", "directory"):
            raise ValueError(f"Links and special files are forbidden: {name!r}")
        # Also reject case-insensitive collisions on common macOS filesystems.
        key = str(target).casefold()
        if key in seen:
            raise ValueError(f"Duplicate archive path: {name!r}")
        seen.add(key)
        total += size
        if size < 0 or total > MAX_EXTRACTED or len(seen) > 10000:
            raise ValueError("Archive exceeds extraction limits")


def extract_binary(archive, executable, run_dir):
    directory = Path(tempfile.mkdtemp(prefix="extracted-", dir=run_dir))
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as bundle:
            entries = bundle.getmembers()
            validate_members([
                (entry.name, entry.size, "file" if entry.isfile() else
                 "directory" if entry.isdir() else "forbidden")
                for entry in entries
            ], directory)
            for entry in entries:
                target = member_target(entry.name, directory)
                if entry.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.extractfile(entry) as stream:
                        copy_limited(stream, target, entry.size)
    elif archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            descriptions = []
            for entry in entries:
                mode = entry.external_attr >> 16
                kind = "directory" if entry.is_dir() else "file"
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    kind = "forbidden"
                descriptions.append((entry.filename, entry.file_size, kind))
            validate_members(descriptions, directory)
            for entry in entries:
                target = member_target(entry.filename, directory)
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(entry) as stream:
                        copy_limited(stream, target, entry.file_size)
    elif archive.name.endswith(".gz"):
        # Ignore the optional gzip filename; write only the known executable name.
        with gzip.open(archive, "rb") as stream:
            copy_limited(stream, directory / executable, MAX_EXTRACTED)
    else:
        raise ValueError("Unsupported archive format")
    candidates = [path for path in directory.rglob(executable) if path.is_file()]
    if len(candidates) != 1:
        raise ValueError("Expected exactly one client executable")
    binary = candidates[0]
    # 在执行任何东西之前校验格式与本机架构匹配，避免把一个错误平台的二进制
    # 跑起来（历史上只有 Mach-O 校验，Linux 上会直接失败）。
    verify_executable(binary)
    binary.chmod(0o700)
    return binary


def verify_executable(binary):
    """确认是当前平台的本地可执行文件；不认识就失败，不猜。"""
    with binary.open("rb") as stream:
        header = stream.read(20)
    machine = platform.machine()
    if platform.system() == "Darwin":
        # little-endian 64-bit Mach-O：magic, cputype, cpusubtype, filetype
        if len(header) < 16:
            raise ValueError("Binary is too short to be a Mach-O executable")
        magic, cpu_type, _, file_type = struct.unpack("<IIII", header[:16])
        if magic != 0xFEEDFACF:
            raise ValueError("Binary is not a 64-bit little-endian Mach-O executable")
        if file_type != 2:
            raise ValueError("Mach-O is not an executable")
        expected = {"arm64": 0x0100000C, "x86_64": 0x01000007}
        if cpu_type != expected[machine]:
            raise ValueError(f"Mach-O architecture does not match {machine}")
        return
    if platform.system() == "Linux":
        # ELF64: 7f 45 4c 46, class 2, data 1 (little-endian)
        if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
            raise ValueError("Binary is not a 64-bit little-endian ELF executable")
        # e_type 在偏移 16（2 字节）应为 ET_EXEC(2) 或 ET_DYN(3，PIE)。
        e_type = struct.unpack("<H", header[16:18])[0]
        if e_type not in (2, 3):
            raise ValueError("ELF is not an executable")
        # e_machine 在偏移 18：x86_64=62, aarch64=183
        e_machine = struct.unpack("<H", header[18:20])[0]
        expected = {"x86_64": 62, "aarch64": 183}
        if e_machine != expected[machine]:
            raise ValueError(f"ELF architecture does not match {machine}")
        return
    raise ValueError(f"Unsupported platform for executable verification: {platform.system()}")


def tag_commit(repo, tag):
    url = f"{API}/repos/{repo}/git/ref/tags/{urllib.parse.quote(tag, safe='')}"
    obj = api_json(url)["object"]
    for _ in range(5):
        if obj["type"] == "commit":
            if not re.fullmatch(r"[0-9a-f]{40}", obj["sha"]):
                raise ValueError("Invalid commit SHA")
            return obj["sha"], url
        if obj["type"] != "tag":
            break
        obj = api_json(f"{API}/repos/{repo}/git/tags/{obj['sha']}")["object"]
    raise ValueError("Tag did not resolve to a commit")


def prepare_client(spec, run_dir, platform_names, platform_label):
    name, repo, version, asset_name, executable, version_arg = spec
    asset_name = asset_name.format(**platform_names)
    print(f"{name}: querying official release {version}", flush=True)
    release_url = f"{API}/repos/{repo}/releases/tags/{version}"
    release = api_json(release_url)
    if release["tag_name"] != version or release["draft"] or release["prerelease"]:
        raise ValueError("Release is not the pinned stable version")
    assets = [asset for asset in release["assets"] if asset["name"] == asset_name]
    if len(assets) != 1:
        raise ValueError(f"Official asset not found: {asset_name}")
    commit, ref_url = tag_commit(repo, version)
    asset = assets[0]
    print(f"{name}: downloading {asset_name}", flush=True)
    archive, archive_sha256, verified = download(asset, repo, version, run_dir)
    binary = extract_binary(archive, executable, run_dir)
    binary_sha256 = sha256(binary)
    # Do not inherit proxy/config/plugin variables or execute from an extraction directory.
    version_home = Path(tempfile.mkdtemp(prefix="version-home-", dir=run_dir))
    environment = {
        "PATH": "/usr/bin:/bin", "HOME": str(version_home),
        "XDG_CONFIG_HOME": str(version_home), "XDG_CACHE_HOME": str(version_home),
        "TMPDIR": str(version_home), "LANG": "C", "LC_ALL": "C",
    }
    command = [str(binary), version_arg]
    result = subprocess.run(command, cwd=ROOT, env=environment,
                            capture_output=True, text=True, timeout=15, check=True)
    output = (result.stdout + result.stderr).strip()
    patterns = {
        "mihomo": rf"(?im)^Mihomo Meta {re.escape(version)}(?:\s|$)",
        "sing-box": rf"(?im)^sing-box version {re.escape(version.removeprefix('v'))}(?:\s|$)",
        "xray": rf"(?im)^Xray {re.escape(version.removeprefix('v'))}(?:\s|$)",
    }
    if not re.search(patterns[name], output):
        raise ValueError(f"Unexpected version output: {output!r}")
    if sha256(binary) != binary_sha256:
        raise ValueError("Binary changed during version verification")
    print(f"{name}: verified {output.splitlines()[0]}", flush=True)
    return {
        "name": name, "path": str(binary), "version": version,
        # 与 `detect_platform()` 的规范化名字一致（`arm64` 而非 `aarch64`），
        # 否则 Linux ARM64 上 manifest 写 `linux-aarch64` 而测试侧期望
        # `linux-arm64`，会报平台不匹配。
        "platform": platform_label,
        "source": asset["browser_download_url"],
        "release_url": release["html_url"], "release_api_url": release_url,
        "release_published_at": release["published_at"],
        "tag_commit": commit, "tag_ref_api_url": ref_url,
        "sha256": binary_sha256, "archive_path": str(archive),
        "archive_sha256": archive_sha256, "upstream_digest": asset.get("digest"),
        "upstream_checksum_verified": verified,
        "upstream_checksum_scope": "archive",
        "upstream_checksum_method": "GitHub release asset API SHA-256" if verified else "local SHA-256 only",
        "signature_verified": False,
        "checksum_note": "API digest verifies archive integrity; it is not a publisher signature. Binary SHA-256 is computed locally after extraction."
                         if verified else "No API digest available; local SHA-256 does not establish official authenticity or signature verification.",
        "version_command": command, "version_output": output,
        "version_exit_code": result.returncode, "status": "ready",
    }


def main():
    if not sys.flags.isolated:
        raise SystemExit("Run this script with python3 -I")
    platform_label, platform_names = detect_platform()
    ARTIFACTS.mkdir(exist_ok=True)
    storage = ARTIFACTS / "reference-clients"
    storage.mkdir(exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=storage))
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform_label, "run_directory": str(run_dir),
        "execution_scope": "version commands only; no proxy listener, service installation, or system proxy changes",
        "mihomo_selection": "v1.19.33 was latest stable on 2026-11-04; pinned for this run",
        "clients": [],
    }
    for spec in CLIENTS:
        try:
            manifest["clients"].append(
                prepare_client(spec, run_dir, platform_names, platform_label)
            )
        except Exception as error:
            manifest["clients"].append({
                "name": spec[0], "version": spec[2], "path": None,
                "source": f"https://github.com/{spec[1]}/releases/tag/{spec[2]}",
                "sha256": None, "upstream_checksum_verified": False,
                "status": "blocked", "error": str(error),
            })
            print(f"{spec[0]}: BLOCKED: {error}", file=sys.stderr, flush=True)
    manifest_path = ARTIFACTS / "reference-clients.json"
    temporary = run_dir / "manifest.json"
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    os.replace(temporary, manifest_path)
    print(f"Manifest: {manifest_path}", flush=True)
    return int(any(client["status"] != "ready" for client in manifest["clients"]))


if __name__ == "__main__":
    raise SystemExit(main())
