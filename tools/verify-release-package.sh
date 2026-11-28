#!/usr/bin/env bash
# Run from the packaging directory on the matching native runner, before upload.
set -euo pipefail
export LC_ALL=C
name=${1:?package basename}
expected=${2:?build SHA-256}
asset=${3:?matrix asset}
[[ $expected =~ ^[0-9a-f]{64}$ ]]
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Compare the entire manifest, so checking a checksum for the wrong file fails.
shasum -a 256 "$name.tar.gz" > "$tmp/archive.sha256"
cmp "$tmp/archive.sha256" "$name.tar.gz.sha256"
tar -xzf "$name.tar.gz" -C "$tmp"
cd "$tmp/$name"
printf '%s  dubhe\n' "$expected" > "$tmp/built.sha256"
cmp "$tmp/built.sha256" dubhe.sha256
shasum -a 256 -c dubhe.sha256

if [[ $asset == linux-x86_64-musl ]]; then
    readelf -hW dubhe > "$tmp/header"
    readelf -lW dubhe > "$tmp/program"
    readelf -dW dubhe > "$tmp/dynamic"
    grep -Eq 'Class:[[:space:]]+ELF64$' "$tmp/header"
    grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64$' "$tmp/header"
    if grep -E '^[[:space:]]*INTERP[[:space:]]' "$tmp/program" || grep -F '(NEEDED)' "$tmp/dynamic"; then
        echo 'release package contains a dynamically linked ELF' >&2
        exit 1
    fi
fi
./dubhe version
./dubhe check -c examples/socks5.json
