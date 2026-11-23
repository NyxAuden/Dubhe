#!/usr/bin/env bash
# 下载真实地理数据集，供 tests/geo_routing.rs 的真实数据用例使用。
#
# 这些文件**不进仓库**（.test-artifacts/ 已 gitignore）：数据每周在变，
# 且本项目不为第三方列表的正确性背书。缺文件时相关用例会打印「跳过」，
# 不会静默通过。
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="$root/.test-artifacts/geodata"
mkdir -p "$target"
cd "$target"

fetch() {
    local name="$1" url="$2"
    if [ -s "$name" ]; then
        echo "已存在，跳过: $name"
        return
    fi
    echo "下载 $name"
    curl -fsSL --retry 3 -o "$name.part" "$url"
    mv "$name.part" "$name"
}

# 版本**钉死**，不用 latest：数据每周在变，latest 会让 CI 随机失败，
# 也让「这次的结果」无法复现。要更新数据时改这两个变量并重跑全部用例。
V2RAY_RULES_TAG="${V2RAY_RULES_TAG:-202611222203}"
MAXMIND_GEOIP_TAG="${MAXMIND_GEOIP_TAG:-20261112}"

# Xray / Mihomo 格式（protobuf）
fetch geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${V2RAY_RULES_TAG}/geosite.dat"
fetch geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${V2RAY_RULES_TAG}/geoip.dat"
# MaxMind 格式（Mihomo 的 country.mmdb）
fetch Country.mmdb "https://github.com/Dreamacro/maxmind-geoip/releases/download/${MAXMIND_GEOIP_TAG}/Country.mmdb"

ls -lh "$target"/geosite.dat "$target"/geoip.dat "$target"/Country.mmdb
echo
echo "完成。运行真实数据用例："
echo "  cargo test --test geo_routing"
