# SBOM 记录

本文件记录本地生成的 CycloneDX SBOM，不代表已发布或已签名。

## 2026-11-14

- 工具：`cargo-cyclonedx 0.5.10`
- 格式：CycloneDX 1.3 JSON
- 文件：`dist/sbom.cdx.json`（gitignored，本地产物）
- 大小：约 375 KiB
- 组件数：312
- SHA-256：`2132b10548aa2cc8b99fb2e270e6629530db9e3f04fab52e85690a59c9446be7`
- 状态：本地生成，未签名、未随正式发布上传

生成命令：

```sh
cargo cyclonedx --format json --override-filename sbom
mv sbom.json dist/sbom.cdx.json
rm -f vendor/shadowsocks/sbom.json
```

`cargo-cyclonedx` 会对 workspace 成员分别生成文件；本记录只保留根包
`dubhe` 的结果。SBOM 反映当前 `Cargo.lock`，不替代许可证法律审查、
漏洞扫描或构建产物签名。

发布脚本 `tools/release.sh` 已改为在打包前生成 SBOM，并把它放入 tarball；如果未安装
`cargo-cyclonedx`，脚本会提示并继续生成不含 SBOM 的包，这种包不能作为正式发布产物。
