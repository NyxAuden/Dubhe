# 可复现构建记录

本记录只证明：在固定源码、工具链和平台上，用固定环境变量在两个全新 target 目录中
构建出的 release 二进制逐字节一致。它不证明跨操作系统、跨架构或跨工具链可复现。

## 2026-11-14 验证

- 平台：macOS ARM64
- 工具链：`rust-toolchain.toml` 固定 Rust 1.91.0，`--locked`
- 环境：`SOURCE_DATE_EPOCH=1700000000`、`CARGO_INCREMENTAL=0`
- RUSTFLAGS：`--remap-path-prefix=<项目绝对路径>=/build`
- 构建目录：两个独立的全新临时 target 目录
- 产物大小：30,138,800 字节
- 两次 SHA-256 均为：
  `b5a1db63f86b3cde2615258cb3c00f34410056d35536ff742c67b6a2fdb13e3f`
- `cmp` 结果为逐字节相同。

复现命令：

```sh
SOURCE_DATE_EPOCH=1700000000 tools/repro-check.sh
```

脚本使用固定的 `/tmp/rpk-repro-a`、`/tmp/rpk-repro-b` 两个干净 target 目录（可用
`REPRO_TARGET_A`/`REPRO_TARGET_B` 覆盖），构建后比较 SHA-256，结束时删除目录。
`target/release/dubhe` 的当前记录产物已用同一次干净构建的二进制替换，因此其
SHA-256 与上述值一致。

## 2026-11-14 本地打包验证

使用 `SOURCE_DATE_EPOCH=1700000000 tools/release.sh` 在 `/tmp/rpk-repro-a` 干净 target
目录构建并打包：

- `dist/dubhe-0.1.0-darwin-arm64.tar.gz`
- 大小约 11.6 MiB
- SHA-256：`15632029f874e529f3f9620eb9931e5209ce326a9274ebf34919ca05ccd55b94`
- tarball 包含：二进制、LICENSE、THIRD-PARTY、README、systemd unit、`sbom.cdx.json`
- 二进制 SHA-256：`b5a1db63f86b3cde2615258cb3c00f34410056d35536ff742c67b6a2fdb13e3f`
- 未签名、未上传；`dist/` 为本地 gitignored 产物。

## 注意

- 在已有 `target/` 上直接重建可能复用旧指纹/构建脚本输出，得到不同字节；可复现验证必须
  使用干净 target 目录。
- 实测不同 target 绝对路径前缀可能改变产物字节；本记录只证明固定 `/tmp/rpk-repro-a|b`
  布局下的一致，尚未证明任意构建目录/前缀下的路径无关可复现性。
- 该结果不覆盖 Linux x86_64、Linux ARM64、Windows 或不同 Rust 版本；这些平台仍需在原生
  环境重复验证。
- 发布仍需生成 SBOM、签名和校验和；可复现构建不等于安全审计或发布批准。
