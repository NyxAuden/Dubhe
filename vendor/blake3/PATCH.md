# 本地补丁：blake3 1.8.7

基线：crates.io `blake3 1.8.7`（2026-08-20 发布，Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR CC0-1.0）。
仅保留构建所需内容（移除了 `.github/`、`benches/`、`tools/`、`media/`、`Cargo.lock`），源码与许可文件未改动。

## 修改内容

`src/hazmat.rs`：

- 新增 `pub fn hash_derive_key_context_bytes(context: &[u8]) -> ContextKey`，
  与上游 `hash_derive_key_context(&str)` 语义完全一致（同为
  `hash_all_at_once(context, IV, DERIVE_KEY_CONTEXT).root_hash()`），仅放宽入参为任意字节。
- `hash_derive_key_context(&str)` 改为委托上述函数，行为不变。

## 原因

Xray-core 的 VLESS Encryption 把随机 IV、握手中的 ML-KEM 密文、票据、以及重密钥时的整条记录字节
直接作为 BLAKE3 derive-key 上下文（Go 的 `string(ctx)` 可承载任意字节）。
Rust blake3 上游只提供 `&str` 上下文，无法无损表示这些字节；`from_utf8_unchecked`
属于未定义行为，自行实现 BLAKE3 压缩又违反“不自研密码原语”。

补丁只是把同样的内部调用暴露成字节入参，不改变算法、标志位或输出。

## 验证

`hash_derive_key_context_bytes(b"foo") == hash_derive_key_context("foo")` 且
`derive_key("foo", b"bar")` 与原函数输出一致（见项目内 `src/transport/vless_encryption.rs` 单测）。
