# 本地补丁：h3-datagram 0.0.2

基线：`vendor/h3-datagram`，版本 0.0.2，MIT。源码由项目固定 vendored，经
`[patch.crates-io]` 引入；本补丁不改变版本、许可、features、MSRV 或依赖。

## 修改内容

`src/datagram.rs` 的 `Datagram::encode`：

- 原实现把 `quarter-stream-ID` 的 varint 写入局部 `buffer`，却用
  `stream_id: [0; VarInt::MAX_SIZE]` 构造 `EncodedDatagram`，导致所有
  RFC 9297 HTTP Datagram 都以流 0 发送。
- 改为 `stream_id: buffer`，把已经编码好的 quarter-stream-ID 实际写入输出。
  流 0（quarter 0）的字节保持不变。

## 原因

RFC 9297 §2.1 的 Quarter Stream ID 必须标识请求流。该缺陷会使同一 QUIC
连接上的非零流数据报被错误归属到流 0；修复是协议编解码的一行纠正，不新增
协议扩展、不改 QUIC/密码原语。

## 验证

修复后的 h3-quinn `datagram` feature 编译通过；MASQUE 已按用户要求删除，
本补丁仅作为既有 h3-quinn/Hysteria2 数据报依赖修复保留，不再作为 MASQUE
能力或官方兼容证据。
