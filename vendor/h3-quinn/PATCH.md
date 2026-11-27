# 本地补丁：h3-quinn 0.0.10

基线：`vendor/h3-quinn`，版本 0.0.10，MIT。
本补丁不改变版本、许可、features、MSRV 或依赖。

## 修改内容

`src/lib.rs` 的 `RecvStream::stop_sending`：

- 原实现对 `self.stream.as_mut().unwrap()` 直接解引用。`poll_data` 在读取
  挂起时会把底层 `quinn::RecvStream` 移入 `read_chunk_fut`，`self.stream`
  暂时为 `None`；此时调用 `stop_sending`（例如取消挂起读取后再请求取消）
  会 panic。
- 改为仅在 `self.stream` 存在时发送 STOP_SENDING；读取 future 持有流时跳过。
  发送侧 `RESET_STREAM`/连接关闭仍按原路径终止请求。
- XHTTP 通过 `SendStream::stopped` / `BidiStream::stopped` 观察 Quinn 的
  `STOP_SENDING`，即使没有业务写入也能回收请求；正常 FIN 确认不取消上行。

## 原因

这是取消路径的健壮性缺陷，不涉及协议编解码或密码学。MASQUE 服务端在读取
挂起后进入错误/停机结束时会调用 `stop_sending`，该 panic 会中止请求任务；
客户端在取消响应等待后调用也会崩溃。

## 验证

`tests/masque_server/lifecycle.rs` 的慢准备/取消用例在挂起读取后调用
`stop_sending`，修复前 panic（`vendor/h3-quinn/src/lib.rs` Option unwrap），
修复后正常回收关联、端口与任务。全量回归见本批开发记录。
