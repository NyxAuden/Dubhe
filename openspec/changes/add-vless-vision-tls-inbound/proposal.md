## Why

现有VLESS入口仅接受空addons，无法服务使用`xtls-rprx-vision`的现有客户端。Vision还要求精确保全TLS记录边界和上下行独立切换，需在继续扩展传输前解决，不能用普通TLS流包装冒充支持。

## What Changes

- 为现有VLESS用户增加缺省为空的显式flow选择，仅新增`xtls-rprx-vision`；保持无flow用户、基础UDP及已实现XUDP旧配置兼容。认证、请求flow、命令及实际TLS版本共同决定准入，不静默去掉flow。
- 在标准TCP + TLS 1.3上原生实现Vision入站，覆盖身份前缀、Continue/End/Direct、padding和内容边界，以及按方向独立结束padding/切换原始流。使用现有成熟TLS与随机数实现，不复制参考内核或其他项目的实现代码。
- 为Vision连接提供从握手开始受控的TLS记录输入和唯一IO所有权，避免Direct之后的原始字节被外层TLS提前消费；完整处理部分读写、背压、控制消息、半关闭及取消。
- 复用路由、DNS、TCP连接/握手许可、明文计量和停机。按固定上游的flow/命令语义接入可用UDP/XUDP路径，不把Vision TCP通过扩大成UDP通过，也不增加通用TCP mux。
- 按用户2026-11-05确认的方式推进：开发时执行编译、独立报文、认证/数据边界及资源回收的必要测试；完整三平台回归、三家官方客户端矩阵与交付报告集中在后续能力簇收尾执行。未执行的验收保留未完成，不阻止开始下一个已规划模块，也不提前声称兼容。

## Capabilities

### New Capabilities

- `vless-vision-inbound`：标准TLS 1.3上的Vision用户配置、请求准入、双向流状态、TCP及UDP/XUDP边界、有限资源和分层验证证据。

### Modified Capabilities

无。现有基础VLESS规格仍保留在未归档的`add-vless-tls-inbound`变更，不改写其历史验收。新规格在显式配置Vision用户时扩展行为；原无flow契约继续回归。

## Impact

涉及`config`的VLESS用户模型、`protocol/vless`握手、专用Vision状态机与TLS承载、`runtime`分派、共享转发/UDP适配点、示例及参考测试。优先保持锁定的rustls 0.23.46 / tokio-rustls 0.26.6和ring后端，不预设依赖fork或换密码后端；若实验证明现有API不满足，先记录具体失败与补丁范围，不能暗中降低Direct语义。

本批不含REALITY、VLESS Encryption、WS/gRPC/XHTTP、历史XTLS flow、平台splice或客户端产品；它们按后续独立批次推进，不缩减长期目标。首版用户态复制必须线协议正确，不能用“未优化”掩盖不切换原始流。当前宿主空间约47GiB，Colima未运行且Docker socket不存在；本机开发可继续，Linux最终验收前需核实/恢复隔离环境，不能把历史平台结果当新构建通过。不启动/重建/删除容器，不改全局context或系统网络，不Git、不归档、不发布。当前仅建立规划，不代表已实现或获准运行新的官方客户端矩阵。
