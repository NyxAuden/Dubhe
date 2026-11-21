# VLESS Vision（开发实现，待集中验收）

本批原生实现标准 TCP + TLS 上的 `xtls-rprx-vision` 服务端与出站客户端；**当前已有本地验证、Xray v26.10.31 双向、Mihomo v1.19.33 与 sing-box v1.14.4 客户端 VLESS Vision 入站 TCP/UDP 有限互通，不代表三家官方客户端全矩阵或新构建三平台验收完成**。出站要求 `vless` 配置 `flow: "xtls-rprx-vision"`、`tls`、TLS 1.3，且不得与 `transport` 或 `encryption` 并用；本机 TLS 1.3 回环已通过。REALITY、VLESS Encryption、WS/gRPC/XHTTP、历史 XTLS flow 和 Linux splice 不在此批范围。固定研究来源与设计见 `openspec/changes/add-vless-vision-tls-inbound/design.md`。

## 配置

模板为 `examples/vless-vision.json`，默认仅监听回环。先替换随机标准 UUID 和证书链/私钥的绝对路径，再运行当前开发构建的 `check`。旧的 Shadowsocks release 是历史验收二进制，不包含本批 Vision，不能用旧二进制检查新字段。仓库不附带生产凭据。

```json
{
  "name": "vision-user",
  "uuid": "REPLACE_WITH_A_RANDOM_UUID_BEFORE_USE",
  "flow": "xtls-rprx-vision"
}
```

flow 在 `users[]` 内，不是入口字段。缺省或空字符串仍为普通 VLESS；唯一非空值为精确的 `xtls-rprx-vision`，null/未知类型和历史 flow 均拒绝。普通与 Vision 用户可同一监听共存，原普通用户 JSON 无需迁移。`xudp` 默认 true，可显式关闭；命令 3/`v1.mux.cool` 进入完整 Mux，TCP 会话始终允许，UDP New/GlobalID 默认准入，`xudp:false` 时关闭。GlobalID 跨承载 1 分钟续接已随 Mux 接入（已实现待集中验收）；Vision 包装保持既有双向 Continue/End/Direct 语义，见 [Mux 说明](mux.md)。UoT 已在 VLESS/VMess 接入，状态为“已实现待集中验收”，见[UoT 说明](uot.md)。

## 请求准入

| 用户 | 请求 flow | 命令 | 外层 TLS | 数据路径 |
|---|---|---|---|---|
| 普通 | 空 | TCP、原生 UDP、命令 3 Mux（TCP；`xudp` 门控 UDP） | 1.2/1.3 | 普通 TLS |
| 普通 | Vision | 任意 | 任意 | 拒绝 |
| Vision | Vision | 命令 3 Mux（TCP；`xudp` 门控 UDP） | 必须 1.3 | Vision body |
| Vision | Vision | 原生 UDP | 任意 | 拒绝 |
| Vision | 空 | TCP | 任意 | 拒绝 |
| Vision | 空 | 原生 UDP、命令 3 Mux（TCP；`xudp` 门控 UDP） | 1.2/1.3 | 普通 TLS 例外，无 Vision padding |

未知请求 flow、畸形/重复/未知 addons 拒绝。真正 Vision 的外层 TLS 必须 1.3；这不表示内部业务不能使用 TLS1.2。内层非 TLS/TLS1.2 走 End，仍保持外层 TLS；识别到允许套件的内层 TLS1.3 后，在完整 ApplicationData 记录边界发送 Direct。接收对端合法 Direct 不再强加本端内层识别门禁。

客户端策略不能混同服务端 wire：固定 Xray 的 `xtls-rprx-vision-udp443` 是客户端本地策略后缀，线上仍发送 `xtls-rprx-vision`，不能作为本内核用户 flow。服务端没有额外全局 UDP443 禁令，仍按路由处理。sing-box 显式空 `packet_encoding` 的原生 UDP 会清空请求 flow，属于表中普通 TLS 例外，不应称为 Vision padding UDP；客户端默认 XUDP/命令 3 则保留 Vision flow，此时 TCP Mux 与 `xudp` 门控的 UDP 都走 Vision body。

## 实现边界

- rustls/ring 执行 TLS 密码学，没有更换后端、依赖 fork、unsafe 私有字段访问或自研密码原语。
- 含 Vision 用户的监听从握手起使用单记录驱动；纯无 flow VLESS 与 Trojan 保留既有承载。上下行 Continue/End/Direct 独立，不因一向 Direct 自动切另一向。
- 完整消费 Direct 头、内容和 padding 后才切 raw，保留当前 TLS 明文尾部；最终 TLS 输出及 flush 屏障完成后才写 raw。raw 写方向不发送外层 close_notify；若后续 TLS 控制需要在该方向插入 TLS 记录，终止承载而非污染业务。
- 接收端流式处理 u16 全范围，发送块正文最多8171、总块最多8192字节；padding最大1399再受总块限制，不将参考发送策略当接收协议上限。
- 内层识别共享最多8条记录/65536业务字节预算，不解密内层 TLS；预算耗尽 End，不拒绝普通业务。首 UUID 明确不匹配时仅一次透明回退；部分匹配/半头/半帧 EOF 报截断。此策略不声称三家异常输入行为一致。
- 限额与回收使用既有 TCP/握手/UDP/字节预算和 stop→drain→force→join/children。计量沿用业务 `AsyncWrite::Ok(n)` 接受语义，不含 VLESS/Vision/TLS 开销；不是远端收讫或财务计费保证。

## 验证节奏

开发时做必要的配置/准入、wire、真实内层 TLS、记录交接、半关闭、背压与资源检查，随后可继续其他模块。已执行 Xray v26.10.31 双向、Mihomo v1.19.33 与 sing-box v1.14.4 客户端 VLESS Vision TCP/UDP 有限互通；完整 Vision 矩阵，以及新构建三平台全量、MSRV、release 与最终兼容报告，集中在能力簇收尾执行并独立记录。未执行项目保持未完成；旧209普通/33官方结果不能自动继承至本批源码。

### 2026-11-05 开发阶段结果

根package格式检查、locked/offline all-targets check、严格Clippy与OpenSpec严格校验均通过。本机macOS ARM64 Rust1.95的定向测试共 **106 passed、0 failed、0 ignored**，不是全量普通回归：配置22、VLESS wire18、Vision codec23、TLS10（含7项受控承载/适配回归和3项既有TLS测试）、拒绝先于本地DNS探针1、Vision运行器9、旧VLESS/XUDP/资源各7、CLI VLESS2。**2026-11-06 命令 3 改为完整 Mux 后的相关测试本批未运行；上述旧 XUDP 数字不能当作新 Mux 的验收结果。**

真实受控内层TLS1.2走End、TLS1.3双向Direct通过，独立外层对端逐record读取并在Direct后直接读写raw；没有以普通echo成功冒充Direct。另有相邻TLS明文尾部/raw、写gate背压反例、关闭后拒写及计量、慢读/半帧强停、联合准备失败归还监听。开发中实际暴露并修复了读方向被无关应用输出背压阻塞、Vision写关闭后仍可能接受缓存两处状态问题；初始关闭夹具、载荷长度期望、路由拒绝事件计数期望及并行编辑编译失败分别保留，不伪称首次全部通过。拒绝计数沿用既有“路由拒绝＋连接失败”分类，同一请求可能增加两次，不是唯一请求计费数。

私有命令日志与当前输入集合摘要位于 `.test-artifacts/vision-dev-zvwic_5k/`。依赖与Cargo.lock未变。现有release是旧构建，本批没有执行release构建、MSRV或三平台全量，不将旧结果关联为新代码通过。

新官方矩阵未启动；本批未启动/重建/删除 Colima 或容器，没有修改系统代理、DNS、防火墙或全局 Docker context。`.test-artifacts/` 可能包含临时私钥和凭据，不整体公开。
