## Why

Naive 入站已有 H1/H2/H3，但内核无法将已接受的流量送往正式 Naive 上游。补原生 Rust 的 H2/H3 普通 CONNECT、认证与 padding，以及固定 sing-box 公开的可选 UoT v2，不引入 Cronet 子进程、不声称浏览器指纹等价。

## What Changes

- 新 `type:naive` 出站，显式 TLS 信任锚、Basic 身份及 `naive.http_version:2/3`（默认2），可选有界额外请求头和 `udp_over_tcp:true`（默认false，标准UoT v2）。
- H2/H3 普通 CONNECT 只携带目标 authority，不使用 MASQUE :protocol/scheme/path；Padding 非空请求/响应协商后双向首8块PaddedData，第9块起裸字节。只接受200成功，坏身份、证书、ALPN、状态或截断明确失败，不重放或回落直连。
- H2支持原TCP via链，H3独立QUIC且禁止嵌入TCP链；每业务建立独立成熟HTTP连接，不宣称连接池、Cronet指纹、ECH或特定Chromium拥塞控制等价。
- 可选UDP通过正式UoT v2魔数目标与地址/长度帧；服务端Naive H2/H3按固定sing-box的UoT路由识别接入已有共享UDP处理，不扩成私有CONNECT-UDP；默认UDP拒绝。
- 有界头/流窗口/写队列、短写取消安全、真实flush/FIN及独立读方向；所有driver/writer有明确所有权、取消与停机屏障。完整实施后集中离线回归并清项目对象。

## Capabilities

### New Capabilities

- `naive-outbound`: 原生H2/H3普通CONNECT出站与正式可选UoT v2、认证/填充和资源生命周期。

### Modified Capabilities

- 无，主规格尚无Naive出站。

## Impact

config、route、forward/链工厂、UDP、Naive承载与padding、共享H2 flush观察器、测试/文档。固定NaiveProxy v154.0.8037.49-5、forwardproxy e747854e78743dba85c039b38ed185fb11d93667，sing-box v1.14.4及其固定cronet-go v0.0.0-20260912104727-0d28acc44093；naive_conn.go SHA256 `c32bf867819dd773398da7506c25360be55cab887ac31237c1ab48c814b5aed3`。既有h3 0.0.8客户端会为普通CONNECT补scheme/path，使用公开backend接口替换有限首HEADERS为RFC9114/RFC9204字面编码，其他控制/响应/DATA仍由成熟h3处理，不改vendor或新增依赖。不Git/归档/发布/系统网络，不执行官方客户端、三平台、MSRV或release验收。H1原生Naive出站不在本批，不改变既有HTTP CONNECT或固定上游H1无payload padding语义。
