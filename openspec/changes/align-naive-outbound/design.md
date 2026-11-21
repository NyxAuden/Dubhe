## Context

见proposal.md。现有naive_padding可复用，但读方向不主动排空已接受写；XHTTP已有H2 Buf消耗/底层flush观察器，适合抽为共享有限工具，不能用send_data入队冒充flush。h3 0.0.8普通CONNECT补scheme/path有已验证缺陷，不能放宽服务端或偷偷改vendor。

## Goals / Non-Goals

**Goals:** 标准H2/H3普通CONNECT、200/认证/TLS、首8块padding、显式UoT v2、H2 TCP链、有限资源和取消安全。

**Non-Goals:** 非Chromium/Cronet/uTLS/ECH指纹等价；不增依赖/改vendor/密码原语，不实现H1出站、连接池、QUIC 0-RTT、自动重放或私有UDP。官方/三平台/MSRV/release另验收。

## Decisions

- 新NaiveClientOptions，http_version沿用明确字符串2/3（默认2）、extra_headers有界且禁止伪头/认证/padding/连接语义覆盖；udp_over_tcp默认false只提供标准v2。根用户名/密码必填且用户名不得含冒号，TLS必需；其他协议字段不得混入。
- 每个业务独立成熟H2/H3连接，限制头8192、收发窗口/队列与写块。H2由Context原TCP/TLS工厂完成ALPN h2，可链式；H3显式独立QUIC/TLS1.3且禁止TCP via任一侧，不自动切换版本。
- 将既有XHTTP H2Progress/H2Data/FlushIo抽到共享模块供两者使用；保留原语义与回归。单会话写泵逐块等真实Buf消耗和底层flush，FIN也等确认；不改成熟h2库。
- H3普通CONNECT适配使用公开QUIC backend，仅替换首HEADERS为RFC9204无动态表字面字段，所有控制/响应/DATA仍由h3处理；编码有界且用独立服务端确认没有scheme/path/protocol，不把测试适配原样当未经检查的生产实现。
- H2/H3成熟驱动与写泵由TaskTracker跟踪；实例所有者Drop取消并关闭QUIC，握手前建立guard，失败/取消也释放。读独立按成熟API拉DATA/释放流控，错误存在共享状态防止通道结束伪装EOF。
- 复用PaddedStream，补读方向主动推进已接受写、错误永久失败及关闭后拒写边界；合法wire不改。请求非空padding，响应非空才启用，无响应头保持plain。HTTP成功状态严格200。
- UoT出站采用每目标专属普通CONNECT到sp.v2.udp-over-tcp.arpa:0、v2 isConnect与SOCKS目标、u16长度帧，缓存部分读保取消安全；send开始后取消不可复用。Naive服务端在认证/解析后识别明确魔数且端口0的合法占位，直接进入已有udp::uot，不先DNS/拨号；普通端口0仍拒绝。H1保持历史裸payload语义，不添加padding扩展。
- 公开低层outbound::connect没有任务生命周期，Naive显式要求Context工厂；根与链中间跳接同一受控H2入口。业务与UDP整体握手沿用dial_timeout，不更改系统代理/网络。

## Risks / Trade-offs

- [手动普通CONNECT首头适配出错] → 限定无动态表编码、独立解码/真实H3服务端验证、只替换一个有限HEADERS，其余成熟栈；不更改vendor与服务端RFC校验。
- [padding缓存导致先写后读停滞] → 实例持有有界块并在read/flush/FIN推进旧写，取消不认领新buffer。
- [任务持有连接造成停机挂起] → 握手前guard、共享取消、无Context自持，children屏障和端口回收断言。
- [UoT魔数被当普通DNS目标] → 只对已认证Naive明确识别，不改普通HTTP行为，UDP禁用/身份错误/路由拒绝零目标。
