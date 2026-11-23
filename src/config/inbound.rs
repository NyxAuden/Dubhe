//! 入站入口定义：每种协议的监听与认证参数。
//!
//! 这里只做结构与序列化；跨入口的语义校验在 `validate` 中完成。

use super::*;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Inbound {
    Socks5 {
        tag: String,
        listen: SocketAddr,
        #[serde(default)]
        users: Vec<User>,
        #[serde(default)]
        allow_insecure: bool,
    },
    Http {
        tag: String,
        listen: SocketAddr,
        #[serde(default)]
        users: Vec<User>,
        #[serde(default)]
        allow_insecure: bool,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    Mixed {
        tag: String,
        listen: SocketAddr,
        #[serde(default)]
        users: Vec<User>,
        #[serde(default)]
        allow_insecure: bool,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    /// 固定目标转发；不做系统级透明代理重定向。
    #[serde(rename = "dokodemo-door")]
    DokodemoDoor {
        tag: String,
        listen: SocketAddr,
        address: String,
        port: u16,
        #[serde(default = "default_dokodemo_network")]
        network: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sniffing: Option<Sniffing>,
    },
    /// WireGuard 服务端：UDP-only，用户在隧道内发起 TCP/UDP，由本机终止
    /// 后经 route/direct 拨号转发。`address` 是本机隧道地址，peer 的
    /// `allowed_ips` 同时作为隧道内源地址 ACL。
    #[serde(rename = "wireguard")]
    Wireguard {
        tag: String,
        listen: SocketAddr,
        /// 服务端静态私钥（base64，32 字节）。
        private_key: String,
        /// 本机隧道内 IPv4/IPv6 CIDR 列表，至少一条。
        address: Vec<String>,
        peers: Vec<WireguardServerPeerOptions>,
        /// IP MTU；缺省 1420，范围 576-1500。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mtu: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_peers: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_tcp_connections: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_udp_associations: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_queued_datagrams: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_handshake_inits_per_sec: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_idle_timeout_secs: Option<u64>,
    },
    Naive {
        tag: String,
        listen: SocketAddr,
        users: Vec<User>,
        certificate: PathBuf,
        private_key: PathBuf,
        /// 同一实际端口增加 UDP QUIC/HTTP3；TCP H1/H2 保持开启。
        #[serde(default)]
        h3: bool,
        /// sing-box H1首八块填充及UoT；默认裸流对齐forwardproxy，不自动探测。
        #[serde(default)]
        h1_padding: bool,
    },
    /// AnyTLS：TLS 之上的密码哈希认证与多流复用。
    #[serde(rename = "anytls")]
    AnyTls {
        tag: String,
        listen: SocketAddr,
        users: Vec<User>,
        certificate: PathBuf,
        private_key: PathBuf,
        /// 按上游原始文本下发的正式方案；省略使用规范默认值。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        padding_scheme: Option<String>,
    },
    Trojan {
        tag: String,
        listen: SocketAddr,
        users: Vec<User>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fallbacks: Vec<Fallback>,
        certificate: PathBuf,
        private_key: PathBuf,
    },
    Shadowsocks {
        tag: String,
        listen: SocketAddr,
        method: ShadowsocksMethod,
        password: Secret,
        #[serde(
            default,
            deserialize_with = "shadowsocks::present_users",
            skip_serializing_if = "Option::is_none"
        )]
        users: Option<Vec<User>>,
    },
    Vless {
        tag: String,
        listen: SocketAddr,
        users: Vec<VlessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fallbacks: Vec<Fallback>,
        /// Xray VLESS Encryption（`mlkem768x25519plus...`）服务端配置。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decryption: Option<String>,
        /// 省略证书/私钥表示明文 VLESS（Xray 无 TLS 的 VLESS 入站）。
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "vless-reality")]
    VlessReality {
        tag: String,
        listen: SocketAddr,
        /// VLESS Encryption 服务端配置；可与 Vision flow 组合，但与 fallbacks 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decryption: Option<String>,
        users: Vec<VlessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        reality: Reality,
    },
    /// VMess AEAD over REALITY（Xray `security: "reality"` + RAW 传输）。
    #[serde(rename = "vmess-reality")]
    VmessReality {
        tag: String,
        listen: SocketAddr,
        users: Vec<VmessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        packetaddr: bool,
        #[serde(default)]
        allow_insecure_body: bool,
        #[serde(default)]
        allow_authenticated_length: bool,
        reality: Reality,
    },
    /// Trojan over REALITY（Xray `security: "reality"` + RAW 传输）。
    #[serde(rename = "trojan-reality")]
    TrojanReality {
        tag: String,
        listen: SocketAddr,
        users: Vec<User>,
        reality: Reality,
    },
    Vmess {
        tag: String,
        listen: SocketAddr,
        users: Vec<VmessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        packetaddr: bool,
        #[serde(default)]
        allow_insecure_body: bool,
        #[serde(default)]
        allow_authenticated_length: bool,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "vless-ws")]
    VlessWs {
        tag: String,
        listen: SocketAddr,
        /// VLESS Encryption 服务端配置；可与 Vision flow 组合，但与 fallbacks 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decryption: Option<String>,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<VlessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        allow_insecure_transport: bool,
        websocket: WebSocket,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "vmess-ws")]
    VmessWs {
        tag: String,
        listen: SocketAddr,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<VmessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        packetaddr: bool,
        #[serde(default)]
        allow_insecure_body: bool,
        #[serde(default)]
        allow_authenticated_length: bool,
        websocket: WebSocket,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "trojan-ws")]
    TrojanWs {
        tag: String,
        listen: SocketAddr,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<User>,
        #[serde(default)]
        allow_insecure_transport: bool,
        websocket: WebSocket,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "vless-grpc")]
    VlessGrpc {
        tag: String,
        listen: SocketAddr,
        /// VLESS Encryption 服务端配置；可与 Vision flow 组合，但与 fallbacks 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decryption: Option<String>,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<VlessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        allow_insecure_transport: bool,
        grpc: Grpc,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "vmess-grpc")]
    VmessGrpc {
        tag: String,
        listen: SocketAddr,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<VmessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        packetaddr: bool,
        #[serde(default)]
        allow_insecure_body: bool,
        #[serde(default)]
        allow_authenticated_length: bool,
        grpc: Grpc,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "trojan-grpc")]
    TrojanGrpc {
        tag: String,
        listen: SocketAddr,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<User>,
        #[serde(default)]
        allow_insecure_transport: bool,
        grpc: Grpc,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "vless-xhttp")]
    VlessXhttp {
        tag: String,
        listen: SocketAddr,
        /// VLESS Encryption 服务端配置；可与 Vision flow 组合，但与 fallbacks 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decryption: Option<String>,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<VlessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        allow_insecure_transport: bool,
        xhttp: Xhttp,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "vmess-xhttp")]
    VmessXhttp {
        tag: String,
        listen: SocketAddr,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<VmessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        packetaddr: bool,
        #[serde(default)]
        allow_insecure_body: bool,
        #[serde(default)]
        allow_authenticated_length: bool,
        xhttp: Xhttp,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "vless-httpupgrade")]
    VlessHttpUpgrade {
        tag: String,
        listen: SocketAddr,
        /// VLESS Encryption 服务端配置；可与 Vision flow 组合，但与 fallbacks 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decryption: Option<String>,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<VlessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        allow_insecure_transport: bool,
        httpupgrade: HttpUpgrade,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "vmess-httpupgrade")]
    VmessHttpUpgrade {
        tag: String,
        listen: SocketAddr,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<VmessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        packetaddr: bool,
        #[serde(default)]
        allow_insecure_body: bool,
        #[serde(default)]
        allow_authenticated_length: bool,
        httpupgrade: HttpUpgrade,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "trojan-httpupgrade")]
    TrojanHttpUpgrade {
        tag: String,
        listen: SocketAddr,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<User>,
        #[serde(default)]
        allow_insecure_transport: bool,
        httpupgrade: HttpUpgrade,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    #[serde(rename = "trojan-xhttp")]
    TrojanXhttp {
        tag: String,
        listen: SocketAddr,
        /// REALITY 安全层；与 certificate/private_key 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reality: Option<Reality>,
        users: Vec<User>,
        #[serde(default)]
        allow_insecure_transport: bool,
        xhttp: Xhttp,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    /// Snell v4/v5：Argon2id 密钥派生与 AES-128-GCM 记录层。
    /// mKCP 承载的 VLESS；省略证书/私钥表示 KCP 之上直接明文 VLESS。
    #[serde(rename = "vless-kcp")]
    VlessKcp {
        tag: String,
        listen: SocketAddr,
        /// VLESS Encryption 服务端配置；可与 Vision flow 组合，但与 fallbacks 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decryption: Option<String>,
        users: Vec<VlessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        allow_insecure_transport: bool,
        #[serde(default)]
        kcp: Kcp,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    /// mKCP 承载的 VMess；VMess 自带加密，允许显式明文 transport。
    #[serde(rename = "vmess-kcp")]
    VmessKcp {
        tag: String,
        listen: SocketAddr,
        users: Vec<VmessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        packetaddr: bool,
        #[serde(default)]
        allow_insecure_body: bool,
        #[serde(default)]
        allow_authenticated_length: bool,
        #[serde(default)]
        kcp: Kcp,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    /// mKCP 承载的 Trojan。
    #[serde(rename = "trojan-kcp")]
    TrojanKcp {
        tag: String,
        listen: SocketAddr,
        users: Vec<User>,
        #[serde(default)]
        allow_insecure_transport: bool,
        #[serde(default)]
        kcp: Kcp,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    /// V2Ray HTTP 传输承载的 VLESS；无 TLS 时为 HTTP/1.1，TLS 时协商 h2。
    #[serde(rename = "vless-http")]
    VlessHttp {
        tag: String,
        listen: SocketAddr,
        /// VLESS Encryption 服务端配置；可与 Vision flow 组合，但与 fallbacks 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decryption: Option<String>,
        users: Vec<VlessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        allow_insecure_transport: bool,
        #[serde(default)]
        http: V2rayHttp,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    /// V2Ray HTTP 传输承载的 VMess。
    #[serde(rename = "vmess-http")]
    VmessHttp {
        tag: String,
        listen: SocketAddr,
        users: Vec<VmessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        packetaddr: bool,
        #[serde(default)]
        allow_insecure_body: bool,
        #[serde(default)]
        allow_authenticated_length: bool,
        #[serde(default)]
        http: V2rayHttp,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    /// V2Ray HTTP 传输承载的 Trojan。
    #[serde(rename = "trojan-http")]
    TrojanHttp {
        tag: String,
        listen: SocketAddr,
        users: Vec<User>,
        #[serde(default)]
        allow_insecure_transport: bool,
        #[serde(default)]
        http: V2rayHttp,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
    /// V2Ray QUIC 传输承载的 VLESS；QUIC 强制 TLS。
    #[serde(rename = "vless-quic")]
    VlessQuic {
        tag: String,
        listen: SocketAddr,
        /// VLESS Encryption 服务端配置；可与 Vision flow 组合，但与 fallbacks 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decryption: Option<String>,
        users: Vec<VlessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        quic: V2rayQuic,
        certificate: PathBuf,
        private_key: PathBuf,
    },
    /// V2Ray QUIC 传输承载的 VMess。
    #[serde(rename = "vmess-quic")]
    VmessQuic {
        tag: String,
        listen: SocketAddr,
        users: Vec<VmessUser>,
        #[serde(default = "default_true")]
        xudp: bool,
        #[serde(default)]
        packetaddr: bool,
        #[serde(default)]
        allow_authenticated_length: bool,
        #[serde(default)]
        quic: V2rayQuic,
        certificate: PathBuf,
        private_key: PathBuf,
    },
    /// V2Ray QUIC 传输承载的 Trojan。
    #[serde(rename = "trojan-quic")]
    TrojanQuic {
        tag: String,
        listen: SocketAddr,
        users: Vec<User>,
        #[serde(default)]
        quic: V2rayQuic,
        certificate: PathBuf,
        private_key: PathBuf,
    },
    Snell {
        tag: String,
        listen: SocketAddr,
        psk: Secret,
        version: u8,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        users: Vec<SnellUser>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        obfs_mode: Option<String>,
        /// v6 记录模式：`default`（缺省）、`unshaped` 或 `unsafe-raw`；v4/v5 禁止配置。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
    },
    /// Hysteria2：QUIC/HTTP-3 密码认证、TCP 流与 UDP DATAGRAM。
    Hysteria2 {
        tag: String,
        listen: SocketAddr,
        users: Vec<User>,
        certificate: PathBuf,
        private_key: PathBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        obfs: Option<Hysteria2Obfs>,
        #[serde(default = "default_true")]
        udp: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        up_mbps: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        down_mbps: Option<u64>,
        #[serde(default)]
        ignore_client_bandwidth: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_timeout_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        masquerade: Option<Hysteria2Masquerade>,
    },
    /// TUIC v5：QUIC/TLS 1.3，UUID 与 TLS exporter 认证。
    Tuic {
        tag: String,
        listen: SocketAddr,
        users: Vec<TuicUser>,
        certificate: PathBuf,
        private_key: PathBuf,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        alpn: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_timeout_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        heartbeat_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_timeout_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_streams: Option<u32>,
        /// QUIC 拥塞控制：`cubic`（缺省）、`new_reno` 或 `bbr`。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        congestion_control: Option<String>,
        /// 服务端是否接受 TLS 1.3 0-RTT；默认关闭。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        zero_rtt_handshake: Option<bool>,
    },
    /// ShadowTLS v3：真实 TLS 握手伪装与 HMAC 认证，认证后交给同进程 detour 入站。
    ShadowTls {
        tag: String,
        listen: SocketAddr,
        #[serde(default = "default_shadowtls_version")]
        version: u8,
        users: Vec<User>,
        handshake: ShadowTlsHandshake,
        /// 按 ClientHello SNI 选择伪装握手目标；未命中时使用 `handshake`。
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        handshake_for_server_name: std::collections::BTreeMap<String, ShadowTlsHandshake>,
        /// v3 wildcard SNI：`authed` 仅认证成功时使用 SNI:443，`all` 未认证回落也使用。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wildcard_sni: Option<ShadowTlsWildcardSni>,
        #[serde(default)]
        strict_mode: bool,
        detour: String,
    },
    /// NW3（Nowhere Protocol v3）Portal；复用 Nowhere 3.3.0 的 GPL-3.0-only 实现。
    Nw3 {
        tag: String,
        listen: SocketAddr,
        /// 32 个小写十六进制字符的共享密钥。
        key: String,
        /// Morph 线格式伪装；默认开启，必须与客户端配置一致。
        #[serde(default = "default_true")]
        morph: bool,
        /// 出口选择：默认直连目标；`egress` 交给同 Portal 注册的 Egress 服务；
        /// 其余取值为 `[USER:PASS@]HOST:PORT` 形式的 SOCKS5 上游。
        #[serde(default)]
        out: Nw3Out,
        /// 直连目标的源地址绑定：`auto` 或具体 IP；与 `dial4`/`dial6` 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dial: Option<String>,
        /// 仅 IPv4 源地址；与 `dial`/`dial6` 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dial4: Option<String>,
        /// 仅 IPv6 源地址；与 `dial`/`dial4` 互斥。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dial6: Option<String>,
        /// 源到目标限速（Mbps）；0 或省略表示不限制。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rate: Option<u32>,
        /// 目标到源限速（Mbps）；0 或省略表示不限制。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        etar: Option<u32>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        certificate: Option<PathBuf>,
        #[serde(
            default,
            deserialize_with = "vmess::present_tls_path",
            skip_serializing_if = "Option::is_none"
        )]
        private_key: Option<PathBuf>,
    },
}

fn default_dokodemo_network() -> String {
    "tcp".to_owned()
}

fn default_shadowtls_version() -> u8 {
    3
}

/// ShadowTLS 伪装握手服务器；该连接只承载真实 TLS 握手，不参与内层代理。
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowTlsHandshake {
    pub server: String,
    pub server_port: u16,
}

/// ShadowTLS v3 wildcard SNI 模式。
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ShadowTlsWildcardSni {
    #[serde(rename = "authed")]
    Authed,
    #[serde(rename = "all")]
    All,
}

impl ShadowTlsHandshake {
    /// 域名在解析前做 ASCII 校验；IP 字面量直接作为目标。
    pub fn target(&self) -> Result<crate::session::Target> {
        use crate::session::{Host, Target};
        ensure!(
            !self.server.is_empty() && self.server.len() <= 255,
            "ShadowTLS handshake.server 长度无效"
        );
        let host = match self.server.parse::<std::net::IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(self.server.clone()),
        };
        let target = Target {
            host,
            port: self.server_port,
        };
        crate::protocol::address::encode(&target)
            .map_err(|_| anyhow::anyhow!("ShadowTLS handshake.server 无效"))?;
        ensure!(target.port != 0, "ShadowTLS handshake.server_port 不得为 0");
        Ok(target)
    }
}

impl fmt::Debug for ShadowTlsHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShadowTlsHandshake")
            .field("server", &self.server)
            .field("server_port", &self.server_port)
            .finish()
    }
}

impl Inbound {
    pub fn tag(&self) -> &str {
        match self {
            Self::Socks5 { tag, .. }
            | Self::Trojan { tag, .. }
            | Self::Vless { tag, .. }
            | Self::VlessReality { tag, .. }
            | Self::VmessReality { tag, .. }
            | Self::TrojanReality { tag, .. }
            | Self::Vmess { tag, .. }
            | Self::VlessWs { tag, .. }
            | Self::VmessWs { tag, .. }
            | Self::TrojanWs { tag, .. }
            | Self::VlessGrpc { tag, .. }
            | Self::VmessGrpc { tag, .. }
            | Self::TrojanGrpc { tag, .. }
            | Self::VlessXhttp { tag, .. }
            | Self::VmessXhttp { tag, .. }
            | Self::TrojanXhttp { tag, .. }
            | Self::Http { tag, .. }
            | Self::Mixed { tag, .. }
            | Self::Naive { tag, .. }
            | Self::AnyTls { tag, .. }
            | Self::VlessHttpUpgrade { tag, .. }
            | Self::VmessHttpUpgrade { tag, .. }
            | Self::TrojanHttpUpgrade { tag, .. }
            | Self::VlessKcp { tag, .. }
            | Self::VmessKcp { tag, .. }
            | Self::TrojanKcp { tag, .. }
            | Self::VlessHttp { tag, .. }
            | Self::VmessHttp { tag, .. }
            | Self::TrojanHttp { tag, .. }
            | Self::VlessQuic { tag, .. }
            | Self::VmessQuic { tag, .. }
            | Self::TrojanQuic { tag, .. }
            | Self::DokodemoDoor { tag, .. }
            | Self::Snell { tag, .. }
            | Self::Hysteria2 { tag, .. }
            | Self::Tuic { tag, .. }
            | Self::ShadowTls { tag, .. }
            | Self::Nw3 { tag, .. }
            | Self::Wireguard { tag, .. }
            | Self::Shadowsocks { tag, .. } => tag,
        }
    }

    pub fn listen(&self) -> SocketAddr {
        match self {
            Self::Socks5 { listen, .. }
            | Self::Http { listen, .. }
            | Self::Mixed { listen, .. }
            | Self::Naive { listen, .. }
            | Self::AnyTls { listen, .. }
            | Self::Trojan { listen, .. }
            | Self::Vless { listen, .. }
            | Self::VlessReality { listen, .. }
            | Self::VmessReality { listen, .. }
            | Self::TrojanReality { listen, .. }
            | Self::Vmess { listen, .. }
            | Self::VlessWs { listen, .. }
            | Self::VmessWs { listen, .. }
            | Self::TrojanWs { listen, .. }
            | Self::VlessGrpc { listen, .. }
            | Self::VmessGrpc { listen, .. }
            | Self::TrojanGrpc { listen, .. }
            | Self::VlessXhttp { listen, .. }
            | Self::VmessXhttp { listen, .. }
            | Self::TrojanXhttp { listen, .. }
            | Self::VlessHttpUpgrade { listen, .. }
            | Self::VmessHttpUpgrade { listen, .. }
            | Self::TrojanHttpUpgrade { listen, .. }
            | Self::VlessKcp { listen, .. }
            | Self::VmessKcp { listen, .. }
            | Self::TrojanKcp { listen, .. }
            | Self::VlessHttp { listen, .. }
            | Self::VmessHttp { listen, .. }
            | Self::TrojanHttp { listen, .. }
            | Self::VlessQuic { listen, .. }
            | Self::VmessQuic { listen, .. }
            | Self::TrojanQuic { listen, .. }
            | Self::DokodemoDoor { listen, .. }
            | Self::Snell { listen, .. }
            | Self::Hysteria2 { listen, .. }
            | Self::Tuic { listen, .. }
            | Self::ShadowTls { listen, .. }
            | Self::Nw3 { listen, .. }
            | Self::Wireguard { listen, .. }
            | Self::Shadowsocks { listen, .. } => *listen,
        }
    }

    /// 该入口实际会占用的网络类型 `(tcp, udp)`。
    ///
    /// 与 `runtime.rs` 的绑定路径一一对应：多数入口绑 TCP；Hysteria2 / TUIC /
    /// WireGuard / mKCP / V2Ray QUIC 只绑 UDP；dokodemo-door 依 `network`；
    /// Shadowsocks 与 Naive H3 联合绑定；XHTTP/3 额外占用 UDP。
    pub fn networks(&self) -> (bool, bool) {
        match self {
            // 只占 TCP。
            Self::Socks5 { .. }
            | Self::Http { .. }
            | Self::Mixed { .. }
            | Self::AnyTls { .. }
            | Self::Trojan { .. }
            | Self::Vless { .. }
            | Self::VlessReality { .. }
            | Self::VmessReality { .. }
            | Self::TrojanReality { .. }
            | Self::Vmess { .. }
            | Self::VlessWs { .. }
            | Self::VmessWs { .. }
            | Self::TrojanWs { .. }
            | Self::VlessGrpc { .. }
            | Self::VmessGrpc { .. }
            | Self::TrojanGrpc { .. }
            | Self::VlessHttpUpgrade { .. }
            | Self::VmessHttpUpgrade { .. }
            | Self::TrojanHttpUpgrade { .. }
            | Self::VlessHttp { .. }
            | Self::VmessHttp { .. }
            | Self::TrojanHttp { .. }
            | Self::Snell { .. }
            | Self::ShadowTls { .. } => (true, false),
            // NW3 Portal 同端口绑 TCP（TLS 1.3）与 UDP（QUIC）两个 socket，
            // 实测 lsof 两个 FD 都在监听。
            Self::Nw3 { .. } => (true, true),
            // 只占 UDP。
            Self::Hysteria2 { .. } | Self::Tuic { .. } | Self::Wireguard { .. } => (false, true),
            // 联合绑定 TCP + UDP。
            Self::Shadowsocks { .. } => (true, true),
            Self::Naive { h3, .. } => (true, *h3),
            // mKCP 只占 UDP。
            Self::VlessKcp { .. } | Self::VmessKcp { .. } | Self::TrojanKcp { .. } => (false, true),
            // V2Ray 旧 QUIC 只占 UDP；`http` 承载在 UDP 之上。
            Self::VlessQuic { .. } | Self::VmessQuic { .. } | Self::TrojanQuic { .. } => {
                (false, true)
            }
            // XHTTP：h1/h2 走 TCP；h3 在 runtime 里走 `continue`，**只**绑 UDP，
            // 不起 TCP 监听，因此两者互斥而不是叠加。
            Self::VlessXhttp { xhttp, .. }
            | Self::VmessXhttp { xhttp, .. }
            | Self::TrojanXhttp { xhttp, .. } => {
                if xhttp.h3 {
                    (false, true)
                } else {
                    (true, false)
                }
            }
            // dokodemo-door 依 `network` 字段。
            Self::DokodemoDoor { network, .. } => {
                crate::config::dokodemo_networks(network).unwrap_or((true, true))
            }
        }
    }

    /// 该入口配置的 REALITY 安全层；未配置时为 `None`。
    pub fn reality(&self) -> Option<&Reality> {
        match self {
            Self::VlessReality { reality, .. }
            | Self::VmessReality { reality, .. }
            | Self::TrojanReality { reality, .. } => Some(reality),
            Self::VlessWs { reality, .. }
            | Self::VmessWs { reality, .. }
            | Self::TrojanWs { reality, .. }
            | Self::VlessGrpc { reality, .. }
            | Self::VmessGrpc { reality, .. }
            | Self::TrojanGrpc { reality, .. }
            | Self::VlessXhttp { reality, .. }
            | Self::VmessXhttp { reality, .. }
            | Self::TrojanXhttp { reality, .. }
            | Self::VlessHttpUpgrade { reality, .. }
            | Self::VmessHttpUpgrade { reality, .. }
            | Self::TrojanHttpUpgrade { reality, .. } => reality.as_ref(),
            _ => None,
        }
    }

    /// VLESS Encryption 服务端配置字符串；未配置时为 `None`。
    pub fn decryption(&self) -> Option<&str> {
        match self {
            Self::Vless { decryption, .. }
            | Self::VlessReality { decryption, .. }
            | Self::VlessWs { decryption, .. }
            | Self::VlessGrpc { decryption, .. }
            | Self::VlessXhttp { decryption, .. }
            | Self::VlessHttpUpgrade { decryption, .. }
            | Self::VlessKcp { decryption, .. }
            | Self::VlessQuic { decryption, .. }
            | Self::VlessHttp { decryption, .. } => decryption.as_deref(),
            _ => None,
        }
    }

    pub fn tls_paths(&self) -> Option<(&Path, &Path)> {
        // REALITY 与证书互斥；由 REALITY acceptor 负责握手。
        if self.reality().is_some() {
            return None;
        }
        match self {
            Self::Socks5 { .. }
            | Self::DokodemoDoor { .. }
            | Self::Snell { .. }
            | Self::ShadowTls { .. }
            | Self::Wireguard { .. }
            | Self::Shadowsocks { .. }
            | Self::VlessReality { .. }
            | Self::VmessReality { .. }
            | Self::TrojanReality { .. } => None,
            Self::Http {
                certificate: Some(certificate),
                private_key: Some(private_key),
                ..
            }
            | Self::Mixed {
                certificate: Some(certificate),
                private_key: Some(private_key),
                ..
            }
            | Self::Trojan {
                certificate,
                private_key,
                ..
            }
            | Self::Naive {
                certificate,
                private_key,
                ..
            }
            | Self::AnyTls {
                certificate,
                private_key,
                ..
            }
            | Self::Hysteria2 {
                certificate,
                private_key,
                ..
            }
            | Self::Tuic {
                certificate,
                private_key,
                ..
            }
            | Self::VlessQuic {
                certificate,
                private_key,
                ..
            }
            | Self::VmessQuic {
                certificate,
                private_key,
                ..
            }
            | Self::TrojanQuic {
                certificate,
                private_key,
                ..
            } => Some((certificate.as_path(), private_key.as_path())),
            Self::Http { .. } | Self::Mixed { .. } => None,
            Self::Vless {
                certificate,
                private_key,
                ..
            }
            | Self::Vmess {
                certificate,
                private_key,
                ..
            }
            | Self::VlessWs {
                certificate,
                private_key,
                ..
            }
            | Self::VmessWs {
                certificate,
                private_key,
                ..
            }
            | Self::TrojanWs {
                certificate,
                private_key,
                ..
            }
            | Self::VlessGrpc {
                certificate,
                private_key,
                ..
            }
            | Self::TrojanGrpc {
                certificate,
                private_key,
                ..
            }
            | Self::VlessXhttp {
                certificate,
                private_key,
                ..
            }
            | Self::TrojanXhttp {
                certificate,
                private_key,
                ..
            }
            | Self::VlessHttpUpgrade {
                certificate,
                private_key,
                ..
            }
            | Self::TrojanHttpUpgrade {
                certificate,
                private_key,
                ..
            }
            | Self::VlessKcp {
                certificate,
                private_key,
                ..
            }
            | Self::VmessKcp {
                certificate,
                private_key,
                ..
            }
            | Self::TrojanKcp {
                certificate,
                private_key,
                ..
            }
            | Self::VlessHttp {
                certificate,
                private_key,
                ..
            }
            | Self::VmessHttp {
                certificate,
                private_key,
                ..
            }
            | Self::TrojanHttp {
                certificate,
                private_key,
                ..
            } => certificate.as_deref().zip(private_key.as_deref()),
            Self::VmessGrpc {
                certificate,
                private_key,
                ..
            }
            | Self::VmessXhttp {
                certificate,
                private_key,
                ..
            }
            | Self::VmessHttpUpgrade {
                certificate,
                private_key,
                ..
            } => certificate.as_deref().zip(private_key.as_deref()),
            Self::Nw3 {
                certificate,
                private_key,
                ..
            } => certificate.as_deref().zip(private_key.as_deref()),
        }
    }
}

impl fmt::Debug for Inbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Socks5 { .. } => "Socks5",
            Self::Http { .. } => "Http",
            Self::Mixed { .. } => "Mixed",
            Self::Naive { .. } => "Naive",
            Self::AnyTls { .. } => "AnyTls",
            Self::Snell { .. } => "Snell",
            Self::Hysteria2 { .. } => "Hysteria2",
            Self::Tuic { .. } => "Tuic",
            Self::ShadowTls { .. } => "ShadowTls",
            Self::Nw3 { .. } => "Nw3",
            Self::Wireguard { .. } => "Wireguard",
            Self::Trojan { .. } => "Trojan",
            Self::Shadowsocks { .. } => "Shadowsocks",
            Self::Vless { .. } => "Vless",
            Self::VlessReality { .. } => "VlessReality",
            Self::VmessReality { .. } => "VmessReality",
            Self::TrojanReality { .. } => "TrojanReality",
            Self::Vmess { .. } => "Vmess",
            Self::VlessWs { .. } => "VlessWs",
            Self::VmessWs { .. } => "VmessWs",
            Self::TrojanWs { .. } => "TrojanWs",
            Self::VlessGrpc { .. } => "VlessGrpc",
            Self::VmessGrpc { .. } => "VmessGrpc",
            Self::TrojanGrpc { .. } => "TrojanGrpc",
            Self::VlessXhttp { .. } => "VlessXhttp",
            Self::VmessXhttp { .. } => "VmessXhttp",
            Self::TrojanXhttp { .. } => "TrojanXhttp",
            Self::VlessHttpUpgrade { .. } => "VlessHttpUpgrade",
            Self::VmessHttpUpgrade { .. } => "VmessHttpUpgrade",
            Self::TrojanHttpUpgrade { .. } => "TrojanHttpUpgrade",
            Self::VlessKcp { .. } => "VlessKcp",
            Self::VmessKcp { .. } => "VmessKcp",
            Self::TrojanKcp { .. } => "TrojanKcp",
            Self::VlessHttp { .. } => "VlessHttp",
            Self::VmessHttp { .. } => "VmessHttp",
            Self::TrojanHttp { .. } => "TrojanHttp",
            Self::VlessQuic { .. } => "VlessQuic",
            Self::VmessQuic { .. } => "VmessQuic",
            Self::TrojanQuic { .. } => "TrojanQuic",
            Self::DokodemoDoor { .. } => "DokodemoDoor",
        };
        let mut debug = formatter.debug_struct(kind);
        debug
            .field("tag", &self.tag())
            .field("listen", &self.listen());
        match self {
            Self::Socks5 {
                users,
                allow_insecure,
                ..
            }
            | Self::Http {
                users,
                allow_insecure,
                ..
            }
            | Self::Mixed {
                users,
                allow_insecure,
                ..
            } => {
                debug
                    .field("users", users)
                    .field("allow_insecure", allow_insecure);
            }
            Self::Naive { users, .. }
            | Self::AnyTls { users, .. }
            | Self::Trojan { users, .. }
            | Self::TrojanReality { users, .. }
            | Self::TrojanWs { users, .. }
            | Self::TrojanGrpc { users, .. }
            | Self::TrojanXhttp { users, .. }
            | Self::TrojanHttpUpgrade { users, .. }
            | Self::TrojanKcp { users, .. }
            | Self::TrojanHttp { users, .. }
            | Self::TrojanQuic { users, .. } => {
                debug.field("users", users);
            }
            Self::Shadowsocks {
                method,
                password,
                users,
                ..
            } => {
                debug
                    .field("method", method)
                    .field("password", password)
                    .field("users", users);
            }
            Self::Snell { users, version, .. } => {
                debug.field("users", users).field("version", version);
            }
            Self::Hysteria2 {
                users, obfs, udp, ..
            } => {
                debug
                    .field("users", users)
                    .field("obfs", &obfs.is_some())
                    .field("udp", udp);
            }
            Self::Tuic { users, alpn, .. } => {
                debug.field("users", users).field("alpn", alpn);
            }
            Self::ShadowTls {
                users,
                handshake,
                strict_mode,
                detour,
                version,
                ..
            } => {
                debug
                    .field("version", version)
                    .field("users", users)
                    .field("handshake", handshake)
                    .field("strict_mode", strict_mode)
                    .field("detour", detour);
            }
            Self::Nw3 { morph, out, .. } => {
                // 共享密钥不进入调试输出。
                debug.field("morph", morph).field("out", out);
            }
            Self::DokodemoDoor {
                address,
                port,
                network,
                sniffing,
                ..
            } => {
                debug
                    .field("address", address)
                    .field("port", port)
                    .field("network", network)
                    .field("sniffing", sniffing);
            }
            Self::Vless { users, xudp, .. }
            | Self::VlessReality { users, xudp, .. }
            | Self::VlessGrpc { users, xudp, .. }
            | Self::VlessXhttp { users, xudp, .. }
            | Self::VlessHttpUpgrade { users, xudp, .. }
            | Self::VlessWs { users, xudp, .. }
            | Self::VlessKcp { users, xudp, .. }
            | Self::VlessHttp { users, xudp, .. }
            | Self::VlessQuic { users, xudp, .. } => {
                debug.field("users", users).field("xudp", xudp);
            }
            Self::Vmess {
                users,
                xudp,
                packetaddr,
                allow_insecure_body,
                allow_authenticated_length,
                ..
            }
            | Self::VmessReality {
                users,
                xudp,
                packetaddr,
                allow_insecure_body,
                allow_authenticated_length,
                ..
            }
            | Self::VmessGrpc {
                users,
                xudp,
                packetaddr,
                allow_insecure_body,
                allow_authenticated_length,
                ..
            }
            | Self::VmessWs {
                users,
                xudp,
                packetaddr,
                allow_insecure_body,
                allow_authenticated_length,
                ..
            }
            | Self::VmessXhttp {
                users,
                xudp,
                packetaddr,
                allow_insecure_body,
                allow_authenticated_length,
                ..
            }
            | Self::VmessHttpUpgrade {
                users,
                xudp,
                packetaddr,
                allow_insecure_body,
                allow_authenticated_length,
                ..
            }
            | Self::VmessKcp {
                users,
                xudp,
                packetaddr,
                allow_insecure_body,
                allow_authenticated_length,
                ..
            }
            | Self::VmessHttp {
                users,
                xudp,
                packetaddr,
                allow_insecure_body,
                allow_authenticated_length,
                ..
            } => {
                debug
                    .field("users", users)
                    .field("xudp", xudp)
                    .field("packetaddr", packetaddr)
                    .field("allow_insecure_body", allow_insecure_body)
                    .field("allow_authenticated_length", allow_authenticated_length);
            }
            Self::VmessQuic {
                users,
                xudp,
                packetaddr,
                allow_authenticated_length,
                ..
            } => {
                debug
                    .field("users", users)
                    .field("xudp", xudp)
                    .field("packetaddr", packetaddr)
                    .field("allow_authenticated_length", allow_authenticated_length);
            }
            Self::Wireguard { peers, .. } => {
                debug.field("peers", peers);
            }
        }
        match self {
            Self::VlessWs {
                websocket,
                allow_insecure_transport,
                ..
            }
            | Self::TrojanWs {
                websocket,
                allow_insecure_transport,
                ..
            } => {
                debug
                    .field("websocket", websocket)
                    .field("allow_insecure_transport", allow_insecure_transport);
            }
            Self::VmessWs { websocket, .. } => {
                debug.field("websocket", websocket);
            }
            Self::VlessGrpc { .. } | Self::VmessGrpc { .. } | Self::TrojanGrpc { .. } => {
                // 路径可能含私有服务名，仅标记已配置，不输出内容。
                debug.field("grpc", &"[CONFIGURED]");
            }
            Self::VlessXhttp { .. } | Self::VmessXhttp { .. } | Self::TrojanXhttp { .. } => {
                // 主机/路径可能含私有材料，仅标记已配置。
                debug.field("xhttp", &"[CONFIGURED]");
            }
            Self::VlessHttpUpgrade { .. }
            | Self::VmessHttpUpgrade { .. }
            | Self::TrojanHttpUpgrade { .. } => {
                debug.field("httpupgrade", &"[CONFIGURED]");
            }
            Self::VlessReality { reality, .. }
            | Self::VmessReality { reality, .. }
            | Self::TrojanReality { reality, .. } => {
                debug.field("reality", reality);
            }
            _ => {}
        }
        // 路径虽不是密钥内容，也可能含私有材料；包括不完整 TLS 对在内均不输出。
        debug.field("tls_paths", &"[REDACTED]").finish()
    }
}
