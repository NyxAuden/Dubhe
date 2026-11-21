use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, de};

/// XHTTP 上行模式；auto 由服务端接受任一合法请求形状。
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Auto,
    StreamOne,
    StreamUp,
    PacketUp,
}

/// XHTTP 入站配置；路径与模式为兼容性核心，其余为有界资源参数。
///
/// 反序列化额外接受 Xray 风格的 `extra` 对象，但只映射可由本内核服务端
/// 语义真实承接的字段；映射结果会规范化到下面的顶层字段。`extra` 与顶层
/// 字段出现同一语义时拒绝加载，不做静默覆盖。
#[derive(Clone, Debug, Serialize)]
pub struct Xhttp {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub no_sse_header: bool,
    /// 附加到每个下行响应上的静态头；名称/值在加载时严格校验。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_post_bytes")]
    pub sc_max_each_post_bytes: u32,
    #[serde(default = "default_buffered_posts")]
    pub sc_max_buffered_posts: usize,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding: Option<Padding>,
    /// 混淆 padding 模式：请求/响应按 `x_padding_placement` 放置。
    #[serde(default)]
    pub x_padding_obfs_mode: bool,
    #[serde(default = "default_padding_key")]
    pub x_padding_key: String,
    #[serde(default = "default_padding_header")]
    pub x_padding_header: String,
    /// `queryInHeader`（默认）、`cookie`、`header`、`query`。
    #[serde(default = "default_padding_placement")]
    pub x_padding_placement: String,
    /// 目前仅支持 `repeat-x`；`tokenish` 在加载时拒绝。
    #[serde(default = "default_padding_method")]
    pub x_padding_method: String,
    /// 会话标识放置位置：`path`（默认）、`cookie`、`header`、`query`。
    #[serde(default = "default_meta_placement")]
    pub session_id_placement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id_key: Option<String>,
    /// 序号放置位置：`path`（默认）、`cookie`、`header`、`query`。
    #[serde(default = "default_meta_placement")]
    pub seq_placement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq_key: Option<String>,
    /// packet-up 上行数据放置位置：`body`（默认）、`auto`、`cookie`、`header`。
    #[serde(default = "default_uplink_data_placement")]
    pub uplink_data_placement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_data_key: Option<String>,
    /// HTTP/1.1 与 HTTP/2 服务端请求头上限；0 表示上游默认 8192。
    #[serde(default)]
    pub server_max_header_bytes: u32,
    /// 使用 QUIC/HTTP3 承载而不是 TCP 上的 HTTP/1.1 或 HTTP/2。
    /// QUIC 强制 TLS 1.3，因此必须配置真实证书与私钥。
    #[serde(default)]
    pub h3: bool,
}

/// 允许的 x_padding 长度范围；空填充始终接受。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Padding {
    pub from: usize,
    pub to: usize,
}

const fn default_post_bytes() -> u32 {
    1_000_000
}
const fn default_buffered_posts() -> usize {
    30
}
const fn default_session_ttl() -> u64 {
    30_000
}
fn default_padding_key() -> String {
    "x_padding".to_owned()
}
fn default_padding_header() -> String {
    "X-Padding".to_owned()
}
fn default_padding_placement() -> String {
    "queryInHeader".to_owned()
}
fn default_padding_method() -> String {
    "repeat-x".to_owned()
}
fn default_meta_placement() -> String {
    "path".to_owned()
}
fn default_uplink_data_placement() -> String {
    "body".to_owned()
}
const fn default_server_max_header_bytes() -> u32 {
    8_192
}

impl Padding {
    pub const DEFAULT: Self = Self {
        from: 100,
        to: 1_000,
    };
    pub fn contains(&self, length: usize) -> bool {
        length == 0 || (self.from..=self.to).contains(&length)
    }
}

impl Xhttp {
    pub fn validate(&self, inbound_index: usize) -> Result<()> {
        validate(self, inbound_index)
    }

    pub fn padding(&self) -> Padding {
        match self.x_padding {
            // Xray 把零范围归一化为默认 100..1000。
            Some(padding) if padding.to > 0 => padding,
            _ => Padding::DEFAULT,
        }
    }

    /// 生效的会话 key；`path` 放置没有 key。
    pub fn session_key(&self) -> Option<&str> {
        placement_key(
            &self.session_id_placement,
            self.session_id_key.as_deref(),
            "x_session",
            "X-Session",
        )
    }

    /// 生效的序号 key；`path` 放置没有 key。
    pub fn seq_key(&self) -> Option<&str> {
        placement_key(
            &self.seq_placement,
            self.seq_key.as_deref(),
            "x_seq",
            "X-Seq",
        )
    }

    /// 生效的上行数据 key；`body` 放置没有 key。
    pub fn uplink_data_key(&self) -> Option<&str> {
        match self.uplink_data_placement.as_str() {
            "body" => None,
            "cookie" => Some(self.uplink_data_key.as_deref().unwrap_or("x_data")),
            _ => Some(self.uplink_data_key.as_deref().unwrap_or("X-Data")),
        }
    }

    /// 服务端请求头上限；0 归一化为上游默认 8192。
    pub fn server_max_header_bytes(&self) -> usize {
        if self.server_max_header_bytes == 0 {
            8_192
        } else {
            self.server_max_header_bytes as usize
        }
    }
}

fn placement_key<'a>(
    placement: &str,
    configured: Option<&'a str>,
    lower: &'a str,
    header: &'a str,
) -> Option<&'a str> {
    match placement {
        "path" => None,
        "cookie" | "query" => Some(configured.unwrap_or(lower)),
        "header" => Some(configured.unwrap_or(header)),
        _ => None,
    }
}

/// 顶层字段的原始形状：保留“是否显式出现”，用于拒绝 `extra` 冲突。
/// `deny_unknown_fields` 维持顶层配置的严格性。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XhttpRaw {
    path: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    mode: Option<Mode>,
    #[serde(default)]
    no_sse_header: Option<bool>,
    #[serde(default)]
    headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    sc_max_each_post_bytes: Option<u32>,
    #[serde(default)]
    sc_max_buffered_posts: Option<usize>,
    #[serde(default)]
    session_ttl_ms: Option<u64>,
    #[serde(default)]
    x_padding: Option<Padding>,
    #[serde(default)]
    x_padding_obfs_mode: Option<bool>,
    #[serde(default)]
    x_padding_key: Option<String>,
    #[serde(default)]
    x_padding_header: Option<String>,
    #[serde(default)]
    x_padding_placement: Option<String>,
    #[serde(default)]
    x_padding_method: Option<String>,
    #[serde(default)]
    session_id_placement: Option<String>,
    #[serde(default)]
    session_id_key: Option<String>,
    #[serde(default)]
    seq_placement: Option<String>,
    #[serde(default)]
    seq_key: Option<String>,
    #[serde(default)]
    uplink_data_placement: Option<String>,
    #[serde(default)]
    uplink_data_key: Option<String>,
    #[serde(default)]
    server_max_header_bytes: Option<u32>,
    #[serde(default)]
    h3: Option<bool>,
    /// Xray 风格 `extra`；仅接受可安全映射到服务端线格式的子集。
    #[serde(default)]
    extra: Option<XhttpExtra>,
}

impl<'de> Deserialize<'de> for Xhttp {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        XhttpRaw::deserialize(deserializer)?
            .build()
            .map_err(de::Error::custom)
    }
}

impl XhttpRaw {
    fn build(self) -> std::result::Result<Xhttp, String> {
        let top_level = TopLevelPresence {
            no_sse_header: self.no_sse_header.is_some(),
            sc_max_each_post_bytes: self.sc_max_each_post_bytes.is_some(),
            sc_max_buffered_posts: self.sc_max_buffered_posts.is_some(),
            x_padding: self.x_padding.is_some(),
            x_padding_obfs_mode: self.x_padding_obfs_mode.is_some(),
            x_padding_key: self.x_padding_key.is_some(),
            x_padding_header: self.x_padding_header.is_some(),
            x_padding_placement: self.x_padding_placement.is_some(),
            x_padding_method: self.x_padding_method.is_some(),
            session_id_placement: self.session_id_placement.is_some(),
            session_id_key: self.session_id_key.is_some(),
            seq_placement: self.seq_placement.is_some(),
            seq_key: self.seq_key.is_some(),
            uplink_data_placement: self.uplink_data_placement.is_some(),
            uplink_data_key: self.uplink_data_key.is_some(),
            server_max_header_bytes: self.server_max_header_bytes.is_some(),
        };
        let mut xhttp = Xhttp {
            path: self.path,
            host: self.host,
            mode: self.mode.unwrap_or_default(),
            no_sse_header: self.no_sse_header.unwrap_or(false),
            headers: self.headers.unwrap_or_default(),
            sc_max_each_post_bytes: self
                .sc_max_each_post_bytes
                .unwrap_or_else(default_post_bytes),
            sc_max_buffered_posts: self
                .sc_max_buffered_posts
                .unwrap_or_else(default_buffered_posts),
            session_ttl_ms: self.session_ttl_ms.unwrap_or_else(default_session_ttl),
            x_padding: self.x_padding,
            x_padding_obfs_mode: self.x_padding_obfs_mode.unwrap_or(false),
            x_padding_key: self.x_padding_key.unwrap_or_else(default_padding_key),
            x_padding_header: self.x_padding_header.unwrap_or_else(default_padding_header),
            x_padding_placement: self
                .x_padding_placement
                .unwrap_or_else(default_padding_placement),
            x_padding_method: self.x_padding_method.unwrap_or_else(default_padding_method),
            session_id_placement: self
                .session_id_placement
                .unwrap_or_else(default_meta_placement),
            session_id_key: self.session_id_key,
            seq_placement: self.seq_placement.unwrap_or_else(default_meta_placement),
            seq_key: self.seq_key,
            uplink_data_placement: self
                .uplink_data_placement
                .unwrap_or_else(default_uplink_data_placement),
            uplink_data_key: self.uplink_data_key,
            server_max_header_bytes: self
                .server_max_header_bytes
                .unwrap_or_else(default_server_max_header_bytes),
            h3: self.h3.unwrap_or(false),
        };
        if let Some(extra) = self.extra {
            extra.apply(&mut xhttp, top_level)?;
        }
        Ok(xhttp)
    }
}

#[derive(Clone, Copy)]
struct TopLevelPresence {
    no_sse_header: bool,
    sc_max_each_post_bytes: bool,
    sc_max_buffered_posts: bool,
    x_padding: bool,
    x_padding_obfs_mode: bool,
    x_padding_key: bool,
    x_padding_header: bool,
    x_padding_placement: bool,
    x_padding_method: bool,
    session_id_placement: bool,
    session_id_key: bool,
    seq_placement: bool,
    seq_key: bool,
    uplink_data_placement: bool,
    uplink_data_key: bool,
    server_max_header_bytes: bool,
}

/// Xray v26.10.31 `SplitHTTPConfig.extra` 的严格子集。
///
/// 可映射字段沿用上游 JSON 名称与值形状；其余已知字段显式声明后拒绝，
/// 未知字段由 `deny_unknown_fields` 拒绝。这里不使用 `flatten`，避免破坏
/// 未知字段诊断。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XhttpExtra {
    #[serde(rename = "xPaddingBytes")]
    x_padding_bytes: Option<XrayIntRange>,
    #[serde(rename = "scMaxEachPostBytes")]
    sc_max_each_post_bytes: Option<XrayIntRange>,
    #[serde(rename = "scMaxBufferedPosts")]
    sc_max_buffered_posts: Option<i64>,
    #[serde(rename = "noSSEHeader")]
    no_sse_header: Option<bool>,

    // 服务端可真实承接的线格式/行为字段。
    #[serde(rename = "xPaddingObfsMode")]
    x_padding_obfs_mode: Option<bool>,
    #[serde(rename = "xPaddingKey")]
    x_padding_key: Option<String>,
    #[serde(rename = "xPaddingHeader")]
    x_padding_header: Option<String>,
    #[serde(rename = "xPaddingPlacement")]
    x_padding_placement: Option<String>,
    #[serde(rename = "xPaddingMethod")]
    x_padding_method: Option<String>,
    #[serde(rename = "sessionIDPlacement")]
    session_id_placement: Option<String>,
    #[serde(rename = "sessionIDKey")]
    session_id_key: Option<String>,
    #[serde(rename = "seqPlacement")]
    seq_placement: Option<String>,
    #[serde(rename = "seqKey")]
    seq_key: Option<String>,
    #[serde(rename = "uplinkDataPlacement")]
    uplink_data_placement: Option<String>,
    #[serde(rename = "uplinkDataKey")]
    uplink_data_key: Option<String>,
    #[serde(rename = "scStreamUpServerSecs")]
    sc_stream_up_server_secs: Option<serde_json::Value>,
    #[serde(rename = "serverMaxHeaderBytes")]
    server_max_header_bytes: Option<i64>,

    // 以下字段属于客户端请求形状/独立下行/连接复用，或本内核无法等价
    // 承接；全部显式拒绝，绝不静默忽略或假装支持。
    host: Option<serde_json::Value>,
    path: Option<serde_json::Value>,
    mode: Option<serde_json::Value>,
    headers: Option<serde_json::Value>,
    #[serde(rename = "uplinkHTTPMethod")]
    uplink_http_method: Option<serde_json::Value>,
    #[serde(rename = "sessionIDTable")]
    session_id_table: Option<serde_json::Value>,
    #[serde(rename = "sessionIDLength")]
    session_id_length: Option<serde_json::Value>,
    #[serde(rename = "uplinkChunkSize")]
    uplink_chunk_size: Option<serde_json::Value>,
    #[serde(rename = "noGRPCHeader")]
    no_grpc_header: Option<serde_json::Value>,
    #[serde(rename = "scMinPostsIntervalMs")]
    sc_min_posts_interval_ms: Option<serde_json::Value>,
    xmux: Option<serde_json::Value>,
    #[serde(rename = "downloadSettings")]
    download_settings: Option<serde_json::Value>,
    #[serde(rename = "h2Params")]
    h2_params: Option<serde_json::Value>,
    extra: Option<serde_json::Value>,
}

impl XhttpExtra {
    fn apply(
        self,
        xhttp: &mut Xhttp,
        top_level: TopLevelPresence,
    ) -> std::result::Result<(), String> {
        self.reject_unsupported()?;

        if self.x_padding_bytes.is_some() && top_level.x_padding {
            return Err(
                "xhttp.extra.xPaddingBytes 与顶层 xhttp.x_padding 语义冲突，拒绝静默覆盖".into(),
            );
        }
        if self.sc_max_each_post_bytes.is_some() && top_level.sc_max_each_post_bytes {
            return Err(
                "xhttp.extra.scMaxEachPostBytes 与顶层 xhttp.sc_max_each_post_bytes 语义冲突，拒绝静默覆盖"
                    .into(),
            );
        }
        if self.sc_max_buffered_posts.is_some() && top_level.sc_max_buffered_posts {
            return Err(
                "xhttp.extra.scMaxBufferedPosts 与顶层 xhttp.sc_max_buffered_posts 语义冲突，拒绝静默覆盖"
                    .into(),
            );
        }
        if self.no_sse_header.is_some() && top_level.no_sse_header {
            return Err(
                "xhttp.extra.noSSEHeader 与顶层 xhttp.no_sse_header 语义冲突，拒绝静默覆盖".into(),
            );
        }
        for (name, duplicated) in [
            (
                "xPaddingObfsMode",
                self.x_padding_obfs_mode.is_some() && top_level.x_padding_obfs_mode,
            ),
            (
                "xPaddingKey",
                self.x_padding_key.is_some() && top_level.x_padding_key,
            ),
            (
                "xPaddingHeader",
                self.x_padding_header.is_some() && top_level.x_padding_header,
            ),
            (
                "xPaddingPlacement",
                self.x_padding_placement.is_some() && top_level.x_padding_placement,
            ),
            (
                "xPaddingMethod",
                self.x_padding_method.is_some() && top_level.x_padding_method,
            ),
            (
                "sessionIDPlacement",
                self.session_id_placement.is_some() && top_level.session_id_placement,
            ),
            (
                "sessionIDKey",
                self.session_id_key.is_some() && top_level.session_id_key,
            ),
            (
                "seqPlacement",
                self.seq_placement.is_some() && top_level.seq_placement,
            ),
            ("seqKey", self.seq_key.is_some() && top_level.seq_key),
            (
                "uplinkDataPlacement",
                self.uplink_data_placement.is_some() && top_level.uplink_data_placement,
            ),
            (
                "uplinkDataKey",
                self.uplink_data_key.is_some() && top_level.uplink_data_key,
            ),
            (
                "serverMaxHeaderBytes",
                self.server_max_header_bytes.is_some() && top_level.server_max_header_bytes,
            ),
        ] {
            if duplicated {
                return Err(format!(
                    "xhttp.extra.{name} 与顶层同义字段冲突，拒绝静默覆盖"
                ));
            }
        }

        if let Some(range) = self.x_padding_bytes {
            xhttp.x_padding = Some(padding_from_xray(range)?);
        }
        if let Some(range) = self.sc_max_each_post_bytes {
            xhttp.sc_max_each_post_bytes = post_bytes_from_xray(range)?;
        }
        if let Some(value) = self.sc_max_buffered_posts {
            xhttp.sc_max_buffered_posts = buffered_posts_from_xray(value)?;
        }
        if let Some(value) = self.no_sse_header {
            xhttp.no_sse_header = value;
        }
        if let Some(value) = self.x_padding_obfs_mode {
            xhttp.x_padding_obfs_mode = value;
        }
        if let Some(value) = self.x_padding_key {
            xhttp.x_padding_key = value;
        }
        if let Some(value) = self.x_padding_header {
            xhttp.x_padding_header = value;
        }
        if let Some(value) = self.x_padding_placement {
            xhttp.x_padding_placement = value;
        }
        if let Some(value) = self.x_padding_method {
            xhttp.x_padding_method = value;
        }
        if let Some(value) = self.session_id_placement {
            xhttp.session_id_placement = value;
        }
        if let Some(value) = self.session_id_key {
            xhttp.session_id_key = Some(value);
        }
        if let Some(value) = self.seq_placement {
            xhttp.seq_placement = value;
        }
        if let Some(value) = self.seq_key {
            xhttp.seq_key = Some(value);
        }
        if let Some(value) = self.uplink_data_placement {
            xhttp.uplink_data_placement = value;
        }
        if let Some(value) = self.uplink_data_key {
            xhttp.uplink_data_key = Some(value);
        }
        if let Some(value) = self.server_max_header_bytes {
            xhttp.server_max_header_bytes = server_max_header_from_xray(value)?;
        }
        Ok(())
    }

    fn reject_unsupported(&self) -> std::result::Result<(), String> {
        if self.download_settings.is_some() {
            return Err(
                "xhttp.extra.downloadSettings 不受支持：这是客户端独立下行连接配置（含独立目标/TLS/路径），本内核出站 XHTTP 参数不接受该对象，入站也无下行连接可配置"
                    .into(),
            );
        }
        for (name, present) in [
            ("host", self.host.is_some()),
            ("path", self.path.is_some()),
            ("mode", self.mode.is_some()),
        ] {
            if present {
                return Err(format!(
                    "xhttp.extra.{name} 不受支持：Xray 会用顶层值覆盖 {name}，本实现拒绝在 extra 中重复表达"
                ));
            }
        }
        if self.headers.is_some() {
            return Err(
                "xhttp.extra.headers 不受支持：Xray 的 headers 是客户端请求头语义，本内核入站 headers 是下行响应头，二者不能安全互换"
                    .into(),
            );
        }
        if self.uplink_http_method.is_some() {
            return Err(
                "xhttp.extra.uplinkHTTPMethod 不受支持：这是客户端上行方法配置；服务端按请求形状分类，本内核不把它作为入站配置项"
                    .into(),
            );
        }
        for (name, present) in [
            ("sessionIDTable", self.session_id_table.is_some()),
            ("sessionIDLength", self.session_id_length.is_some()),
        ] {
            if present {
                return Err(format!(
                    "xhttp.extra.{name} 不受支持：只用于客户端生成会话标识，服务端不生成会话 ID"
                ));
            }
        }
        if self.uplink_chunk_size.is_some() {
            return Err(
                "xhttp.extra.uplinkChunkSize 不受支持：只控制客户端把上行数据切分成头/Cookie 块的大小，服务端解码不依赖该值"
                    .into(),
            );
        }
        if self.no_grpc_header.is_some() {
            return Err(
                "xhttp.extra.noGRPCHeader 不受支持：这是客户端请求 Content-Type 形状配置，服务端不校验该头"
                    .into(),
            );
        }
        if self.sc_min_posts_interval_ms.is_some() {
            return Err(
                "xhttp.extra.scMinPostsIntervalMs 不受支持：这是客户端 POST 发送间隔，服务端无对应行为"
                    .into(),
            );
        }
        if self.sc_stream_up_server_secs.is_some() {
            return Err(
                "xhttp.extra.scStreamUpServerSecs 不受支持：需要 stream-up 服务端定时向 POST 响应体写入保活填充，本内核当前未实现该定时器"
                    .into(),
            );
        }
        if self.xmux.is_some() {
            return Err(
                "xhttp.extra.xmux 不受支持：属于客户端连接复用/请求配额参数，服务端无对应行为"
                    .into(),
            );
        }
        if self.h2_params.is_some() {
            return Err(
                "xhttp.extra.h2Params 不受支持：需要等价覆盖 SETTINGS、流控窗口与超时等 HTTP/2 参数，本内核的 h2/h3 承载无法逐项等价映射"
                    .into(),
            );
        }
        if self.extra.is_some() {
            return Err("xhttp.extra.extra 不受支持：拒绝嵌套 extra".into());
        }
        Ok(())
    }
}

/// Xray `Int32Range`：接受整数或 `"from-to"` 字符串，`from > to` 时交换。
/// 与会改变线格式的字段一样，这里只用于可安全映射到本内核的字段。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct XrayIntRange {
    from: i32,
    to: i32,
}

impl<'de> Deserialize<'de> for XrayIntRange {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RangeVisitor;

        impl<'de> de::Visitor<'de> for RangeVisitor {
            type Value = XrayIntRange;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("整数或形如 \"100-1000\" 的范围字符串")
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                XrayIntRange::new(value, value).map_err(E::custom)
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                let value =
                    i64::try_from(value).map_err(|_| E::custom("xhttp.extra 范围端点超出 i32"))?;
                XrayIntRange::new(value, value).map_err(E::custom)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                let (left, right) = parse_xray_range(value).map_err(E::custom)?;
                XrayIntRange::new(left, right).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(RangeVisitor)
    }
}

impl XrayIntRange {
    fn new(left: i64, right: i64) -> std::result::Result<Self, String> {
        let left =
            i32::try_from(left).map_err(|_| "xhttp.extra 范围端点超出 i32 范围".to_owned())?;
        let right =
            i32::try_from(right).map_err(|_| "xhttp.extra 范围端点超出 i32 范围".to_owned())?;
        // 与 Xray 的 ensureOrder 一致：保证 from <= to。
        Ok(Self {
            from: left.min(right),
            to: left.max(right),
        })
    }

    fn is_zero(self) -> bool {
        self.from == 0 && self.to == 0
    }
}

/// 复刻 Xray `ParseRangeString`：支持 `"114"`、`"114-514"`、
/// `"-114-514"`、`"-1919--810"` 与空字符串（0/0）。
fn parse_xray_range(value: &str) -> std::result::Result<(i64, i64), String> {
    if let Ok(single) = value.parse::<i64>() {
        return Ok((single, single));
    }
    if value.is_empty() {
        return Ok((0, 0));
    }
    let (left, right) = if value.starts_with('-') {
        match value.splitn(3, '-').collect::<Vec<_>>().as_slice() {
            [first, second, rest] => (format!("{first}-{second}"), (*rest).to_owned()),
            _ => {
                return Err(format!(
                    "无效的 xhttp.extra 范围字符串 {value:?}，应为整数或 \"from-to\""
                ));
            }
        }
    } else {
        match value.splitn(2, '-').collect::<Vec<_>>().as_slice() {
            [left, right] => ((*left).to_owned(), (*right).to_owned()),
            _ => {
                return Err(format!(
                    "无效的 xhttp.extra 范围字符串 {value:?}，应为整数或 \"from-to\""
                ));
            }
        }
    };
    let left = left
        .parse::<i64>()
        .map_err(|_| format!("无效的 xhttp.extra 范围字符串 {value:?}，应为整数或 \"from-to\""))?;
    let right = right
        .parse::<i64>()
        .map_err(|_| format!("无效的 xhttp.extra 范围字符串 {value:?}，应为整数或 \"from-to\""))?;
    Ok((left, right))
}

fn padding_from_xray(range: XrayIntRange) -> std::result::Result<Padding, String> {
    if range.is_zero() {
        // Xray GetNormalizedXPaddingBytes 对零值返回默认 100..1000。
        return Ok(Padding::DEFAULT);
    }
    if range.from <= 0 || range.to <= 0 {
        return Err(
            "xhttp.extra.xPaddingBytes 不能禁用 padding：from/to 必须为正整数（0 表示默认范围）"
                .into(),
        );
    }
    Ok(Padding {
        from: range.from as usize,
        to: range.to as usize,
    })
}

fn post_bytes_from_xray(range: XrayIntRange) -> std::result::Result<u32, String> {
    if range.is_zero() {
        // Xray GetNormalizedScMaxEachPostBytes 对零值返回 1,000,000。
        return Ok(default_post_bytes());
    }
    if range.from <= 0 || range.to <= 0 {
        return Err(
            "xhttp.extra.scMaxEachPostBytes 的 from/to 必须为正整数（0 表示默认值）".into(),
        );
    }
    // 与 Xray 服务端 hub.go 一致：单次 POST 上限使用范围的 To。
    Ok(range.to as u32)
}

fn buffered_posts_from_xray(value: i64) -> std::result::Result<usize, String> {
    if value == 0 {
        // Xray GetNormalizedScMaxBufferedPosts 对 0 返回 30。
        return Ok(default_buffered_posts());
    }
    usize::try_from(value)
        .map_err(|_| "xhttp.extra.scMaxBufferedPosts 必须为非负整数（0 表示默认值）".to_owned())
}

fn server_max_header_from_xray(value: i64) -> std::result::Result<u32, String> {
    if value < 0 {
        return Err("xhttp.extra.serverMaxHeaderBytes 不能为负数".into());
    }
    if value == 0 {
        // Xray GetNormalizedServerMaxHeaderBytes 对 <=0 返回 8192。
        return Ok(default_server_max_header_bytes());
    }
    if value > 16 * 1024 * 1024 {
        return Err("xhttp.extra.serverMaxHeaderBytes 不能超过16MiB".into());
    }
    Ok(value as u32)
}

fn valid_path(path: &str) -> bool {
    (1..=1024).contains(&path.len())
        && path.starts_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#' && byte != b'?')
}

pub(super) fn validate(xhttp: &Xhttp, inbound_index: usize) -> Result<()> {
    ensure!(
        valid_path(&xhttp.path),
        "inbounds[{inbound_index}].xhttp.path 必须是1到1024字节、以/开头的ASCII路径"
    );
    if let Some(host) = &xhttp.host {
        ensure!(
            (1..=255).contains(&host.len()) && host.bytes().all(|b| b.is_ascii_graphic()),
            "inbounds[{inbound_index}].xhttp.host 必须是1到255字节的ASCII主机名"
        );
    }
    ensure!(
        (64..=16 * 1024 * 1024).contains(&xhttp.sc_max_each_post_bytes),
        "inbounds[{inbound_index}].xhttp.sc_max_each_post_bytes 必须在64到16MiB之间"
    );
    ensure!(
        (1..=1024).contains(&xhttp.sc_max_buffered_posts),
        "inbounds[{inbound_index}].xhttp.sc_max_buffered_posts 必须在1到1024之间"
    );
    ensure!(
        (1_000..=600_000).contains(&xhttp.session_ttl_ms),
        "inbounds[{inbound_index}].xhttp.session_ttl_ms 必须在1000到600000之间"
    );
    ensure!(
        xhttp.headers.len() <= 16,
        "inbounds[{inbound_index}].xhttp.headers 最多16项"
    );
    for (name, value) in &xhttp.headers {
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b':')
                && !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("transfer-encoding")
                && !name.eq_ignore_ascii_case("connection")
                && !name.eq_ignore_ascii_case("host"),
            "inbounds[{inbound_index}].xhttp.headers 名称非法或受保护"
        );
        ensure!(
            value.len() <= 1024 && !value.contains(['\r', '\n']),
            "inbounds[{inbound_index}].xhttp.headers[{name}] 值非法"
        );
    }
    if let Some(padding) = xhttp.x_padding {
        ensure!(
            padding.from <= padding.to && padding.to <= 16_384,
            "inbounds[{inbound_index}].xhttp.x_padding 必须满足 from<=to<=16384"
        );
    }
    ensure!(
        matches!(
            xhttp.x_padding_placement.as_str(),
            "queryInHeader" | "cookie" | "header" | "query"
        ),
        "inbounds[{inbound_index}].xhttp.x_padding_placement 必须是 queryInHeader/cookie/header/query"
    );
    ensure!(
        valid_name(&xhttp.x_padding_key),
        "inbounds[{inbound_index}].xhttp.x_padding_key 必须是1到64字节的安全ASCII键名"
    );
    if xhttp.x_padding_placement != "query" {
        ensure!(
            valid_header_name(&xhttp.x_padding_header),
            "inbounds[{inbound_index}].xhttp.x_padding_header 必须是安全的HTTP头名称"
        );
    }
    for (name, placement) in [
        ("session_id_placement", xhttp.session_id_placement.as_str()),
        ("seq_placement", xhttp.seq_placement.as_str()),
    ] {
        ensure!(
            matches!(placement, "path" | "cookie" | "header" | "query"),
            "inbounds[{inbound_index}].xhttp.{name} 必须是 path/cookie/header/query"
        );
    }
    ensure!(
        matches!(
            xhttp.uplink_data_placement.as_str(),
            "body" | "auto" | "cookie" | "header"
        ),
        "inbounds[{inbound_index}].xhttp.uplink_data_placement 必须是 body/auto/cookie/header"
    );
    if xhttp.session_id_placement != "path"
        && let Some(key) = xhttp.session_key()
    {
        ensure!(
            valid_placement_key(&xhttp.session_id_placement, key),
            "inbounds[{inbound_index}].xhttp.session_id_key 非法"
        );
    }
    if xhttp.seq_placement != "path"
        && let Some(key) = xhttp.seq_key()
    {
        ensure!(
            valid_placement_key(&xhttp.seq_placement, key),
            "inbounds[{inbound_index}].xhttp.seq_key 非法"
        );
    }
    if xhttp.uplink_data_placement != "body"
        && let Some(key) = xhttp.uplink_data_key()
    {
        let placement = if xhttp.uplink_data_placement == "cookie" {
            "cookie"
        } else {
            "header"
        };
        ensure!(
            valid_placement_key(placement, key),
            "inbounds[{inbound_index}].xhttp.uplink_data_key 非法"
        );
    }
    ensure!(
        xhttp.server_max_header_bytes == 0
            || (128..=16 * 1024 * 1024).contains(&xhttp.server_max_header_bytes),
        "inbounds[{inbound_index}].xhttp.server_max_header_bytes 必须为0（默认8192）或128到16MiB之间"
    );
    ensure!(
        xhttp.x_padding_method == "repeat-x",
        "inbounds[{inbound_index}].xhttp.x_padding_method 目前仅支持 repeat-x；tokenish 需要逐字节复刻 HPACK Huffman 长度表，未实现"
    );
    if xhttp.x_padding_obfs_mode {
        // 混淆模式下客户端必须发送可校验的 padding；不是认证，但缺失即拒绝。
        ensure!(
            xhttp.padding().to > 0,
            "inbounds[{inbound_index}].xhttp.x_padding_obfs_mode 需要非零 padding 范围"
        );
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_graphic() && !matches!(byte, b'=' | b'&' | b';' | b',' | b'"' | b'#')
        })
}

fn valid_header_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && http::header::HeaderName::from_bytes(value.as_bytes()).is_ok()
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "content-length"
                | "transfer-encoding"
                | "connection"
                | "host"
                | "keep-alive"
                | "proxy-connection"
                | "upgrade"
                | "te"
                | "trailer"
        )
}

fn valid_placement_key(placement: &str, key: &str) -> bool {
    match placement {
        "cookie" | "header" => valid_header_name(key),
        "query" => valid_name(key) && !key.contains('?'),
        _ => false,
    }
}

/// HTTP/3 只能运行在 QUIC 的 TLS 1.3 之上，明文入口不可用。
pub(super) fn validate_h3(
    h3: bool,
    certificate: Option<&std::path::Path>,
    inbound_index: usize,
) -> Result<()> {
    ensure!(
        !h3 || certificate.is_some(),
        "inbounds[{inbound_index}] xhttp.h3 需要真实 TLS 证书与私钥"
    );
    Ok(())
}

/// XHTTP 承载的 TLS 策略与 gRPC 一致：VLESS/Trojan 可显式明文，VMess 必须真实 TLS。
pub(super) fn validate_tls(
    certificate: Option<&std::path::Path>,
    private_key: Option<&std::path::Path>,
    allow_plaintext: bool,
    inbound_index: usize,
) -> Result<()> {
    ensure!(
        certificate.is_some() == private_key.is_some(),
        "inbounds[{inbound_index}].certificate 和 private_key 必须成对配置"
    );
    ensure!(
        certificate.is_some() || allow_plaintext,
        "inbounds[{inbound_index}] 无 TLS 的 XHTTP 入口必须显式设置 allow_insecure_transport=true"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(json: &str) -> Xhttp {
        serde_json::from_str(json).unwrap()
    }

    fn error(json: &str) -> String {
        serde_json::from_str::<Xhttp>(json).unwrap_err().to_string()
    }

    #[test]
    fn h3_requires_real_tls() {
        let x = value(r#"{"path":"/x","h3":true}"#);
        assert!(x.h3);
        assert!(!value(r#"{"path":"/x"}"#).h3);
        assert!(validate_h3(true, None, 0).is_err());
        assert!(validate_h3(true, Some(std::path::Path::new("/tmp/cert.pem")), 0).is_ok());
        assert!(validate_h3(false, None, 0).is_ok());
    }

    #[test]
    fn defaults_and_bounds() {
        let x = value(r#"{"path":"/x"}"#);
        assert_eq!(x.mode, Mode::Auto);
        assert_eq!(x.sc_max_each_post_bytes, 1_000_000);
        assert_eq!(x.sc_max_buffered_posts, 30);
        assert_eq!(x.session_ttl_ms, 30_000);
        assert_eq!(x.padding().from, 100);
        x.validate(0).unwrap();
        assert!(
            value(r#"{"path":"/x","sc_max_each_post_bytes":63}"#)
                .validate(0)
                .is_err()
        );
        assert!(value(r#"{"path":"x"}"#).validate(0).is_err());
        assert!(serde_json::from_str::<Xhttp>(r#"{"path":"/x","mode":"weird"}"#).is_err());
    }

    #[test]
    fn extra_maps_supported_fields() {
        let x = value(
            r#"{"path":"/x","extra":{
                "xPaddingBytes":"128-512",
                "scMaxEachPostBytes":"2048-4096",
                "scMaxBufferedPosts":7,
                "noSSEHeader":true
            }}"#,
        );
        assert_eq!(x.x_padding, Some(Padding { from: 128, to: 512 }));
        assert_eq!(x.sc_max_each_post_bytes, 4096);
        assert_eq!(x.sc_max_buffered_posts, 7);
        assert!(x.no_sse_header);
        x.validate(0).unwrap();

        let x = value(
            r#"{"path":"/x","extra":{
                "xPaddingBytes":256,
                "scMaxEachPostBytes":900000,
                "scMaxBufferedPosts":0
            }}"#,
        );
        assert_eq!(x.x_padding, Some(Padding { from: 256, to: 256 }));
        assert_eq!(x.sc_max_each_post_bytes, 900_000);
        assert_eq!(x.sc_max_buffered_posts, 30);

        // 零值按上游归一化为默认范围。
        let x = value(r#"{"path":"/x","extra":{"xPaddingBytes":0}}"#);
        assert_eq!(x.x_padding, Some(Padding::DEFAULT));
    }

    #[test]
    fn extra_rejects_top_level_conflicts() {
        for (field, top, extra) in [
            (
                "xPaddingBytes",
                r#""x_padding":{"from":100,"to":200}"#,
                r#""xPaddingBytes":"64-64""#,
            ),
            (
                "scMaxEachPostBytes",
                r#""sc_max_each_post_bytes":1024"#,
                r#""scMaxEachPostBytes":2048"#,
            ),
            (
                "scMaxBufferedPosts",
                r#""sc_max_buffered_posts":8"#,
                r#""scMaxBufferedPosts":9"#,
            ),
            (
                "noSSEHeader",
                r#""no_sse_header":false"#,
                r#""noSSEHeader":true"#,
            ),
        ] {
            let message = error(&format!(r#"{{"path":"/x",{top},"extra":{{{extra}}}}}"#));
            assert!(message.contains(field), "{message}");
            assert!(message.contains("冲突"), "{message}");
        }
    }

    #[test]
    fn extra_rejects_unsupported_fields() {
        for field in [
            "downloadSettings",
            "host",
            "path",
            "mode",
            "headers",
            "uplinkHTTPMethod",
            "sessionIDTable",
            "sessionIDLength",
            "uplinkChunkSize",
            "noGRPCHeader",
            "scMinPostsIntervalMs",
            "xmux",
            "h2Params",
            "extra",
        ] {
            let message = error(&format!(r#"{{"path":"/x","extra":{{"{field}":true}}}}"#));
            assert!(message.contains(field), "{message}");
            assert!(message.contains("不受支持"), "{message}");
        }
    }

    #[test]
    fn extra_maps_padding_obfs_and_placement_fields() {
        let x = value(
            r#"{"path":"/x","extra":{
                "xPaddingObfsMode":true,
                "xPaddingKey":"pad",
                "xPaddingHeader":"X-Pad",
                "xPaddingPlacement":"cookie",
                "xPaddingMethod":"repeat-x",
                "sessionIDPlacement":"header",
                "sessionIDKey":"X-Sid",
                "seqPlacement":"query",
                "seqKey":"seq",
                "uplinkDataPlacement":"header",
                "uplinkDataKey":"X-Data-Bin",
                "serverMaxHeaderBytes":16384
            }}"#,
        );
        assert!(x.x_padding_obfs_mode);
        assert_eq!(x.x_padding_key, "pad");
        assert_eq!(x.x_padding_header, "X-Pad");
        assert_eq!(x.x_padding_placement, "cookie");
        assert_eq!(x.x_padding_method, "repeat-x");
        assert_eq!(x.session_id_placement, "header");
        assert_eq!(x.session_id_key.as_deref(), Some("X-Sid"));
        assert_eq!(x.seq_placement, "query");
        assert_eq!(x.seq_key.as_deref(), Some("seq"));
        assert_eq!(x.uplink_data_placement, "header");
        assert_eq!(x.uplink_data_key.as_deref(), Some("X-Data-Bin"));
        assert_eq!(x.server_max_header_bytes, 16384);
        x.validate(0).unwrap();

        // 默认 key/放置位置由放置类型推导。
        let x = value(
            r#"{"path":"/x","extra":{"sessionIDPlacement":"cookie","seqPlacement":"header"}}"#,
        );
        assert_eq!(x.session_key(), Some("x_session"));
        assert_eq!(x.seq_key(), Some("X-Seq"));

        // 上游零值/缺省归一化。
        let x = value(r#"{"path":"/x","extra":{"serverMaxHeaderBytes":0}}"#);
        assert_eq!(x.server_max_header_bytes(), 8192);
    }

    #[test]
    fn extra_invalid_obfs_and_placement_values_fail_closed() {
        for json in [
            r#"{"path":"/x","extra":{"xPaddingPlacement":"body"}}"#,
            r#"{"path":"/x","extra":{"sessionIDPlacement":"path2"}}"#,
            r#"{"path":"/x","extra":{"uplinkDataPlacement":"query"}}"#,
        ] {
            assert!(value(json).validate(0).is_err(), "{json}");
        }
        let x = value(r#"{"path":"/x","extra":{"xPaddingMethod":"unknown"}}"#);
        assert!(x.validate(0).is_err());
        assert!(error(r#"{"path":"/x","extra":{"serverMaxHeaderBytes":-1}}"#).contains("负数"));
        assert!(error(r#"{"path":"/x","extra":{"scStreamUpServerSecs":5}}"#).contains("不受支持"));
        let x = value(r#"{"path":"/x","x_padding_method":"tokenish"}"#);
        assert!(x.validate(0).is_err());
        // 顶层也会被统一 validate 拒绝。
        let x = value(r#"{"path":"/x","x_padding_key":""}"#);
        assert!(x.validate(0).is_err());
        let x = value(r#"{"path":"/x","x_padding_header":"content-length"}"#);
        assert!(x.validate(0).is_err());
        let x =
            value(r#"{"path":"/x","session_id_placement":"header","session_id_key":"bad key"}"#);
        assert!(x.validate(0).is_err());
        let x = value(r#"{"path":"/x","server_max_header_bytes":64}"#);
        assert!(x.validate(0).is_err());
    }

    #[test]
    fn extra_unknown_fields_stay_rejected() {
        let message = error(r#"{"path":"/x","extra":{"madeUp":1}}"#);
        assert!(message.contains("unknown field"), "{message}");
    }

    #[test]
    fn extra_range_errors_and_bounds_fail_closed() {
        assert!(error(r#"{"path":"/x","extra":{"xPaddingBytes":-1}}"#).contains("不能禁用"));
        assert!(error(r#"{"path":"/x","extra":{"xPaddingBytes":"0-100"}}"#).contains("不能禁用"));
        assert!(error(r#"{"path":"/x","extra":{"xPaddingBytes":"100-0"}}"#).contains("不能禁用"));
        assert!(error(r#"{"path":"/x","extra":{"scMaxEachPostBytes":-5}}"#).contains("正整数"));
        assert!(error(r#"{"path":"/x","extra":{"scMaxBufferedPosts":-1}}"#).contains("非负整数"));
        assert!(error(r#"{"path":"/x","extra":{"xPaddingBytes":"abc"}}"#).contains("范围字符串"));

        // 与上游一致：from > to 时交换，而不是拒绝。
        let x = value(r#"{"path":"/x","extra":{"xPaddingBytes":"1000-100"}}"#);
        assert_eq!(
            x.x_padding,
            Some(Padding {
                from: 100,
                to: 1_000
            })
        );

        // 资源上限仍由统一 validate 执行。
        let x = value(r#"{"path":"/x","extra":{"xPaddingBytes":"1-20000"}}"#);
        assert!(x.validate(0).is_err());
        let x = value(r#"{"path":"/x","extra":{"scMaxEachPostBytes":32}}"#);
        assert!(x.validate(0).is_err());
        let x = value(r#"{"path":"/x","extra":{"scMaxBufferedPosts":2048}}"#);
        assert!(x.validate(0).is_err());
    }

    #[test]
    fn extra_null_and_empty_are_noops() {
        assert!(value(r#"{"path":"/x","extra":null}"#).x_padding.is_none());
        assert_eq!(value(r#"{"path":"/x","extra":{}}"#).path, "/x");
        let x = value(r#"{"path":"/x","extra":{"xPaddingBytes":null}}"#);
        assert!(x.x_padding.is_none());
    }
}
