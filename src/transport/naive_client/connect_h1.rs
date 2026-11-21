//! H1 CONNECT只拥有握手承载，不派生任务；取消直接析构，不自动重放。
//! forwardproxy裸流与sing-box首八块填充必须显式选择，Padding响应头不足以区分。
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_HEADERS: usize = 64;
const MAX_INFORMATIONAL: usize = 4;

pub(super) async fn connect(
    mut wire: Upstream,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<Upstream> {
    let request = request(proxy, target)?;
    let authority = request
        .uri()
        .authority()
        .ok_or_else(|| invalid("Naive CONNECT缺少authority"))?
        .as_str();
    let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n").into_bytes();
    for (name, value) in request.headers() {
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    if head.len() > MAX_HEAD {
        return Err(invalid("Naive H1请求头过大"));
    }
    wire.write_all(&head).await?;
    wire.flush().await?;

    let mut total = 0usize;
    let mut informational = 0usize;
    let padded = loop {
        // 不预读隧道：200头与首批业务同一TCP/TLS记录到达也不能吞字节。
        let mut head = Vec::with_capacity(256);
        loop {
            if total == MAX_HEAD {
                return Err(invalid("Naive H1累计响应头过大"));
            }
            let mut byte = [0];
            wire.read_exact(&mut byte).await?;
            total += 1;
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let response = parse_response(&head)?;
        if matches!(response.status().as_u16(), 100 | 102 | 103) {
            informational += 1;
            if informational > MAX_INFORMATIONAL {
                return Err(invalid("Naive H1临时响应过多"));
            }
            continue;
        }
        break response_padding(&response)?;
    };
    if !options(proxy)?.h1_padding {
        return Ok(wire); // 非空Padding响应也不改变forwardproxy的裸H1语义。
    }
    if !padded {
        return Err(invalid("Naive H1填充模式缺少Padding响应"));
    }
    let (inner, local, session) = wire.into_parts();
    Ok(Upstream::from_parts(
        Box::new(PaddedStream::new(inner, true)),
        local,
        session,
    ))
}

fn parse_response(head: &[u8]) -> io::Result<http::Response<()>> {
    // httparse容忍部分单LF输入；此处只接受完整CRLF头，不接受折行/歧义边界。
    if head.iter().enumerate().any(|(index, byte)| {
        (*byte == b'\n' && (index == 0 || head[index - 1] != b'\r'))
            || (*byte == b'\r' && head.get(index + 1) != Some(&b'\n'))
    }) {
        return Err(invalid("Naive H1响应行边界无效"));
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut headers);
    if !matches!(parsed.parse(head), Ok(httparse::Status::Complete(length)) if length == head.len())
        || parsed.version != Some(1)
    {
        return Err(invalid("Naive H1响应无效"));
    }
    let mut response = http::Response::builder()
        .status(parsed.code.ok_or_else(|| invalid("Naive H1缺少状态码"))?)
        .body(())
        .map_err(|_| invalid("Naive H1响应状态无效"))?;
    for header in parsed.headers {
        if header.name.eq_ignore_ascii_case("padding") {
            response.headers_mut().append(
                "padding",
                HeaderValue::from_bytes(header.value)
                    .map_err(|_| invalid("Naive H1 Padding响应无效"))?,
            );
        }
    }
    if response.headers().get_all("padding").iter().count() > 1 {
        return Err(invalid("Naive响应重复Padding头"));
    }
    // RFC9110 §9.3.6：成功CONNECT后忽略Content-Length/Transfer-Encoding，后续是隧道。
    Ok(response)
}
