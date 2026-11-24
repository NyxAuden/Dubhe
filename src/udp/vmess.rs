//! 原生 VMess cmd2/packetaddr 数据报；正文 chunk 是边界，不插入 VLESS 帧。
use super::*;
use crate::protocol::vmess::{self as wire, Mode};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn decode(bytes: Vec<u8>, fixed: &Option<Target>) -> io::Result<(Target, Vec<u8>)> {
    if let Some(target) = fixed {
        return Ok((target.clone(), bytes));
    }
    let (ip, end) = match bytes.first() {
        Some(1) if bytes.len() >= 7 => (
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&bytes[1..5]).expect("已检查"),
            )),
            5,
        ),
        Some(2) if bytes.len() >= 19 => (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[1..17]).expect("已检查"),
            )),
            17,
        ),
        _ => return Err(invalid("VMess packetaddr 地址无效")),
    };
    let port = u16::from_be_bytes([bytes[end], bytes[end + 1]]);
    if port == 0 {
        return Err(invalid("VMess packetaddr 端口无效"));
    }
    Ok((SocketAddr::new(ip, port).into(), bytes[end + 2..].to_vec()))
}

fn encode(target: &Target, payload: &[u8], packetaddr: bool) -> io::Result<Vec<u8>> {
    if !packetaddr {
        return Ok(payload.to_vec());
    }
    let mut bytes = Vec::with_capacity(19 + payload.len());
    match target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            bytes.push(2);
            bytes.extend_from_slice(&ip.octets());
        }
        Host::Domain(_) => return Err(invalid("VMess packetaddr 回程必须为实际IP")),
    }
    bytes.extend_from_slice(&target.port.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    mut accepted: wire::Accepted,
    ctx: Arc<Context>,
    inbound: String,
    lease: Option<Lease>,
) -> io::Result<()> {
    let fixed = match &accepted.mode {
        Mode::Udp(target) => {
            // 这里只需要确认「该目标被允许」，不应限制出站方式。
            // `allowed` 走 `selected(..., allow_udp_proxy: false)`，选到代理就
            // 直接 `Unsupported`，使 fixed 模式在链式部署下握手即失败；
            // 而数据面（`Association::send`）本来就用 `udp_selected`，允许代理。
            // 改用 `udp_selected` 让两侧一致。
            ctx.udp_selected(&inbound, target).await?;
            Some(target.clone())
        }
        Mode::PacketAddr => None,
        _ => return Err(invalid("VMess UDP 模式无效")),
    };
    let packetaddr = fixed.is_none();
    let _slot = ctx
        .udp_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "UDP 关联上限"))?;
    let _gauge = ctx.stats.enter(Gauge::Udp);
    timeout(
        Duration::from_millis(ctx.limits.handshake_timeout_ms),
        accepted.reply(&mut stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VMess UDP 应答超时"))??;
    let (mut reader, mut writer) = wire::body::split(
        stream,
        accepted.security,
        accepted.options,
        accepted.key,
        accepted.iv,
    )?;
    let (tx, mut rx) = mpsc::channel(ctx.limits.udp_queue_packets);
    let mut readers = JoinSet::new();
    let reader_ctx = ctx.clone();
    let reader_lease = lease.clone();
    readers.spawn(ctx.children.track_future(async move {
        let _lease = reader_lease;
        loop {
            let next = match reader.packet().await {
                Ok(Some(bytes)) => decode(bytes, &fixed),
                Ok(None) => break,
                Err(error) => Err(error),
            };
            match next {
                Ok((target, payload)) => {
                    if payload.len() > reader_ctx.limits.max_udp_payload {
                        reader_ctx.stats.drop_packet();
                        continue;
                    }
                    let Some(packet) = Packet::reserve(&reader_ctx, target, payload) else {
                        reader_ctx.stats.drop_packet();
                        continue;
                    };
                    if let Err(error) = tx.try_send(Ok(packet)) {
                        if matches!(error, mpsc::error::TrySendError::Closed(_)) {
                            break;
                        }
                        reader_ctx.stats.drop_packet();
                    }
                }
                Err(error) => {
                    let _ = tx.send(Err(error)).await;
                    break;
                }
            }
        }
    }));
    let (mut assoc, mut replies) = Association::with_lease(ctx.clone(), inbound, lease);
    let idle = Duration::from_millis(ctx.limits.udp_idle_timeout_ms);
    let mut deadline = Instant::now() + idle;
    let result = async {
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                item = rx.recv() => {
                    let Some(item) = item else { break; };
                    let packet = item?;
                    if timeout(Duration::from_millis(ctx.limits.dial_timeout_ms),assoc.send(packet.target,&packet.payload)).await.is_ok_and(|r|r.is_ok()) {
                        deadline=Instant::now()+idle;
                    } else {ctx.stats.drop_packet();}
                }
                Some(packet) = replies.recv() => {
                    if !packetaddr && packet.payload.is_empty() {ctx.stats.drop_packet();continue;}
                    let bytes=encode(&packet.target,&packet.payload,packetaddr)?;
                    match timeout(idle,writer.packet(&bytes)).await {
                        Ok(Ok(())) => {},
                        Ok(Err(error)) if error.kind()==io::ErrorKind::InvalidInput => {ctx.stats.drop_packet();continue;},
                        Ok(Err(error)) => return Err(error),
                        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut,"VMess UDP 写入超时")),
                    }
                    ctx.stats.downlink.fetch_add(packet.payload.len() as u64,Ordering::Relaxed);
                    deadline=Instant::now()+idle;
                }
            }
        }
        Ok(())
    }.await;
    readers.abort_all();
    while readers.join_next().await.is_some() {}
    assoc.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packetaddr_independent_ipv4_ipv6_bytes_empty_and_bad_headers() {
        let v4 = b"\x01\x7f\x00\x00\x01\x00\x35abc".to_vec();
        let (target, payload) = decode(v4.clone(), &None).unwrap();
        assert_eq!(
            target,
            Target::from("127.0.0.1:53".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(payload, b"abc");
        assert_eq!(encode(&target, &payload, true).unwrap(), v4);
        let mut v6 = vec![2];
        v6.extend([0; 15]);
        v6.extend([1, 0x1f, 0x90]);
        let (target, payload) = decode(v6.clone(), &None).unwrap();
        assert_eq!(
            target,
            Target::from("[::1]:8080".parse::<SocketAddr>().unwrap())
        );
        assert!(payload.is_empty());
        assert_eq!(encode(&target, &[], true).unwrap(), v6);
        for end in 0..19 {
            assert!(decode(v6[..end].to_vec(), &None).is_err());
        }
        assert!(decode(vec![3; 19], &None).is_err());
        assert!(decode(vec![1, 127, 0, 0, 1, 0, 0], &None).is_err());
    }
}
