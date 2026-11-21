use base64::{Engine, engine::general_purpose::STANDARD};
use dubhe::{Config, Server};
use serde_json::{Value, json};
use tokio::net::{TcpListener, UdpSocket};

// 临时端口池对TCP/UDP分别分配；用例间隔离，且先联合预留，不能假定UDP随机端口的TCP空闲。
static PORTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn reserve_pair() -> (TcpListener, UdpSocket) {
    for _ in 0..16 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()).await {
            return (tcp, udp);
        }
    }
    panic!("无法联合预留测试TCP/UDP端口");
}

fn config(address: std::net::SocketAddr) -> Value {
    json!({
        "version": 1,
        "inbounds": [{
            "type": "shadowsocks", "tag": "ss", "listen": address,
            "method": "2022-blake3-aes-128-gcm", "password": STANDARD.encode([1; 16])
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default": "direct"}
    })
}

fn parse(value: &Value) -> Config {
    Config::from_json(&value.to_string()).unwrap()
}

#[tokio::test]
async fn port_zero_reserves_tcp_and_udp_at_one_address_until_drop() {
    let _ports = PORTS.lock().await;
    for ip in ["127.0.0.1:0", "[::1]:0"] {
        let server = Server::bind(parse(&config(ip.parse().unwrap())))
            .await
            .unwrap();
        let address = server.local_addr("ss").unwrap();
        assert_ne!(address.port(), 0);
        assert_eq!(
            address.ip(),
            ip.parse::<std::net::SocketAddr>().unwrap().ip()
        );
        assert!(TcpListener::bind(address).await.is_err());
        assert!(UdpSocket::bind(address).await.is_err());
        drop(server);
        let _tcp = TcpListener::bind(address).await.unwrap();
        let _udp = UdpSocket::bind(address).await.unwrap();
    }
}

#[tokio::test]
async fn udp_conflict_releases_current_tcp_and_all_previous_listeners() {
    let _ports = PORTS.lock().await;
    let (first_tcp, first_udp) = reserve_pair().await;
    let first = first_tcp.local_addr().unwrap();
    // 首入口仍被预留时选第二端口，明确确保两者不同且第二端口原本TCP可用。
    let (second_tcp, occupied) = reserve_pair().await;
    let conflict = occupied.local_addr().unwrap();
    assert_ne!(first, conflict);
    drop((first_tcp, first_udp, second_tcp));
    let mut value = config(first);
    let mut second = value["inbounds"][0].clone();
    second["tag"] = json!("second");
    second["listen"] = json!(conflict);
    value["inbounds"].as_array_mut().unwrap().push(second);
    assert!(Server::bind(parse(&value)).await.is_err());
    let _first_tcp = TcpListener::bind(first).await.unwrap();
    let _first_udp = UdpSocket::bind(first).await.unwrap();
    let _second_tcp = TcpListener::bind(conflict).await.unwrap();
    assert!(UdpSocket::bind(conflict).await.is_err());
}

#[tokio::test]
async fn later_tcp_conflict_releases_prepared_shadowsocks_tcp_and_udp() {
    let _ports = PORTS.lock().await;
    let (first_tcp, first_udp) = reserve_pair().await;
    let first = first_tcp.local_addr().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert_ne!(first, occupied.local_addr().unwrap());
    drop((first_tcp, first_udp));
    let mut value = config(first);
    value["inbounds"].as_array_mut().unwrap().push(json!({
        "type": "socks5", "tag": "second", "listen": occupied.local_addr().unwrap()
    }));
    assert!(Server::bind(parse(&value)).await.is_err());
    let _tcp = TcpListener::bind(first).await.unwrap();
    let _udp = UdpSocket::bind(first).await.unwrap();
    assert!(
        TcpListener::bind(occupied.local_addr().unwrap())
            .await
            .is_err()
    );
}
