//! NAT traversal acceptance, the part a test can prove: STUN and NAT-PMP packets parse right and hostile ones never do; the
//! beacon replay window takes out-of-order beacons from two paths once each and never a replay; the door learns its
//! public address only from the answer to its own STUN request; with the hedge on, every downlink datagram reaches the
//! client over both the leg and UDP (WireGuard drops the second copy); and a stranger at the door gets zero reply bytes.

use ed25519_dalek::SigningKey;
use net_mesh::leg::*;
use net_mesh::punch::*;
use net_mesh::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};

fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }

/// a binding success response to `tid` with XOR-MAPPED-ADDRESS `a`, the shape a public STUN server sends
fn stun_answer(tid: &[u8; 12], a: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v) = a else { panic!() };
    let mut b = vec![0x01, 0x01, 0, 12];
    b.extend_from_slice(&STUN_COOKIE.to_be_bytes());
    b.extend_from_slice(tid);
    b.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 0x01]);
    b.extend_from_slice(&(v.port() ^ 0x2112).to_be_bytes());
    for (o, k) in v.ip().octets().iter().zip(STUN_COOKIE.to_be_bytes()) { b.push(o ^ k); }
    b
}

#[test]
fn stun_request_and_answer() {
    let t = [3u8; 12];
    let r = stun_request(&t);
    assert_eq!(r.len(), 20);
    assert!(is_stun(&r));
    let a: SocketAddr = "203.0.113.174:13126".parse().unwrap();
    let ans = stun_answer(&t, a);
    assert_eq!(stun_parse(&ans, &t), Some(a));
    // another transaction, a request instead of an answer, a truncated answer: nothing
    assert_eq!(stun_parse(&ans, &[4u8; 12]), None);
    assert_eq!(stun_parse(&r, &t), None);
    assert_eq!(stun_parse(&ans[..ans.len() - 3], &t), None);
    let mut long = ans.clone();
    long[3] = 200; // length field past the end
    assert_eq!(stun_parse(&long, &t), None);
    // hostile attribute lengths never panic
    for n in [0u8, 1, 7, 255] {
        let mut h = ans.clone();
        h[23] = n;
        let _ = stun_parse(&h, &t);
    }
    assert!(!is_stun(b"NMPUNCH1"));
    assert!(!is_stun(&beacon(&[1; 8], &[2; 32], "n", 1)));
}

#[test]
fn natpmp_packets() {
    let r = natpmp_request(51880, 51880, 120);
    assert_eq!(r, [0, 1, 0, 0, 0xCA, 0xA8, 0xCA, 0xA8, 0, 0, 0, 120]);
    assert_eq!(natpmp_request(51880, 0, 0)[6..], [0, 0, 0, 0, 0, 0]); // unmap
    let mut ok = vec![0, 129, 0, 0, 0, 0, 1, 0];
    ok.extend_from_slice(&51880u16.to_be_bytes());
    ok.extend_from_slice(&51880u16.to_be_bytes());
    ok.extend_from_slice(&120u32.to_be_bytes());
    assert_eq!(natpmp_parse(&ok), Some(Ok((51880, 51880, 120))));
    let mut refused = ok.clone();
    refused[3] = 2;
    assert_eq!(natpmp_parse(&refused), Some(Err(2)));
    assert_eq!(natpmp_parse(&ok[..10]), None);
    assert_eq!(natpmp_parse(&[0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), None); // the public-address answer
}

#[test]
fn client_ip_and_announced_door_take_only_public_ipv4() {
    assert_eq!(client_ip(" 198.51.100.192 "), Some("198.51.100.192".parse().unwrap()));
    for bad in ["10.77.1.5", "127.0.0.1", "0.0.0.0", "2001:db8::1", "x", ""] {
        assert_eq!(client_ip(bad), None, "{bad}");
    }
    let d = "udp2 0011223344556677 aa door=203.0.113.174:13126";
    assert_eq!(announced_door(d), Some("203.0.113.174:13126".parse().unwrap()));
    assert_eq!(announced_door("udp2 00 aa"), None);
    assert_eq!(announced_door("udp2 00 aa door=10.77.0.1:5"), None);
    assert_eq!(announced_door("udp2 00 aa door=192.0.2.4:0"), None);
}

#[test]
fn beacon_window_takes_two_paths_out_of_order_and_never_a_replay() {
    // door and private-network beacons interleave and arrive out of order: each seq is taken once
    assert_eq!(beacon_window_accepts(&[2, 1, 4, 3, 6, 5]), vec![true; 6]);
    // a copy of any one of them, later, is refused
    assert_eq!(beacon_window_accepts(&[1, 2, 3, 2]), vec![true, true, true, false]);
    assert_eq!(beacon_window_accepts(&[5, 5]), vec![true, false]);
    // older than the 64-wide window: refused even if never seen
    assert_eq!(beacon_window_accepts(&[100, 30, 37, 36]), vec![true, false, true, false]);
    assert_eq!(beacon_window_accepts(&[100, 36]), vec![true, false]);
    assert_eq!(beacon_window_accepts(&[100, 37]), vec![true, true]);
    assert_eq!(beacon_window_accepts(&[0]), vec![false]);
}

#[tokio::test(flavor = "multi_thread")]
async fn door_learns_its_public_address_only_from_its_own_stun_answer() {
    let srv_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv = Server::with_udp_in([node_id(&key(1))].into_iter().collect(), srv_wg.local_addr().unwrap());
    // a fake STUN server that answers the request with a public address, plus a stranger's forged answer first
    let stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun.local_addr().unwrap();
    let door_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let door = door_sock.local_addr().unwrap();
    let forger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    forger.send_to(&stun_answer(&[9; 12], "192.0.2.66:666".parse().unwrap()), door).await.unwrap();
    tokio::spawn(srv.clone().serve_door(door_sock, None, Some(stun_addr.to_string())));
    let mut b = [0u8; 256];
    let (n, from) = tokio::time::timeout(Duration::from_secs(3), stun.recv_from(&mut b)).await.expect("no stun request").unwrap();
    assert_eq!(from, door);
    let tid: [u8; 12] = b[8..20].try_into().unwrap();
    assert_eq!(n, 20);
    let public: SocketAddr = "203.0.113.174:13126".parse().unwrap();
    stun.send_to(&stun_answer(&tid, public), door).await.unwrap();
    for _ in 0..100 {
        if srv.door_public().is_some() { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(srv.door_public(), Some(public));
    // the forger never answered anything and a late forged answer changes nothing
    forger.send_to(&stun_answer(&[9; 12], "192.0.2.66:666".parse().unwrap()), door).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(srv.door_public(), Some(public));
    assert!(tokio::time::timeout(Duration::from_millis(200), forger.recv_from(&mut b)).await.is_err(), "the door answered a stranger");
}

/// a split-mode rig with the hedge as given; returns (server wg, client wg, client leg listen, server, door)
async fn rig(hedge: bool) -> (Arc<UdpSocket>, Arc<UdpSocket>, SocketAddr, Arc<Server>, SocketAddr) {
    let a = key(1);
    let srv_wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let cli_wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/leg", l.local_addr().unwrap());
    let srv = Server::with_udp_in([node_id(&a)].into_iter().collect(), srv_wg.local_addr().unwrap());
    srv.hedge_down.store(hedge, std::sync::atomic::Ordering::Relaxed);
    let door_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let door = door_sock.local_addr().unwrap();
    tokio::spawn(srv.clone().serve_door(door_sock, None, None));
    tokio::spawn(srv.clone().serve(l));
    let leg_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let leg = leg_udp.local_addr().unwrap();
    drop(leg_udp);
    let cfg = ClientCfg { url, listen: leg, wg: cli_wg.local_addr().unwrap(), key: a, up_udp: Some(door), door: true,
                          alt_urls: vec![], dead_after: DEAD_AFTER };
    let (tx, _rx) = tokio::sync::watch::channel(false);
    tokio::spawn(client_run(cfg, tx));
    for _ in 0..300 {
        if srv.udp_sources().await == 1 { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(srv.udp_sources().await, 1, "client never beaconed the door");
    (srv_wg, cli_wg, leg, srv, door)
}

/// one uplink datagram, so the server side learns the per-node loopback address to answer to
async fn server_peer(srv_wg: &UdpSocket, cli_wg: &UdpSocket, leg: SocketAddr) -> SocketAddr {
    let mut b = [0u8; 64];
    for _ in 0..20 {
        cli_wg.send_to(b"up", leg).await.unwrap();
        if let Ok(Ok((_, f))) = tokio::time::timeout(Duration::from_millis(300), srv_wg.recv_from(&mut b)).await { return f; }
    }
    panic!("uplink never arrived");
}

async fn count_down(srv_wg: &UdpSocket, cli_wg: &UdpSocket, to: SocketAddr, n: u32) -> std::collections::HashMap<u32, u32> {
    for i in 0..n {
        srv_wg.send_to(&i.to_be_bytes(), to).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let mut seen = std::collections::HashMap::new();
    let mut b = [0u8; 64];
    while let Ok(Ok((k, _))) = tokio::time::timeout(Duration::from_millis(600), cli_wg.recv_from(&mut b)).await {
        if k == 4 { *seen.entry(u32::from_be_bytes(b[..4].try_into().unwrap())).or_insert(0) += 1; }
    }
    seen
}

#[tokio::test(flavor = "multi_thread")]
async fn hedged_downlink_arrives_over_both_leg_and_udp() {
    let (srv_wg, cli_wg, leg, _srv, _door) = rig(true).await;
    let to = server_peer(&srv_wg, &cli_wg, leg).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let seen = count_down(&srv_wg, &cli_wg, to, 40).await;
    assert_eq!(seen.len(), 40, "a downlink datagram was lost");
    assert!(seen.values().all(|&c| c == 2), "each datagram should come twice (leg + udp): {seen:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_hedge_sends_downlink_once() {
    let (srv_wg, cli_wg, leg, _srv, _door) = rig(false).await;
    let to = server_peer(&srv_wg, &cli_wg, leg).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let seen = count_down(&srv_wg, &cli_wg, to, 40).await;
    assert_eq!(seen.len(), 40);
    assert!(seen.values().all(|&c| c == 1), "{seen:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn stranger_at_the_door_gets_zero_bytes() {
    let (srv_wg, _mac_wg, _leg, _srv, door) = rig(true).await;
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut probes: Vec<Vec<u8>> = vec![
        b"\x01\x00\x00\x00junk handshake initiation".to_vec(),
        stun_request(&[1; 12]),
        stun_answer(&[1; 12], "192.0.2.4:5".parse().unwrap()),
        PUNCH.to_vec(),
        beacon(&[7; 8], &[7; 32], &node_id(&key(9)), 1), // a stranger's own key
        vec![0u8; 1400],
        vec![],
    ];
    probes.push(vec![0xFE, b'N', b'2']);
    for p in &probes { s.send_to(p, door).await.unwrap(); }
    let mut b = [0u8; 2048];
    assert!(tokio::time::timeout(Duration::from_millis(500), s.recv_from(&mut b)).await.is_err(), "the door answered a stranger");
    assert!(tokio::time::timeout(Duration::from_millis(200), srv_wg.recv_from(&mut b)).await.is_err(), "a stranger reached wireguard");
}
