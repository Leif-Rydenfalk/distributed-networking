//! Relay leg acceptance, the part a test can prove: datagrams cross the leg both ways in order and intact; a stranger, a forged
//! signature and a stale hello are refused before anything is forwarded; the server never listens on an open address.

use ed25519_dalek::SigningKey;
use net_mesh::leg::*;
use net_mesh::*;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};

fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }

#[test]
fn framing_round_trips_and_survives_garbage() {
    let mut b = Vec::new();
    for p in [&b"a"[..], &[0u8; 1400][..], &b""[..], &[7u8; 65535][..]] {
        pack(&mut b, p);
    }
    let v = unpack(&b);
    assert_eq!(v.len(), 4);
    assert_eq!(v[0], b"a");
    assert_eq!(v[1].len(), 1400);
    assert_eq!(v[3].len(), 65535);
    // a truncated or hostile batch yields only the whole datagrams before it, never a panic
    assert_eq!(unpack(&b[..b.len() - 1]).len(), 3);
    assert!(unpack(&[0xff, 0xff, 1]).is_empty());
    assert!(unpack(&[0x01]).is_empty());
}

#[test]
fn hello_door() {
    let (a, stranger) = (key(1), key(9));
    let admitted: BTreeSet<String> = [node_id(&a)].into();
    let n = nonce();
    let t = now();
    assert!(Hello::signed(&a, &n, t).check(&n, &admitted, t).is_ok());
    assert_eq!(Hello::signed(&stranger, &n, t).check(&n, &admitted, t), Err("not admitted"));
    // a hello for another nonce (a replay of an old session) fails the signature
    assert_eq!(Hello::signed(&a, &nonce(), t).check(&n, &admitted, t), Err("bad signature"));
    // a stranger's signature under an admitted node id
    let mut h = Hello::signed(&stranger, &n, t);
    h.node = node_id(&a);
    assert_eq!(h.check(&n, &admitted, t), Err("bad signature"));
    assert_eq!(Hello::signed(&a, &n, t - 3600).check(&n, &admitted, t), Err("timestamp outside window"));
}

#[test]
fn only_loopback_tailnet_or_mesh_listen() {
    for ok in ["127.0.0.1:7742", "100.64.0.1:7742", "10.77.37.223:7742", "[::1]:7742"] {
        assert!(closed_by_default(&ok.parse().unwrap()).is_ok(), "{ok}");
    }
    for bad in ["0.0.0.0:7742", "192.168.1.20:7742", "203.0.113.174:7742", "[::]:7742"] {
        assert!(closed_by_default(&bad.parse().unwrap()).is_err(), "{bad}");
    }
}

/// a fake WireGuard on each side; returns the (server_wg, client_wg) sockets
async fn rig(client_key: SigningKey, admit: &[&SigningKey]) -> (Arc<UdpSocket>, Arc<UdpSocket>, std::net::SocketAddr, Arc<Server>) {
    let (d, m, l, s, _) = rig_mode(client_key, admit, false).await;
    (d, m, l, s)
}

/// split = the server opens a UDP ingress and the client sends up it; returns that ingress address too
async fn rig_mode(client_key: SigningKey, admit: &[&SigningKey], split: bool)
    -> (Arc<UdpSocket>, Arc<UdpSocket>, std::net::SocketAddr, Arc<Server>, Option<std::net::SocketAddr>) {
    let srv_wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let cli_wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/leg", l.local_addr().unwrap());
    let ids: BTreeSet<String> = admit.iter().map(|k| node_id(k)).collect();
    let (srv, up_udp) = if split {
        let srv = Server::with_udp_in(ids, srv_wg.local_addr().unwrap());
        // these tests count downlink datagrams one by one; the hedged copy is tested in tests/punch.rs
        srv.hedge_down.store(false, std::sync::atomic::Ordering::Relaxed);
        let ingress = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = ingress.local_addr().unwrap();
        tokio::spawn(srv.clone().serve_udp(ingress));
        (srv, Some(a))
    } else {
        (Server::new(ids, srv_wg.local_addr().unwrap()), None)
    };
    tokio::spawn(srv.clone().serve(l));
    let leg_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let leg = leg_udp.local_addr().unwrap();
    drop(leg_udp);
    let cfg = ClientCfg { url, listen: leg, wg: cli_wg.local_addr().unwrap(), key: client_key, up_udp, door: false, alt_urls: vec![], dead_after: DEAD_AFTER };
    let (tx, _rx) = tokio::sync::watch::channel(false);
    tokio::spawn(client_run(cfg, tx));
    (srv_wg, cli_wg, leg, srv, up_udp)
}

#[tokio::test(flavor = "multi_thread")]
async fn split_mode_up_udp_down_leg_and_strangers_dropped() {
    let a = key(1);
    let id = node_id(&a);
    let (srv_wg, cli_wg, leg, srv, ingress) = rig_mode(a.clone(), &[&a], true).await;
    let ingress = ingress.unwrap();
    // the client switches its uplink once the token arrived and the first beacon landed
    for _ in 0..200 {
        if srv.udp_sources().await == 1 { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(srv.udp_sources().await, 1, "client never sent up udp");
    tokio::time::sleep(Duration::from_millis(400)).await;
    let port = srv.pipe_port(&id).await.unwrap();
    let mut buf = vec![0u8; 65536];
    // a stranger: raw datagrams and a forged beacon to the ingress reach nothing
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(b"\x04let me in", ingress).await.unwrap();
    let forged = beacon(&[7u8; 8], &[7u8; 32], &id, 1);
    s.send_to(&forged, ingress).await.unwrap();
    s.send_to(b"\x04after a forged beacon", ingress).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(300), srv_wg.recv_from(&mut buf)).await.is_err(), "a stranger reached wireguard");
    assert_eq!(srv.udp_sources().await, 1);
    // client -> server goes up udp but leaves the same per-node loopback port, so WireGuard never roams off the leg
    for i in 0..50u32 {
        cli_wg.send_to(&i.to_be_bytes(), leg).await.unwrap();
    }
    let mut from = None;
    let mut got = 0;
    while let Ok(Ok((n, f))) = tokio::time::timeout(Duration::from_secs(2), srv_wg.recv_from(&mut buf)).await {
        assert_eq!(n, 4);
        assert_eq!(f.port(), port);
        from = Some(f);
        got += 1;
        if got == 50 { break; }
    }
    assert_eq!(got, 50, "uplink datagrams lost on loopback");
    // server -> client still comes down the leg
    for i in 0..20u32 {
        srv_wg.send_to(&i.to_be_bytes(), from.unwrap()).await.unwrap();
    }
    for i in 0..20u32 {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), cli_wg.recv_from(&mut buf)).await.expect("lost").unwrap();
        assert_eq!(&buf[..n], &i.to_be_bytes());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn datagrams_cross_both_ways() {
    let a = key(1);
    let id = node_id(&a);
    let (srv_wg, cli_wg, leg, srv) = rig(a.clone(), &[&a]).await;
    // wait for the handshake
    let mut port = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        // the pipe exists only after the first datagram, so push one
        let _ = cli_wg.send_to(b"hs", leg).await;
        if let Some(p) = srv.pipe_port(&id).await { port = Some(p); break; }
    }
    let port = port.expect("client never got through the door");
    let mut buf = vec![0u8; 65536];
    // drain the handshake probes
    while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(200), srv_wg.recv_from(&mut buf)).await {}

    // client -> server: 200 datagrams up to 1400 bytes, in order (one stream)
    // sent from a task while this one reads: 200 datagrams queued unread overflow a 208 KB loopback receive buffer
    // when the host is loaded (seen once: 138-159 dropped), which is the test's loss, not the leg's
    let mw = cli_wg.clone();
    tokio::spawn(async move {
        for i in 0..200u32 {
            let mut p = i.to_be_bytes().to_vec();
            p.resize(4 + (i as usize * 7) % 1396, i as u8);
            mw.send_to(&p, leg).await.unwrap();
            if i % 25 == 24 { tokio::time::sleep(Duration::from_millis(2)).await; }
        }
    });
    let mut from = None;
    let mut i = 0u32;
    while i < 200 {
        let (n, f) = tokio::time::timeout(Duration::from_secs(5), srv_wg.recv_from(&mut buf)).await.expect("datagram lost").unwrap();
        if &buf[..n] == b"hs" { continue; } // a handshake probe that outlived the drain under load
        assert_eq!(&buf[..4], &i.to_be_bytes());
        i += 1;
        assert_eq!(n, 4 + ((i - 1) as usize * 7) % 1396);
        from = Some(f);
    }
    // WireGuard on the server sees the node's stable loopback port
    assert_eq!(from.unwrap().port(), port);

    // server -> client: answer to the port it came from, like WireGuard roaming does
    for i in 0..50u32 {
        srv_wg.send_to(&i.to_be_bytes(), from.unwrap()).await.unwrap();
    }
    for i in 0..50u32 {
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), cli_wg.recv_from(&mut buf)).await.expect("lost").unwrap();
        assert_eq!(&buf[..n], &i.to_be_bytes());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_is_refused_and_nothing_is_forwarded() {
    let (a, stranger) = (key(1), key(9));
    let (srv_wg, cli_wg, leg, srv) = rig(stranger.clone(), &[&a]).await;
    let mut buf = [0u8; 64];
    for _ in 0..20 {
        let _ = cli_wg.send_to(b"let me in", leg).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(tokio::time::timeout(Duration::from_millis(500), srv_wg.recv_from(&mut buf)).await.is_err(), "a stranger's datagram reached wireguard");
    assert!(srv.pipe_port(&node_id(&stranger)).await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_raw_stranger_gets_refused_text() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let a = key(1);
    let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/leg", l.local_addr().unwrap());
    tokio::spawn(Server::new([node_id(&a)].into(), wg.local_addr().unwrap()).serve(l));
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let Some(Ok(Message::Text(ch))) = ws.next().await else { panic!("no challenge") };
    assert!(ch.starts_with(LEG_PROTO));
    // skip the hello and send data straight away
    ws.send(Message::Binary(vec![0, 2, 1, 2])).await.unwrap();
    let Some(Ok(Message::Text(r))) = ws.next().await else { panic!("no refusal") };
    assert_eq!(r, "refused: no hello");
    let mut buf = [0u8; 16];
    assert!(tokio::time::timeout(Duration::from_millis(300), wg.recv_from(&mut buf)).await.is_err());
}

/// a fake boringtun 0.7.1 UAPI with its two quirks: touching an existing peer kills the API (the real one panics), and
/// `remove` sticks for every later peer section of the same set. Returns (socket path, peers, sets seen, dead flag).
fn fake_boringtun(dir: &std::path::Path) -> (String, Arc<std::sync::Mutex<Vec<(String, Vec<String>)>>>, Arc<std::sync::Mutex<Vec<String>>>, Arc<std::sync::atomic::AtomicBool>) {
    use std::io::{BufRead, BufReader, Write};
    let path = dir.join("utun9.sock").display().to_string();
    let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let peers = Arc::new(std::sync::Mutex::new(vec![("aa".repeat(32), vec!["endpoint=192.0.2.89:51877".into(), "persistent_keepalive_interval=25".into(), "allowed_ip=10.77.37.223/32".into()])]));
    let sets = Arc::new(std::sync::Mutex::new(vec![]));
    let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (p, st, d) = (peers.clone(), sets.clone(), dead.clone());
    std::thread::spawn(move || for c in l.incoming() {
        let mut c = c.unwrap();
        if d.load(std::sync::atomic::Ordering::SeqCst) { continue; }
        let mut r = BufReader::new(c.try_clone().unwrap());
        let mut first = String::new();
        r.read_line(&mut first).unwrap();
        if first == "get=1\n" {
            let mut out = String::new();
            for (k, kv) in p.lock().unwrap().iter() { out += &format!("public_key={k}\n"); for x in kv { out += &format!("{x}\n"); } }
            let _ = c.write_all(format!("{out}errno=0\n\n").as_bytes());
            continue;
        }
        let mut lines = vec![];
        loop { let mut x = String::new(); if r.read_line(&mut x).unwrap() == 0 || x == "\n" { break; } lines.push(x.trim().to_string()); }
        st.lock().unwrap().push(lines.join(";"));
        let (mut cur, mut remove, mut kv): (Option<String>, bool, Vec<String>) = (None, false, vec![]);
        let commit = |cur: &Option<String>, remove: bool, kv: &Vec<String>| -> bool {
            let Some(k) = cur else { return true };
            let mut pl = p.lock().unwrap();
            if remove { pl.retain(|(x, _)| x != k); return true; }
            if pl.iter().any(|(x, _)| x == k) { return false; } // real boringtun: panic, the API thread dies
            pl.push((k.clone(), kv.clone()));
            true
        };
        let mut ok = true;
        for x in &lines {
            let (k, v) = x.split_once('=').unwrap();
            match k {
                "public_key" => { ok &= commit(&cur, remove, &kv); cur = Some(v.into()); kv.clear(); } // remove NOT reset
                "remove" => remove = v == "true",
                "update_only" => { let _ = c.write_all(b"errno=22\n\n"); ok = false; break; }
                _ => kv.push(x.clone()),
            }
        }
        if ok { ok &= commit(&cur, remove, &kv); }
        if !ok { d.store(true, std::sync::atomic::Ordering::SeqCst); continue; }
        let _ = c.write_all(b"errno=0\n\n");
    });
    (path, peers, sets, dead)
}

#[test]
fn endpoint_switch_survives_boringtun_quirks() {
    let dir = std::env::temp_dir().join(format!("nm-uapi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (sock, peers, sets, dead) = fake_boringtun(&dir);
    let k = "aa".repeat(32);
    uapi_set_endpoint(&sock, &k, "127.0.0.1:51878").unwrap();
    assert!(!dead.load(std::sync::atomic::Ordering::SeqCst), "the API died: {:?}", sets.lock().unwrap());
    let p = peers.lock().unwrap().clone();
    assert_eq!(p.len(), 1, "peer lost: {p:?}");
    assert!(p[0].1.contains(&"endpoint=127.0.0.1:51878".to_string()));
    assert!(p[0].1.contains(&"allowed_ip=10.77.37.223/32".to_string()) && p[0].1.contains(&"persistent_keepalive_interval=25".to_string()));
    // the same endpoint again touches nothing (a re-add would reset the session every minute)
    let n = sets.lock().unwrap().len();
    uapi_set_endpoint(&sock, &k, "127.0.0.1:51878").unwrap();
    assert_eq!(sets.lock().unwrap().len(), n);
    // an unknown peer is an error, not an add
    assert!(uapi_set_endpoint(&sock, &"bb".repeat(32), "127.0.0.1:51878").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// split mode with a dead up path (private-network UDP blocked): no echo ever comes, so every datagram still rides the leg
#[tokio::test(flavor = "multi_thread")]
async fn split_mode_dead_up_path_stays_on_the_leg() {
    let a = key(1);
    let srv_wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let cli_wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/leg", l.local_addr().unwrap());
    let srv = Server::with_udp_in([node_id(&a)].into_iter().collect(), srv_wg.local_addr().unwrap());
    tokio::spawn(srv.clone().serve(l));
    let hole = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // swallows the beacons, never echoes
    let leg_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let leg = leg_udp.local_addr().unwrap();
    drop(leg_udp);
    let cfg = ClientCfg { url, listen: leg, wg: cli_wg.local_addr().unwrap(), key: a, up_udp: Some(hole.local_addr().unwrap()), door: false, alt_urls: vec![], dead_after: DEAD_AFTER };
    let (tx, _rx) = tokio::sync::watch::channel(false);
    tokio::spawn(client_run(cfg, tx));
    let mut buf = vec![0u8; 65536];
    // the beacon reaches the hole, so the client did get its token and tried the up path
    tokio::time::timeout(Duration::from_secs(5), hole.recv_from(&mut buf)).await.expect("no beacon").unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    for i in 0..30u32 {
        cli_wg.send_to(&i.to_be_bytes(), leg).await.unwrap();
    }
    let mut got = 0;
    while let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_secs(3), srv_wg.recv_from(&mut buf)).await {
        assert_eq!(n, 4);
        got += 1;
        if got == 30 { break; }
    }
    assert_eq!(got, 30, "uplink went into the dead udp path");
    assert_eq!(srv.udp_sources().await, 0);
}

/// a UDP relay between the client and the door that records every beacon and can hold them back (the lossy long-haul "path")
struct Tap { addr: std::net::SocketAddr, seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>>, hold: Arc<std::sync::atomic::AtomicBool> }

async fn tap(door: std::net::SocketAddr) -> Tap {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let up = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    up.connect(door).await.unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hold = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let client = Arc::new(std::sync::Mutex::new(None));
    let (s1, u1, seen1, hold1, c1) = (s.clone(), up.clone(), seen.clone(), hold.clone(), client.clone());
    tokio::spawn(async move {
        let mut b = vec![0u8; 65536];
        while let Ok((n, f)) = s1.recv_from(&mut b).await {
            *c1.lock().unwrap() = Some(f);
            if beacon_parts(&b[..n]).is_some() {
                seen1.lock().unwrap().push(b[..n].to_vec());
                if hold1.load(std::sync::atomic::Ordering::SeqCst) { continue; }
            }
            let _ = u1.send(&b[..n]).await;
        }
    });
    let (s2, c2) = (s.clone(), client.clone());
    tokio::spawn(async move {
        let mut b = vec![0u8; 65536];
        while let Ok(n) = up.recv(&mut b).await {
            let to = *c2.lock().unwrap();
            if let Some(to) = to { let _ = s2.send_to(&b[..n], to).await; }
        }
    });
    Tap { addr: s.local_addr().unwrap(), seen, hold }
}

/// split rig with a tap on the up path; returns (srv_wg, srv, door, tap, node id, client key)
async fn rig_tap() -> (Arc<UdpSocket>, Arc<Server>, std::net::SocketAddr, Tap, String) {
    let a = key(1);
    let id = node_id(&a);
    let srv_wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let cli_wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/leg", l.local_addr().unwrap());
    let srv = Server::with_udp_in([id.clone()].into_iter().collect(), srv_wg.local_addr().unwrap());
    let door_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let door = door_sock.local_addr().unwrap();
    tokio::spawn(srv.clone().serve_udp(door_sock));
    tokio::spawn(srv.clone().serve(l));
    let t = tap(door).await;
    let leg_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let leg = leg_udp.local_addr().unwrap();
    drop(leg_udp);
    let cfg = ClientCfg { url, listen: leg, wg: cli_wg.local_addr().unwrap(), key: a, up_udp: Some(t.addr), door: false, alt_urls: vec![], dead_after: DEAD_AFTER };
    let (tx, _rx) = tokio::sync::watch::channel(false);
    tokio::spawn(client_run(cfg, tx));
    for _ in 0..200 {
        if srv.udp_sources().await == 1 { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(srv.udp_sources().await, 1, "client never sent up udp");
    (srv_wg, srv, door, t, id)
}

/// sends `p` to the door from a fresh address; true if anything came back within 300 ms
async fn answered(p: &[u8], door: std::net::SocketAddr) -> bool {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(p, door).await.unwrap();
    let mut b = [0u8; 2048];
    tokio::time::timeout(Duration::from_millis(300), s.recv_from(&mut b)).await.is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn door_replayed_beacon_old_seq_and_bad_mac_change_nothing() {
    let (srv_wg, srv, door, t, _id) = rig_tap().await;
    let caught = t.seen.lock().unwrap().last().cloned().expect("no beacon seen on the path");
    // the attacker replays the copied beacon from its own address: no echo, the node stays bound to the real source
    let atk = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    atk.send_to(&caught, door).await.unwrap();
    let mut b = [0u8; 2048];
    assert!(tokio::time::timeout(Duration::from_millis(300), atk.recv_from(&mut b)).await.is_err(), "replayed beacon echoed");
    // and data from the attacker's address reaches nothing
    atk.send_to(b"\x04after replay", door).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(300), srv_wg.recv_from(&mut b)).await.is_err(), "attacker rebound the node");
    assert_eq!(srv.udp_sources().await, 1);
    // a flipped MAC bit with a high seq: refused
    let (tid, seq, _) = beacon_parts(&caught).unwrap();
    let mut bad = caught.clone();
    bad[11..19].copy_from_slice(&(seq + 100).to_be_bytes());
    assert!(!answered(&bad, door).await, "a beacon with a wrong MAC was echoed");
    // random bytes and beacon-sized garbage: nothing
    assert!(!answered(&[0x5a; 200], door).await);
    let mut junk = BEACON.to_vec();
    junk.extend_from_slice(&tid);
    junk.extend_from_slice(&[0xff; 24]);
    assert!(!answered(&junk, door).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn door_oversize_datagram_is_dropped_even_from_the_bound_source() {
    let (srv_wg, _srv, door, t, _id) = rig_tap().await;
    let _ = t;
    // send through the tap's own socket? the tap forwards from its bound up-socket, which is the node's source
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(&[1u8; 2000], t.addr).await.unwrap(); // rides the tap, i.e. from the bound source
    let mut b = vec![0u8; 4096];
    assert!(tokio::time::timeout(Duration::from_millis(400), srv_wg.recv_from(&mut b)).await.is_err(), "a 2000-byte datagram reached wireguard");
    s.send_to(&[1u8; 1400], t.addr).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), srv_wg.recv_from(&mut b)).await.expect("1400 B lost").unwrap();
    assert_eq!(n, 1400);
    let _ = door;
}

#[tokio::test(flavor = "multi_thread")]
async fn door_revoked_node_is_cut_at_once() {
    let (srv_wg, srv, door, t, id) = rig_tap().await;
    // hold the next beacon back on the path: it is valid and newer than anything the server saw
    t.hold.store(true, std::sync::atomic::Ordering::SeqCst);
    let n0 = t.seen.lock().unwrap().len();
    for _ in 0..150 {
        if t.seen.lock().unwrap().len() > n0 { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let fresh = t.seen.lock().unwrap().last().cloned().unwrap();
    let cut = srv.set_admitted(BTreeSet::new()).await;
    assert_eq!(cut, vec![id.clone()]);
    assert_eq!(srv.udp_sources().await, 0, "revoked node kept its udp source");
    assert!(!answered(&fresh, door).await, "a revoked node's freshest beacon was echoed");
    // the leg is closed and the pipe has no sender: nothing more reaches wireguard from it
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(b"\x04revoked", t.addr).await.unwrap();
    let mut b = [0u8; 64];
    assert!(tokio::time::timeout(Duration::from_millis(400), srv_wg.recv_from(&mut b)).await.is_err());
    // and it cannot come back: the hello door refuses it
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(srv.udp_sources().await, 0);
}

#[test]
fn door_binds_a_private_lan_address_only() {
    for ok in ["192.168.1.20:51880", "10.0.0.5:51880", "172.16.3.4:51880"] {
        assert!(door_addr_ok(&ok.parse().unwrap()).is_ok(), "{ok}");
    }
    for bad in ["0.0.0.0:51880", "198.51.100.8:51880", "100.64.0.1:51880", "10.77.1.1:51880", "[::]:51880"] {
        assert!(door_addr_ok(&bad.parse().unwrap()).is_err(), "{bad}");
    }
}

// ---------- relay failover ----------

/// a TCP relay in front of a leg server that can go silent: while `stall` is set it keeps the connection open but
/// moves no bytes, which is what a dead path looks like to the client (no RST, no close)
async fn stallable_relay(upstream: std::net::SocketAddr, stall: Arc<std::sync::atomic::AtomicBool>) -> std::net::SocketAddr {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            let Ok(u) = tokio::net::TcpStream::connect(upstream).await else { continue };
            let (cr, cw) = c.into_split();
            let (ur, uw) = u.into_split();
            for (mut r, mut w, st) in [(Box::new(cr) as Box<dyn tokio::io::AsyncRead + Unpin + Send>, Box::new(uw) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>, stall.clone()),
                                       (Box::new(ur), Box::new(cw), stall.clone())] {
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    loop {
                        let Ok(n) = r.read(&mut b).await else { return };
                        if n == 0 { return; }
                        while st.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_secs(3600)).await; }
                        if w.write_all(&b[..n]).await.is_err() { return; }
                    }
                });
            }
        }
    });
    a
}

/// two leg servers in front of one WireGuard (two relays to the same server) and a client that knows both
async fn rig_two_relays(dead_after: Duration, first_via_stall: Option<Arc<std::sync::atomic::AtomicBool>>)
    -> (Arc<UdpSocket>, Arc<UdpSocket>, std::net::SocketAddr, Arc<Server>, Arc<Server>, String) {
    let a = key(1);
    let srv_wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let cli_wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let ids: BTreeSet<String> = [node_id(&a)].into();
    let mut srvs = vec![];
    let mut urls = vec![];
    for _ in 0..2 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut at = l.local_addr().unwrap();
        let s = Server::new(ids.clone(), srv_wg.local_addr().unwrap());
        tokio::spawn(s.clone().serve(l));
        if urls.is_empty() {
            if let Some(st) = &first_via_stall { at = stallable_relay(at, st.clone()).await; }
        }
        urls.push(format!("ws://{at}/v1/leg"));
        srvs.push(s);
    }
    let leg_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let leg = leg_udp.local_addr().unwrap();
    drop(leg_udp);
    let cfg = ClientCfg { url: urls[0].clone(), listen: leg, wg: cli_wg.local_addr().unwrap(), key: a.clone(), up_udp: None, door: false,
                          alt_urls: vec![urls[1].clone()], dead_after };
    let (tx, _rx) = tokio::sync::watch::channel(false);
    tokio::spawn(client_run(cfg, tx));
    let b = srvs.pop().unwrap();
    (srv_wg, cli_wg, leg, srvs.pop().unwrap(), b, node_id(&a))
}

/// push datagrams from the client side every 20 ms until one reaches the server WireGuard through `via`; returns how long
async fn time_to_flow(cli_wg: &UdpSocket, leg: std::net::SocketAddr, srv_wg: &UdpSocket, via: &Server, id: &str, limit: Duration) -> Option<Duration> {
    let t0 = std::time::Instant::now();
    let mut buf = vec![0u8; 2048];
    while t0.elapsed() < limit {
        let _ = cli_wg.send_to(b"ping", leg).await;
        if let Ok(Ok((_, f))) = tokio::time::timeout(Duration::from_millis(20), srv_wg.recv_from(&mut buf)).await {
            if via.pipe_port(id).await == Some(f.port()) { return Some(t0.elapsed()); }
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
async fn failover_relay_cut_moves_to_the_second_relay_at_once() {
    let (srv_wg, cli_wg, leg, a, b, id) = rig_two_relays(DEAD_AFTER, None).await;
    assert!(time_to_flow(&cli_wg, leg, &srv_wg, &a, &id, Duration::from_secs(5)).await.is_some(), "never up on relay A");
    // relay A drops the node (same effect as A going down with a close or RST)
    a.set_admitted(BTreeSet::new()).await;
    let gap = time_to_flow(&cli_wg, leg, &srv_wg, &b, &id, Duration::from_secs(5)).await.expect("never moved to relay B");
    eprintln!("failover after a cut: {gap:?}");
    assert!(gap < Duration::from_secs(1), "failover took {gap:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn failover_silent_relay_is_left_after_dead_after() {
    let stall = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dead = Duration::from_millis(1500);
    let (srv_wg, cli_wg, leg, a, b, id) = rig_two_relays(dead, Some(stall.clone())).await;
    assert!(time_to_flow(&cli_wg, leg, &srv_wg, &a, &id, Duration::from_secs(5)).await.is_some(), "never up on relay A");
    // relay A goes silent: no close, no RST, bytes just stop
    stall.store(true, std::sync::atomic::Ordering::Relaxed);
    let gap = time_to_flow(&cli_wg, leg, &srv_wg, &b, &id, Duration::from_secs(6)).await.expect("never left the silent relay");
    eprintln!("failover from a silent relay (dead_after {dead:?}): {gap:?}");
    assert!(gap < dead + Duration::from_secs(1), "failover took {gap:?}");
}
