//! The leg's tab door (browser clients): a valid cap is admitted and wired; expired,
//! wrong-cell, unknown-cell, bad-signature, replayed and no-cap hellos are refused before anything is wired; the peer
//! and rule are gone after expiry, on close and when idle; the rule set lets a tab reach its cell's addr:port only.
//! Host side is a recording fake; KernelTabs' own verifier reading is checked against a real IAM verifier command when
//! `NETMESH_TEST_IAM` names one.

use base64::Engine;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use net_mesh::leg::*;
use net_mesh::now;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio_tungstenite::tungstenite::Message;

const CELL: &str = "demo.echo";
fn cell_at() -> SocketAddrV4 { "10.77.0.5:7900".parse().unwrap() }

#[derive(Default)]
struct Fake {
    peers: Mutex<BTreeMap<String, (Ipv4Addr, SocketAddr)>>,
    allow: Mutex<BTreeSet<(Ipv4Addr, SocketAddrV4)>>,
    log: Mutex<Vec<String>>,
}

impl TabSys for Fake {
    /// caps in this test: `cap:<cell>:<not_after>`
    fn verify_cap(&self, cap: &str, _node: &str, cell: &str) -> Result<u64, String> {
        let p: Vec<&str> = cap.split(':').collect();
        match p.as_slice() {
            ["cap", c, t] if *c == cell => t.parse().map_err(|_| "bad".into()),
            ["cap", _, _] => Err("denied: capability does not grant this cell".into()),
            _ => Err("malformed".into()),
        }
    }
    fn resolve_cell(&self, cell: &str) -> Option<SocketAddrV4> { (cell == CELL || cell == "other.cell").then(cell_at) }
    fn add_peer(&self, wg: &str, addr: Ipv4Addr, ep: SocketAddr) -> Result<(), String> {
        self.log.lock().unwrap().push(format!("add {addr}"));
        self.peers.lock().unwrap().insert(wg.into(), (addr, ep));
        Ok(())
    }
    fn remove_peer(&self, wg: &str) -> Result<(), String> {
        self.log.lock().unwrap().push("remove".into());
        self.peers.lock().unwrap().remove(wg);
        Ok(())
    }
    fn allow(&self, t: Ipv4Addr, c: SocketAddrV4) -> Result<(), String> { self.allow.lock().unwrap().insert((t, c)); Ok(()) }
    fn disallow(&self, t: Ipv4Addr, c: SocketAddrV4) -> Result<(), String> { self.allow.lock().unwrap().remove(&(t, c)); Ok(()) }
}

struct Setup { url: String, fake: Arc<Fake>, wg: Arc<UdpSocket>, tabs: Arc<Tabs> }

async fn setup() -> Setup {
    let wg = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let srv = Server::new(BTreeSet::new(), wg.local_addr().unwrap());
    let fake = Arc::new(Fake::default());
    let tabs = Tabs::new(fake.clone(), base64::engine::general_purpose::STANDARD.encode([9u8; 32]));
    srv.set_tabs(tabs.clone());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/leg", l.local_addr().unwrap());
    tokio::spawn(srv.serve(l));
    Setup { url, fake, wg, tabs }
}

fn wg_pub(n: u8) -> String { base64::engine::general_purpose::STANDARD.encode([n; 32]) }

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn text(ws: &mut Ws) -> String {
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => t,
        other => panic!("want text, got {other:?}"),
    }
}

/// connect, read the nonce, send what `make` builds from it, return the answer and the socket
async fn hello(url: &str, make: impl FnOnce(&str) -> TabHello) -> (String, Ws, TabHello) {
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let ch = text(&mut ws).await;
    let nonce = ch.strip_prefix("net.mesh/leg/v1 ").unwrap().to_string();
    let h = make(&nonce);
    ws.send(Message::Text(serde_json::to_string(&h).unwrap())).await.unwrap();
    (text(&mut ws).await, ws, h)
}

fn signed(k: u8, nonce: &str, cell: &str, cap: &str) -> TabHello {
    TabHello::signed(&SigningKey::from_bytes(&[k; 32]), &wg_pub(k), nonce, cell, cap, now())
}

async fn eventually(what: &str, f: impl Fn() -> bool) {
    for _ in 0..100 {
        if f() { return; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: not within 5 s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_cap_is_admitted_wired_and_carries_datagrams_then_unwired_on_close() {
    let s = setup().await;
    let cap = format!("cap:{CELL}:{}", now() + 300);
    let (ok, mut ws, _) = hello(&s.url, |n| signed(1, n, CELL, &cap)).await;
    let p: Vec<&str> = ok.split(' ').collect();
    assert_eq!(p, ["ok", "10.77.255.1", &wg_pub(9), "10.77.0.5:7900"], "{ok}");
    let (addr, ep) = s.fake.peers.lock().unwrap()[&wg_pub(1)];
    assert_eq!(addr, Ipv4Addr::new(10, 77, 255, 1));
    assert!(ep.ip().is_loopback());
    assert!(s.fake.allow.lock().unwrap().contains(&(addr, cell_at())));
    let l = &s.tabs.leases()[0];
    assert!(l.until <= now() + 300 && l.until + 5 >= now() + 300);

    // up: a datagram on the leg reaches WireGuard from the peer's endpoint; down: WireGuard's answer comes back
    let mut b = Vec::new();
    pack(&mut b, b"wg-up");
    ws.send(Message::Binary(b)).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), s.wg.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!((&buf[..n], from), (&b"wg-up"[..], ep));
    s.wg.send_to(b"wg-down", ep).await.unwrap();
    let down = loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await.unwrap() {
            Some(Ok(Message::Binary(b))) => break b,
            Some(Ok(_)) => continue,
            o => panic!("{o:?}"),
        }
    };
    assert_eq!(unpack(&down), vec![&b"wg-down"[..]]);

    ws.close(None).await.unwrap();
    eventually("peer removed on close", || s.fake.peers.lock().unwrap().is_empty()).await;
    assert!(s.fake.allow.lock().unwrap().is_empty());
    assert!(s.tabs.leases().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_hellos_are_refused_and_nothing_is_wired() {
    let s = setup().await;
    let good = format!("cap:{CELL}:{}", now() + 300);
    let cases: Vec<(&str, Box<dyn FnOnce(&str) -> TabHello>)> = vec![
        ("cap expired", Box::new(|n| signed(2, n, CELL, &format!("cap:{CELL}:{}", now() - 1)))),
        ("cap refused: denied", Box::new(|n| signed(2, n, CELL, "cap:other.cell:9999999999"))),
        ("unknown cell", Box::new(|n| signed(2, n, "nope.cell", "cap:nope.cell:9999999999"))),
        ("bad signature", Box::new({ let g = good.clone(); move |n| { let mut h = signed(2, n, CELL, &g); h.cap = format!("cap:{CELL}:9999999999"); h } })),
        ("bad signature", Box::new({ let g = good.clone(); move |n| { let mut h = signed(2, n, CELL, &g); h.sig = "00".repeat(64); h } })),
        ("no cap", Box::new(|n| signed(2, n, CELL, ""))),
        ("timestamp outside window", Box::new({ let g = good.clone(); move |n| TabHello::signed(&SigningKey::from_bytes(&[2; 32]), &wg_pub(2), n, CELL, &g, now() - 120) })),
        ("bad cell name", Box::new(|n| signed(2, n, "a b", "cap:a b:9999999999"))),
    ];
    for (want, make) in cases {
        let (ans, _ws, _) = hello(&s.url, make).await;
        assert!(ans.starts_with("refused: ") && ans.contains(want), "want {want:?}, got {ans:?}");
    }
    // replayed: a hello that passed on one connection is sent again on another (its nonce is the old one)
    let (ok, _ws1, first) = hello(&s.url, |n| signed(3, n, CELL, &good)).await;
    assert!(ok.starts_with("ok "), "{ok}");
    let (ans, _ws2, _) = hello(&s.url, move |_| first).await;
    assert_eq!(ans, "refused: bad signature");
    // only the one good hello was wired
    assert_eq!(s.fake.log.lock().unwrap().iter().filter(|l| l.starts_with("add")).count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_is_gone_after_the_cap_expires() {
    let s = setup().await;
    let cap = format!("cap:{CELL}:{}", now() + 2);
    let (ok, mut ws, _) = hello(&s.url, |n| signed(4, n, CELL, &cap)).await;
    assert!(ok.starts_with("ok "), "{ok}");
    assert_eq!(s.fake.peers.lock().unwrap().len(), 1);
    // keep sending so idleness is not what cuts it
    for _ in 0..30 {
        let mut b = Vec::new();
        pack(&mut b, b"x");
        if ws.send(Message::Binary(b)).await.is_err() { break; }
        if s.fake.peers.lock().unwrap().is_empty() { break; }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eventually("peer removed at expiry", || s.fake.peers.lock().unwrap().is_empty()).await;
    assert!(s.fake.allow.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_newer_connection_of_the_same_key_takes_the_lease_over() {
    let s = setup().await;
    let cap = format!("cap:{CELL}:{}", now() + 300);
    let (a, ws_a, _) = hello(&s.url, |n| signed(5, n, CELL, &cap)).await;
    let (b, _ws_b, _) = hello(&s.url, |n| signed(5, n, CELL, &cap)).await;
    assert!(a.starts_with("ok ") && b.starts_with("ok "));
    assert_eq!(s.tabs.leases().len(), 1);
    drop(ws_a); // the old connection closing must not unwire the new one
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(s.fake.peers.lock().unwrap().len(), 1);
    assert_eq!(s.tabs.leases().len(), 1);
}

#[test]
fn the_rule_set_lets_a_tab_reach_its_cells_port_and_nothing_else() {
    let tab = Ipv4Addr::new(10, 77, 255, 1);
    let other_tab = Ipv4Addr::new(10, 77, 255, 2);
    let allow: BTreeSet<_> = [(tab, cell_at())].into();
    assert!(tab_rules_pass(&allow, tab, cell_at(), true));
    assert!(!tab_rules_pass(&allow, tab, "10.77.0.5:22".parse().unwrap(), true)); // other port, same host
    assert!(!tab_rules_pass(&allow, tab, "10.77.0.1:7900".parse().unwrap(), true)); // same port, other host
    assert!(!tab_rules_pass(&allow, tab, cell_at(), false)); // udp to the cell
    assert!(!tab_rules_pass(&allow, tab, "10.77.255.2:7900".parse().unwrap(), true)); // tab to tab
    assert!(!tab_rules_pass(&allow, other_tab, cell_at(), true)); // another tab's grant is not yours
    assert!(tab_rules_pass(&allow, Ipv4Addr::new(10, 77, 0, 5), "10.77.255.1:50000".parse().unwrap(), true)); // replies
    // and the nft text says the same: an allow lookup then a drop, on input and on forward
    let t = tab_nft_table("netmesh_tabs");
    for chain in ["chain input", "chain forward"] {
        let c = &t[t.find(chain).unwrap()..];
        let c = &c[..c.find('}').unwrap()];
        let acc = c.find("ip saddr 10.77.255.0/24 ip saddr . ip daddr . tcp dport @allow accept").unwrap();
        let drop = c.find("ip saddr 10.77.255.0/24 drop").unwrap();
        assert!(acc < drop, "{chain}: accept must come before the drop");
    }
    assert_eq!(tab_nft_element(tab, cell_at()), "{ 10.77.255.1 . 10.77.0.5 . 7900 }");
}

#[test]
fn cells_file_refuses_tab_and_outside_addresses() {
    let d = std::env::temp_dir().join(format!("tabcells-{}", std::process::id()));
    std::fs::write(&d, "# name addr:port\ndemo.echo 10.77.0.5:7900\n").unwrap();
    assert_eq!(KernelTabs::load_cells(&d).unwrap()["demo.echo"], cell_at());
    for bad in ["x 10.77.255.3:1\n", "x 198.51.100.2:80\n", "x\n", "a/b 10.77.0.5:1\n"] {
        std::fs::write(&d, bad).unwrap();
        assert!(KernelTabs::load_cells(&d).is_err(), "{bad:?}");
    }
    let _ = std::fs::remove_file(&d);
}

/// KernelTabs::verify_cap against a real IAM verifier command (`NETMESH_TEST_IAM`, which must support `grant`,
/// `verify` and `policy inspect`): right cell admitted with the grant's not_after, wrong cell and a grant for another
/// key refused. Skipped when the variable is unset or the command is not runnable.
#[test]
fn kernel_verify_cap_reads_a_real_iam() {
    let Ok(iam) = std::env::var("NETMESH_TEST_IAM") else { eprintln!("NETMESH_TEST_IAM unset, skipped"); return };
    if std::process::Command::new(&iam).arg("--help").output().is_err() { eprintln!("{iam} not runnable, skipped"); return; }
    let dir = std::env::temp_dir().join(format!("tab-iam-{}", std::process::id()));
    let d = dir.to_str().unwrap().to_string();
    let to = "ab".repeat(32);
    let out = std::process::Command::new(&iam).args(["grant", "--data-dir", &d, "--to", &to, "--nonce", "1",
        "--action", "net.mesh:cell:demo.echo", "--expires-in", "600"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let cap = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let k = KernelTabs { iam: iam.clone(), iam_data_dir: Some(d.clone()), verify_flags: vec!["--no-revocation-check".into()],
        wg_if: "none".into(), nft_table: "none".into(), priv_prefix: vec![], cells: BTreeMap::new() };
    let t = k.verify_cap(&cap, &to, "demo.echo").unwrap();
    assert!(t > now() + 590 && t <= now() + 600, "not_after {t}");
    assert!(k.verify_cap(&cap, &to, "other.cell").is_err());
    assert!(k.verify_cap(&cap, &"cd".repeat(32), "demo.echo").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
