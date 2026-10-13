//! Control-plane acceptance, the part a test can prove: admitted nodes get addresses and see each other; a stranger,
//! a forged signature, a replay and a stale timestamp are refused, in-process and over a real TCP socket.

use ed25519_dalek::SigningKey;
use net_mesh::*;
use std::collections::BTreeSet;

fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }

fn ctl(admit: &[&SigningKey]) -> Control {
    Control::new(admit.iter().map(|k| node_id(k)).collect::<BTreeSet<_>>(), None)
}

#[test]
fn admitted_nodes_get_addresses_and_see_each_other() {
    let (a, b) = (key(1), key(2));
    let mut c = ctl(&[&a, &b]);
    let t = now();
    let ra = c.handle(&Request::signed(&a, "register", t, "wgA", vec!["192.0.2.4:51877".into()]), t);
    let rb = c.handle(&Request::signed(&b, "register", t, "wgB", vec![]), t);
    assert!(ra.ok && rb.ok, "{ra:?} {rb:?}");
    assert!(ra.addr.starts_with("10.77.") && rb.addr.starts_with("10.77."));
    assert_ne!(ra.addr, rb.addr);
    assert_eq!(rb.peers.len(), 1);
    assert_eq!(rb.peers[0].wg, "wgA");
    assert_eq!(rb.peers[0].endpoints, vec!["192.0.2.4:51877".to_string()]);
    // address is stable across re-registration
    let ra2 = c.handle(&Request::signed(&a, "register", t + 1, "wgA", vec![]), t + 1);
    assert_eq!(ra2.addr, ra.addr);
}

#[test]
fn stranger_is_refused_and_never_listed() {
    let (a, stranger) = (key(1), key(9));
    let mut c = ctl(&[&a]);
    let t = now();
    let r = c.handle(&Request::signed(&stranger, "register", t, "wgX", vec![]), t);
    assert!(!r.ok);
    assert_eq!(r.err, "not admitted");
    let ra = c.handle(&Request::signed(&a, "peers", t, "", vec![]), t);
    assert!(ra.ok && ra.peers.is_empty());
}

#[test]
fn forged_signature_is_refused() {
    let (a, b) = (key(1), key(2));
    let mut c = ctl(&[&a]);
    let t = now();
    // b signs, but claims to be a
    let mut req = Request::signed(&b, "register", t, "wgEvil", vec![]);
    req.node = node_id(&a);
    assert_eq!(c.handle(&req, t).err, "bad signature");
    // a's genuine request with the wg key swapped after signing
    let mut req = Request::signed(&a, "register", t, "wgA", vec![]);
    req.wg = "wgEvil".into();
    assert_eq!(c.handle(&req, t).err, "bad signature");
}

#[test]
fn replay_and_stale_timestamps_are_refused() {
    let a = key(1);
    let mut c = ctl(&[&a]);
    let t = now();
    let req = Request::signed(&a, "register", t, "wgA", vec![]);
    assert!(c.handle(&req, t).ok);
    assert_eq!(c.handle(&req, t).err, "replay");
    let old = Request::signed(&a, "register", t - 3600, "wgA", vec![]);
    assert_eq!(c.handle(&old, t).err, "timestamp outside window");
    let future = Request::signed(&a, "register", t + 3600, "wgA", vec![]);
    assert_eq!(c.handle(&future, t).err, "timestamp outside window");
}

#[test]
fn over_tcp_stranger_refused_member_served() {
    let (a, stranger) = (key(1), key(9));
    let dir = std::env::temp_dir().join(format!("netmesh-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let admitted = dir.join("admitted.json");
    std::fs::write(&admitted, serde_json::to_string(&vec![node_id(&a)]).unwrap()).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let listen = format!("127.0.0.1:{port}");
    let mut srv = std::process::Command::new(env!("CARGO_BIN_EXE_netmesh-control"))
        .args(["--listen", &listen, "--admitted", admitted.to_str().unwrap(), "--state", dir.join("state.json").to_str().unwrap()])
        .stderr(std::process::Stdio::null()).spawn().unwrap();
    let mut ok = None;
    for _ in 0..50 {
        if let Ok(r) = call(&listen, &Request::signed(&a, "register", now(), "wgA", vec![])) { ok = Some(r); break; }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let r = ok.expect("server never answered");
    assert!(r.ok && r.addr.starts_with("10.77."), "{r:?}");
    let s = call(&listen, &Request::signed(&stranger, "register", now(), "wgX", vec![])).unwrap();
    assert!(!s.ok && s.err == "not admitted", "{s:?}");
    // state file is 0600
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.join("state.json")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    srv.kill().ok();
    let refuse = std::process::Command::new(env!("CARGO_BIN_EXE_netmesh-control"))
        .args(["--listen", "0.0.0.0:0", "--admitted", admitted.to_str().unwrap()]).output().unwrap();
    assert_eq!(refuse.status.code(), Some(2), "must refuse to bind 0.0.0.0");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn node_id_from_seed_is_the_public_key() {
    // the node id is the hex ed25519 public key of the 32-byte seed in identity/node.key
    let k = key(7);
    assert_eq!(node_id(&k), hex(k.verifying_key().as_bytes()));
    assert_eq!(node_id(&k).len(), 64);
}

#[test]
fn wg_quick_lists_every_endpoint_and_keeps_the_first_as_default() {
    let peer = |eps: &[&str]| Peer { node: "n".into(), wg: "k".into(), addr: "10.77.1.2".into(),
                                    endpoints: eps.iter().map(|s| s.to_string()).collect(), last_seen: 0 };
    let resp = Response { ok: true, addr: "10.77.1.1".into(),
                          peers: vec![peer(&["198.51.100.75:51877", "203.0.113.186:51877"]), peer(&["192.0.2.3:51877"])],
                          ..Default::default() };
    let c = wg_quick("priv", 51877, &resp);
    assert!(c.contains("Endpoint = 198.51.100.75:51877\n"), "{c}");
    assert!(c.contains("# Endpoints = 198.51.100.75:51877,203.0.113.186:51877\n"), "{c}");
    assert_eq!(c.matches("# Endpoints").count(), 1, "a single-endpoint peer gets no list: {c}");
}

fn cap_ctl(admit: &[&SigningKey]) -> Control {
    let mut c = ctl(admit);
    // stand-in for the external IAM verifier: the grant "ok:<node>" admits exactly that node
    c.cap_verifier = Some(Box::new(|cap: &str, node: &str| cap == format!("ok:{node}")));
    c
}

#[test]
fn a_capability_grant_admits_a_node_that_is_not_listed() {
    let (a, b) = (key(1), key(9));
    let mut c = cap_ctl(&[&a]);
    let t = now();
    let mut r = Request::signed(&b, "register", t, "wgb", vec!["192.0.2.4:51877".into()]);
    assert!(!c.handle(&r, t).ok, "no grant -> refused");
    r = Request::signed(&b, "register", t + 1, "wgb", vec![]);
    r.cap = format!("ok:{}", node_id(&key(8)));                         // a grant for someone else
    assert!(!c.handle(&r, t + 1).ok, "grant for another node -> refused");
    r = Request::signed(&b, "register", t + 2, "wgb", vec![]);
    r.cap = format!("ok:{}", node_id(&b));
    let resp = c.handle(&r, t + 2);
    assert!(resp.ok, "{}", resp.err);
    assert!(resp.addr.starts_with("10.77."));
    // the listed node now sees the granted one
    let pa = c.handle(&Request::signed(&a, "register", t + 3, "wga", vec![]), t + 3);
    assert!(pa.peers.iter().any(|p| p.node == node_id(&b)), "{:?}", pa.peers);
}

#[test]
fn a_revoked_grant_drops_the_node_at_its_next_call() {
    let (a, b) = (key(1), key(9));
    let mut c = cap_ctl(&[&a]);
    let t = now();
    let mut r = Request::signed(&b, "register", t, "wgb", vec![]);
    r.cap = format!("ok:{}", node_id(&b));
    assert!(c.handle(&r, t).ok);
    c.cap_verifier = Some(Box::new(|_: &str, _: &str| false));              // revoked
    let mut r2 = Request::signed(&b, "peers", t + 1, "wgb", vec![]);
    r2.cap = format!("ok:{}", node_id(&b));
    assert!(!c.handle(&r2, t + 1).ok);
    let pa = c.handle(&Request::signed(&a, "register", t + 2, "wga", vec![]), t + 2);
    assert!(!pa.peers.iter().any(|p| p.node == node_id(&b)), "revoked node still listed");
}

#[test]
fn without_a_verifier_a_grant_is_never_enough() {
    let b = key(9);
    let mut c = ctl(&[&key(1)]);
    let t = now();
    let mut r = Request::signed(&b, "register", t, "wgb", vec![]);
    r.cap = format!("ok:{}", node_id(&b));
    assert!(!c.handle(&r, t).ok);
}
