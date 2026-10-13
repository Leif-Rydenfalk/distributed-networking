//! netmesh-path: probe auth, replay guard, selector rules, and a live failover on loopback.

use net_mesh::path::*;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn keypair(seed: u8) -> (Key, Key) {
    let mut k = [seed; 32];
    k[0] &= 248; // clamp like x25519 does; any 32 bytes work, this keeps keys distinct per seed
    (k, wg_public(&k))
}

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn pair_key_is_the_same_on_both_ends_and_differs_per_pair() {
    let (pa, a_pub) = keypair(1);
    let (pb, b_pub) = keypair(2);
    let (pc, c_pub) = keypair(3);
    assert_eq!(pair_key(&pa, &b_pub), pair_key(&pb, &a_pub));
    assert_ne!(pair_key(&pa, &b_pub), pair_key(&pa, &c_pub));
    assert_ne!(pair_key(&pa, &b_pub), pair_key(&pc, &b_pub));
}

#[test]
fn packet_round_trips_and_a_flipped_bit_is_refused() {
    let k = [7u8; 32];
    let p = Pkt { kind: PING, sender: [9; 32], seq: 42, echo_ns: 123456789 };
    let b = encode(&p, &k);
    assert_eq!(decode(&b, &k), Some(p));
    for i in 0..PKT_LEN {
        let mut t = b;
        t[i] ^= 1;
        assert_eq!(decode(&t, &k), None, "bit flip at byte {i} accepted");
    }
}

#[test]
fn wrong_key_short_long_and_garbage_are_refused() {
    let p = Pkt { kind: PONG, sender: [9; 32], seq: 1, echo_ns: 0 };
    let b = encode(&p, &[1; 32]);
    assert_eq!(decode(&b, &[2; 32]), None);
    assert_eq!(decode(&b[..PKT_LEN - 1], &[1; 32]), None);
    let mut long = b.to_vec();
    long.push(0);
    assert_eq!(decode(&long, &[1; 32]), None);
    assert_eq!(decode(&[0u8; PKT_LEN], &[1; 32]), None);
    let mut bad_kind = b;
    bad_kind[4] = 9;
    assert_eq!(peek_sender(&bad_kind), None);
}

#[test]
fn replayed_or_old_ping_seq_is_refused() {
    let mut g = SeqGuard::default();
    assert!(g.accept(&[1; 32], 5));
    assert!(!g.accept(&[1; 32], 5));
    assert!(!g.accept(&[1; 32], 4));
    assert!(g.accept(&[1; 32], 6));
    assert!(g.accept(&[2; 32], 1), "guard is per sender");
}

#[test]
fn uapi_message_is_what_boringtun_takes() {
    let m = uapi_set_endpoint(&[0xab; 32], a("10.77.1.115:51877"));
    assert_eq!(m, format!("set=1\npublic_key={}\nendpoint=10.77.1.115:51877\n\n", "ab".repeat(32)));
}

#[test]
fn selector_starts_on_fallback_and_takes_direct_after_two_answers() {
    let t0 = Instant::now();
    let lan = a("10.77.1.115:51878");
    let mut s = Selector::new(&[lan], Tuning::default());
    assert_eq!(s.decide(t0), None);
    assert_eq!(s.choice, Choice::Fallback);
    s.pong(lan, Duration::from_millis(5), t0);
    assert_eq!(s.decide(t0), None, "one answer is not enough");
    s.pong(lan, Duration::from_millis(5), t0 + Duration::from_millis(200));
    assert_eq!(s.decide(t0 + Duration::from_millis(200)), Some(Choice::Direct(lan)));
}

#[test]
fn selector_leaves_a_dead_direct_path_within_dead_after() {
    let t0 = Instant::now();
    let lan = a("10.77.1.115:51878");
    let tu = Tuning::default();
    let mut s = Selector::new(&[lan], tu);
    s.pong(lan, Duration::from_millis(5), t0);
    s.pong(lan, Duration::from_millis(5), t0 + Duration::from_millis(200));
    s.decide(t0 + Duration::from_millis(200));
    // last answer at 200 ms; still alive at 700 ms, dead just after
    assert_eq!(s.decide(t0 + Duration::from_millis(700)), None);
    assert_eq!(s.decide(t0 + Duration::from_millis(701)), Some(Choice::Fallback));
}

#[test]
fn selector_moves_to_a_second_direct_path_when_the_first_dies() {
    let t0 = Instant::now();
    let (wifi, cable) = (a("10.77.10.1:51878"), a("10.77.99.2:51878"));
    let mut s = Selector::new(&[wifi, cable], Tuning::default());
    for i in 0..3 {
        let t = t0 + Duration::from_millis(200 * i);
        s.pong(wifi, Duration::from_millis(4), t);
        s.pong(cable, Duration::from_millis(3), t);
        s.decide(t);
    }
    let first = s.choice.clone();
    let (dead, other) = if first == Choice::Direct(wifi) { (wifi, cable) } else { (cable, wifi) };
    // only `other` keeps answering
    for i in 3..8 {
        let t = t0 + Duration::from_millis(200 * i);
        s.pong(other, Duration::from_millis(4), t);
        s.decide(t);
    }
    assert_eq!(s.choice, Choice::Direct(other), "still on {dead} after it went silent");
}

#[test]
fn selector_does_not_flap_between_similar_paths() {
    let t0 = Instant::now();
    let (x, y) = (a("10.77.0.11:1"), a("10.77.0.12:1"));
    let mut s = Selector::new(&[x, y], Tuning::default());
    let mut switches = 0;
    for i in 0..100u64 {
        let t = t0 + Duration::from_millis(200 * i);
        // RTTs that cross each other every step, within 30 % of each other
        let (rx, ry) = if i % 2 == 0 { (10, 12) } else { (12, 10) };
        s.pong(x, Duration::from_millis(rx), t);
        s.pong(y, Duration::from_millis(ry), t);
        if s.decide(t).is_some() {
            switches += 1;
        }
    }
    assert_eq!(switches, 1, "only the first move off the fallback");
}

#[test]
fn selector_moves_to_a_much_faster_path() {
    let t0 = Instant::now();
    let (slow, fast) = (a("10.77.0.1:1"), a("10.77.1.2:1"));
    let mut s = Selector::new(&[slow, fast], Tuning::default());
    for i in 0..3u64 {
        let t = t0 + Duration::from_millis(200 * i);
        s.pong(slow, Duration::from_millis(250), t);
        s.decide(t);
    }
    assert_eq!(s.choice, Choice::Direct(slow));
    for i in 3..6u64 {
        let t = t0 + Duration::from_millis(200 * i);
        s.pong(slow, Duration::from_millis(250), t);
        s.pong(fast, Duration::from_millis(5), t);
        s.decide(t);
    }
    assert_eq!(s.choice, Choice::Direct(fast));
}

#[test]
fn a_pong_from_an_unknown_address_changes_nothing() {
    let t0 = Instant::now();
    let mut s = Selector::new(&[a("10.77.0.1:1")], Tuning::default());
    s.pong(a("10.77.0.9:1"), Duration::from_millis(1), t0);
    s.pong(a("10.77.0.9:1"), Duration::from_millis(1), t0);
    assert_eq!(s.decide(t0), None);
}

/// Records every endpoint the path manager sets, with the time it was set.
#[derive(Clone, Default)]
struct Rec(Arc<Mutex<Vec<(Instant, Key, SocketAddr)>>>);
impl Apply for Rec {
    fn set_endpoint(&mut self, peer: &Key, ep: SocketAddr) -> Result<(), String> {
        self.0.lock().unwrap().push((Instant::now(), *peer, ep));
        Ok(())
    }
}

/// A UDP relay between node A's socket and node B's that can be cut: stands in for the LAN.
async fn cuttable_link(to: SocketAddr, cut: Arc<std::sync::atomic::AtomicBool>) -> SocketAddr {
    use std::sync::atomic::Ordering;
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    // the far side answers to this relay; the relay remembers who to send answers back to
    let back = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    {
        let (sock, back, client, cut) = (sock.clone(), back.clone(), client.clone(), cut.clone());
        tokio::spawn(async move {
            let mut b = [0u8; 256];
            while let Ok((n, from)) = sock.recv_from(&mut b).await {
                *client.lock().unwrap() = Some(from);
                if !cut.load(Ordering::SeqCst) {
                    let _ = back.send_to(&b[..n], to).await;
                }
            }
        });
    }
    {
        let (sock, back, client) = (sock.clone(), back.clone(), client.clone());
        tokio::spawn(async move {
            let mut b = [0u8; 256];
            while let Ok((n, _)) = back.recv_from(&mut b).await {
                let c = *client.lock().unwrap();
                if let (Some(c), false) = (c, cut.load(Ordering::SeqCst)) {
                    let _ = sock.send_to(&b[..n], c).await;
                }
            }
        });
    }
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_failover_to_relay_under_one_second_and_back_when_the_link_returns() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (pa, a_pub) = keypair(11);
    let (pb, b_pub) = keypair(12);
    let sa = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sb = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_addr = sb.local_addr().unwrap();
    let cut = Arc::new(AtomicBool::new(false));
    let link = cuttable_link(b_addr, cut.clone()).await;
    let relay = a("127.0.0.1:50599");
    let rec = Rec::default();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let peer_b = PeerCfg { name: "peer-b".into(), wg_public: b_pub, candidates: vec![link], wg_port: 51877, fallback: relay };
    let peer_a = PeerCfg { name: "peer-a".into(), wg_public: a_pub, candidates: vec![], wg_port: 51877, fallback: relay };
    let (tx_b, _rx_b) = tokio::sync::mpsc::unbounded_channel();
    let ha = tokio::spawn(run(sa, pa, vec![peer_b], Tuning::default(), Box::new(rec.clone()), tx));
    let hb = tokio::spawn(run(sb, pb, vec![peer_a], Tuning::default(), Box::new(Rec::default()), tx_b));

    let direct = SocketAddr::new(link.ip(), 51877);
    let s = tokio::time::timeout(Duration::from_secs(3), rx.recv()).await.expect("no switch to direct in 3 s").unwrap();
    assert_eq!((s.to, s.direct), (direct, true));

    let t_cut = Instant::now();
    cut.store(true, Ordering::SeqCst);
    let s = tokio::time::timeout(Duration::from_secs(3), rx.recv()).await.expect("no failover in 3 s").unwrap();
    let gap = t_cut.elapsed();
    assert_eq!((s.to, s.direct), (relay, false));
    assert!(gap < Duration::from_secs(1), "failover took {gap:?}");
    eprintln!("failover after cut: {gap:?}");

    let t_back = Instant::now();
    cut.store(false, Ordering::SeqCst);
    let s = tokio::time::timeout(Duration::from_secs(3), rx.recv()).await.expect("no return in 3 s").unwrap();
    let back = t_back.elapsed();
    assert_eq!((s.to, s.direct), (direct, true));
    assert!(back < Duration::from_secs(1), "return took {back:?}");
    eprintln!("back on direct after restore: {back:?}");

    let eps: Vec<SocketAddr> = rec.0.lock().unwrap().iter().map(|r| r.2).collect();
    assert_eq!(eps, vec![relay, direct, relay, direct]);
    ha.abort();
    hb.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_gets_no_answer() {
    let (pa, _) = keypair(21);
    let (_, b_pub) = keypair(22);
    let (stranger_priv, stranger_pub) = keypair(23);
    let sa = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = sa.local_addr().unwrap();
    let peer_b = PeerCfg { name: "b".into(), wg_public: b_pub, candidates: vec![], wg_port: 1, fallback: a("127.0.0.1:9") };
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let h = tokio::spawn(run(sa, pa, vec![peer_b], Tuning::default(), Box::new(Rec::default()), tx));
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // a correctly formed ping from a key A does not know, and one that claims to be B but cannot know the pair key
    let k = pair_key(&stranger_priv, &wg_public(&pa));
    s.send_to(&encode(&Pkt { kind: PING, sender: stranger_pub, seq: 1, echo_ns: 0 }, &k), a_addr).await.unwrap();
    s.send_to(&encode(&Pkt { kind: PING, sender: b_pub, seq: 1, echo_ns: 0 }, &k), a_addr).await.unwrap();
    s.send_to(b"hello", a_addr).await.unwrap();
    let mut buf = [0u8; 256];
    let r = tokio::time::timeout(Duration::from_millis(700), s.recv_from(&mut buf)).await;
    assert!(r.is_err(), "stranger got an answer");
    h.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_ping_gets_one_answer_only() {
    let (pa, a_pub) = keypair(31);
    let (pb, b_pub) = keypair(32);
    let sa = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = sa.local_addr().unwrap();
    let peer_b = PeerCfg { name: "b".into(), wg_public: b_pub, candidates: vec![], wg_port: 1, fallback: a("127.0.0.1:9") };
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let h = tokio::spawn(run(sa, pa, vec![peer_b], Tuning::default(), Box::new(Rec::default()), tx));
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ping = encode(&Pkt { kind: PING, sender: b_pub, seq: 77, echo_ns: 5 }, &pair_key(&pb, &a_pub));
    let mut buf = [0u8; 256];
    s.send_to(&ping, a_addr).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), s.recv_from(&mut buf)).await.expect("no pong").unwrap();
    let pong = decode(&buf[..n], &pair_key(&pb, &a_pub)).expect("pong does not verify");
    assert_eq!((pong.kind, pong.seq, pong.echo_ns, pong.sender), (PONG, 77, 5, a_pub));
    s.send_to(&ping, a_addr).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(500), s.recv_from(&mut buf)).await.is_err(), "replay answered");
    h.abort();
}
