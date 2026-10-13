//! Regressions for a WAN outage: live, signed calls hung until the client gave up at ~20 s while a heavily loaded
//! replica was leader at a 500 ms heartbeat.
//! - a leader that cannot reach a quorum answers within leader_wait instead of hanging;
//! - a follower behind a long-haul path (connect 300 ms + reply 300 ms, a test proxy in front of replica 3) catches up
//!   at a 500 ms heartbeat;
//! - a voter whose replies take 1.5 s (a heavily loaded host) stays a member: no term change, same leader, state caught up.

use ed25519_dalek::SigningKey;
use net_mesh::raft::*;
use net_mesh::*;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }

async fn call_async(control: String, req: Request) -> Result<Response, String> {
    tokio::task::spawn_blocking(move || call(&control, &req)).await.unwrap()
}

/// listens on a fresh port and forwards to `to`: a new connection's first bytes wait `connect` (the connect round trip),
/// every chunk coming back waits `reply` (pipelined, in order)
async fn slow_proxy(to: String, connect: Duration, reply: Duration) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            let to = to.clone();
            tokio::spawn(async move {
                tokio::time::sleep(connect).await;
                let Ok(u) = TcpStream::connect(&to).await else { return };
                let (mut cr, mut cw) = c.into_split();
                let (mut ur, mut uw) = u.into_split();
                tokio::spawn(async move { let _ = tokio::io::copy(&mut cr, &mut uw).await; });
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    while let Ok(n) = ur.read(&mut buf).await {
                        if n == 0 || tx.send((Instant::now() + reply, buf[..n].to_vec())).is_err() { break; }
                    }
                });
                while let Some((at, b)) = rx.recv().await {
                    tokio::time::sleep_until(at.into()).await;
                    if cw.write_all(&b).await.is_err() { break; }
                }
            });
        }
    });
    addr
}

struct Group {
    reps: BTreeMap<u64, Replica>,
    all: String,
}

/// three replicas at `t`; every peer reaches replica 3 through a proxy with the given latency
async fn group(admitted: BTreeSet<String>, t: Timing, connect: Duration, reply: Duration) -> Group {
    let (mut raft_ls, mut client_ls, mut peers, mut clients) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), Vec::new());
    for id in 1..=3u64 {
        let rl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ra = rl.local_addr().unwrap().to_string();
        peers.insert(id, if id == 3 { slow_proxy(ra, connect, reply).await } else { ra });
        clients.push(cl.local_addr().unwrap().to_string());
        raft_ls.insert(id, rl);
        client_ls.insert(id, cl);
    }
    let mut reps = BTreeMap::new();
    // 2 and 3 listen before 1 initializes and elects itself, so the slow replica is a follower
    for id in [2u64, 3, 1] {
        let opts = Opts { id, secret: [9u8; 32], dir: None, init: (id == 1).then(|| peers.clone()), seed: None, timing: t, fast_elect: true };
        let r = Replica::start(opts, Control::new(admitted.clone(), None), raft_ls.remove(&id).unwrap(), client_ls.remove(&id).unwrap()).await.unwrap();
        reps.insert(id, r);
    }
    Group { reps, all: clients.join(",") }
}

async fn leader_of(g: &Group) -> u64 {
    for _ in 0..100 {
        if let Some(l) = g.reps[&1].raft.current_leader().await {
            return l;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no leader in 10 s");
}

fn nodes(r: &Replica) -> usize { r.ctl.lock().unwrap().state.nodes.len() }

fn term(r: &Replica) -> u64 { r.raft.metrics().borrow().current_term }

/// commits three registrations, each within leader_wait; returns how long each took
async fn commit_three(g: &Group, t: Timing) -> Vec<Duration> {
    let wait = Duration::from_millis(2 * t.election_max + 2000);
    let mut took = Vec::new();
    let now = now();
    for (i, k) in [key(41), key(42), key(43)].iter().enumerate() {
        let s = Instant::now();
        let r = call_async(g.all.clone(), Request::signed(k, "register", now, &format!("wg{i}"), vec![])).await.unwrap();
        took.push(s.elapsed());
        assert!(r.ok, "register {i}: {r:?}");
        assert!(took[i] < wait, "register {i} took {:?}, leader_wait is {wait:?}", took[i]);
    }
    took
}

fn admitted() -> BTreeSet<String> { [key(41), key(42), key(43)].iter().map(node_id).collect() }

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_long_haul_follower_catches_up_at_a_500ms_heartbeat() {
    let t = Timing::wan();
    assert_eq!(t.heartbeat, 500);
    let g = group(admitted(), t, Duration::from_millis(300), Duration::from_millis(300)).await;
    let leader = leader_of(&g).await;
    assert_ne!(leader, 3, "the slow replica must be the follower");
    let took = commit_three(&g, t).await;
    println!("commits took {took:?}");
    let s = Instant::now();
    while nodes(&g.reps[&3]) < 3 {
        assert!(s.elapsed() < Duration::from_secs(10), "replica 3 (300+300 ms) has {} of 3 nodes after 10 s", nodes(&g.reps[&3]));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("replica 3 caught up {:?} after the last commit", s.elapsed());
    for (_, r) in g.reps { r.stop().await; }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voter_with_1500ms_replies_stays_a_member() {
    let t = Timing::wan();
    let g = group(admitted(), t, Duration::from_millis(300), Duration::from_millis(1500)).await;
    let leader = leader_of(&g).await;
    assert_ne!(leader, 3, "the slow replica must be the follower");
    commit_three(&g, t).await;
    // replica 3 learns the leader's term from its first append; wait for that before asserting it never moves
    let s = Instant::now();
    let t0 = term(&g.reps[&leader]);
    while term(&g.reps[&3]) != t0 || g.reps[&3].raft.metrics().borrow().current_leader != Some(leader) {
        assert!(s.elapsed() < Duration::from_secs(10), "replica 3 never joined term {t0}: {}", term(&g.reps[&3]));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // 15 s, five election timeouts: nobody's term moves, replica 3 keeps the same leader and gets every entry
    let s = Instant::now();
    let mut caught = None;
    while s.elapsed() < Duration::from_secs(15) {
        for (id, r) in &g.reps {
            assert_eq!(term(r), t0, "replica {id} changed term at {:?}", s.elapsed());
        }
        let m = g.reps[&3].raft.metrics().borrow().clone();
        assert_eq!(m.current_leader, Some(leader), "replica 3 lost its leader at {:?}: {:?}", s.elapsed(), m.state);
        if caught.is_none() && nodes(&g.reps[&3]) == 3 { caught = Some(s.elapsed()); }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(caught.is_some(), "replica 3 (1.5 s replies) has {} of 3 nodes after 15 s", nodes(&g.reps[&3]));
    println!("replica 3 caught up after {:?}; term {t0} held 15 s", caught.unwrap());
    for (_, r) in g.reps { r.stop().await; }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leader_without_a_quorum_answers_within_leader_wait() {
    let t = Timing::wan();
    let wait = Duration::from_millis(2 * t.election_max + 2000);
    let mut g = group(admitted(), t, Duration::ZERO, Duration::ZERO).await;
    let leader = leader_of(&g).await;
    commit_three(&g, t).await;
    let lc = g.reps[&leader].raft.metrics().borrow().id;
    assert_eq!(lc, leader);
    // both followers die; the leader keeps its role (openraft 0.9 has no check-quorum) and must still answer
    for id in [1u64, 2, 3] {
        if id != leader { g.reps.remove(&id).unwrap().stop().await; }
    }
    let client = g.all.split(',').nth(leader as usize - 1).unwrap().to_string();
    let s = Instant::now();
    let r = call_async(client, Request::signed(&key(41), "register", now() + 1, "wgX", vec![])).await;
    let took = s.elapsed();
    println!("leader {leader} without quorum answered in {took:?}: {r:?}");
    assert!(took < wait + Duration::from_secs(2), "took {took:?}, leader_wait is {wait:?}");
    let r = r.expect("an answer, not a client timeout");
    assert!(!r.ok && r.err.contains("quorum"), "{r:?}");
    for (_, r) in g.reps { r.stop().await; }
}
