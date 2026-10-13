//! Raft acceptance: three replicas in process on loopback TCP; nodes register (one through a follower, so the
//! forward op runs); the leader is killed; a call through a survivor still answers and the new leader holds the old
//! state. Also: a raft message with a bad MAC is refused.

use ed25519_dalek::SigningKey;
use net_mesh::raft::*;
use net_mesh::*;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;
use tokio::net::TcpListener;

fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }

async fn call_async(control: String, req: Request) -> Result<Response, String> {
    tokio::task::spawn_blocking(move || call(&control, &req)).await.unwrap()
}

async fn wait_leader(rs: &[&Replica], not: Option<u64>) -> u64 {
    for _ in 0..100 {
        for r in rs {
            if let Some(l) = r.raft.current_leader().await {
                if Some(l) != not && rs.iter().any(|x| x.id == l) {
                    return l;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no leader in 10 s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_replicas_survive_the_leader_dying() {
    let (a, b, c) = (key(1), key(2), key(3));
    let admitted: BTreeSet<String> = [&a, &b, &c].iter().map(|k| node_id(k)).collect();
    let secret = [7u8; 32];
    let mut raft_ls = Vec::new();
    let mut client_ls = Vec::new();
    let mut peers = BTreeMap::new();
    let mut clients = BTreeMap::new();
    for id in 1..=3u64 {
        let rl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        peers.insert(id, rl.local_addr().unwrap().to_string());
        clients.insert(id, cl.local_addr().unwrap().to_string());
        raft_ls.push(rl);
        client_ls.push(cl);
    }
    let mut reps = Vec::new();
    for (i, (rl, cl)) in raft_ls.into_iter().zip(client_ls).enumerate() {
        let id = i as u64 + 1;
        let opts = Opts { id, secret, dir: None, init: (id == 1).then(|| peers.clone()), seed: None, timing: Timing::lan(), fast_elect: true };
        reps.push(Replica::start(opts, Control::new(admitted.clone(), None), rl, cl).await.unwrap());
    }
    let leader = wait_leader(&reps.iter().collect::<Vec<_>>(), None).await;
    let follower = (1..=3).find(|&i| i != leader).unwrap();
    let all = clients.values().cloned().collect::<Vec<_>>().join(",");

    // a registers at the leader, b through a follower (forward op)
    let t = now();
    let ra = call_async(clients[&leader].clone(), Request::signed(&a, "register", t, "wgA", vec!["192.0.2.4:51877".into()])).await.unwrap();
    let rb = call_async(clients[&follower].clone(), Request::signed(&b, "register", t, "wgB", vec![])).await.unwrap();
    assert!(ra.ok && rb.ok, "{ra:?} {rb:?}");
    assert_ne!(ra.addr, rb.addr);
    assert_eq!(rb.peers.len(), 1);
    // the replay guard holds across replicas: the same request again, through another port, is refused
    let replay = call_async(all.clone(), Request::signed(&b, "register", t, "wgB", vec![])).await.unwrap();
    assert_eq!(replay.err, "replay");

    // every replica applied both registrations
    tokio::time::sleep(Duration::from_millis(500)).await;
    for r in &reps {
        assert_eq!(r.ctl.lock().unwrap().state.nodes.len(), 2, "replica {} state", r.id);
    }

    // bad MAC on a raft port is refused
    {
        let addr = peers[&follower].clone();
        let reply = tokio::task::spawn_blocking(move || {
            let mut m = RaftMsg::new(&[9u8; 32], "vote", "{}".into());
            m.mac = net_mesh::hex(&[0u8; 32]);
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all((serde_json::to_string(&m).unwrap() + "\n").as_bytes()).unwrap();
            let mut out = String::new();
            BufReader::new(s).read_line(&mut out).unwrap();
            out
        }).await.unwrap();
        assert!(reply.contains("bad mac"), "{reply}");
        // on one persistent link, a frame whose seq does not rise is refused and the link closed
        let addr = peers[&follower].clone();
        let (first, again) = tokio::task::spawn_blocking(move || {
            let s = std::net::TcpStream::connect(addr).unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            let mut send = |m: &RaftMsg| {
                w.write_all((serde_json::to_string(m).unwrap() + "\n").as_bytes()).unwrap();
                let mut out = String::new();
                r.read_line(&mut out).unwrap();
                out
            };
            let m = RaftMsg::with_seq(&secret, "vote", 1, "{}".into());
            (send(&m), send(&m))
        }).await.unwrap();
        assert!(!first.contains("replay") && !first.contains("bad mac"), "{first}");
        assert!(again.contains("\"err\":\"replay\""), "{again}");
    }

    // kill the leader
    let idx = reps.iter().position(|r| r.id == leader).unwrap();
    let dead = reps.remove(idx);
    dead.stop().await;
    let survivors: Vec<&Replica> = reps.iter().collect();
    let new_leader = wait_leader(&survivors, Some(leader)).await;
    assert_ne!(new_leader, leader);

    // a client with the full list (dead one first) still gets an answer, and it carries the old state
    let dead_first = std::iter::once(clients[&leader].clone())
        .chain(clients.iter().filter(|(k, _)| **k != leader).map(|(_, v)| v.clone())).collect::<Vec<_>>().join(",");
    let rc = call_async(dead_first, Request::signed(&c, "register", t + 1, "wgC", vec![])).await.unwrap();
    assert!(rc.ok, "{rc:?}");
    let mut seen: Vec<String> = rc.peers.iter().map(|p| p.wg.clone()).collect();
    seen.sort();
    assert_eq!(seen, vec!["wgA", "wgB"]);
    let pa = call_async(clients[&follower.max(new_leader)].clone(), Request::signed(&a, "peers", t + 2, "", vec![])).await.unwrap();
    assert!(pa.ok && pa.addr == ra.addr && pa.peers.len() == 2, "{pa:?}");
    let nl = reps.iter().find(|r| r.id == new_leader).unwrap();
    assert_eq!(nl.ctl.lock().unwrap().state.nodes.len(), 3);
    for r in reps {
        r.stop().await;
    }
}

#[test]
fn hmac_matches_python_and_secret_mode_is_checked() {
    // python3: hmac.new(bytes([1]*32), b"x", hashlib.sha256).hexdigest()
    let k = [1u8; 32];
    assert_eq!(net_mesh::hex(&hmac(&k, b"x")), "9a6525695460ebcfaee4b950ffa6c3c733d87c4af567a4bdfd2ae664147b7fc0");
    assert_eq!(hmac(&k, b"x"), hmac(&k, b"x"));
    assert_ne!(hmac(&k, b"x"), hmac(&k, b"y"));
    assert_ne!(hmac(&k, b"x"), hmac(&[2u8; 32], b"x"));
    let d = std::env::temp_dir().join(format!("netmesh-raft-secret-{}", std::process::id()));
    std::fs::write(&d, [5u8; 32]).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_secret(&d).is_err());
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(load_secret(&d).unwrap(), [5u8; 32]);
    let _ = std::fs::remove_file(&d);
    assert!(check_bind("0.0.0.0:7743").is_err() && check_bind("127.0.0.1:7743").is_ok());
}

// ---------- phase 2: the file store survives restarts; a pre-Raft state seeds the cluster ----------

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("netmesh-raft-{tag}-{}-{}", std::process::id(), now()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Cluster {
    raft: BTreeMap<u64, String>,
    client: BTreeMap<u64, String>,
    dirs: BTreeMap<u64, std::path::PathBuf>,
    admitted: BTreeSet<String>,
}

impl Cluster {
    async fn new(tag: &str, admitted: BTreeSet<String>) -> Cluster {
        let base = tmpdir(tag);
        let (mut raft, mut client, mut dirs) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        for id in 1..=3u64 {
            // pick free ports, then let them go: a replica restarts on the same addresses
            let rl = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let cl = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            raft.insert(id, rl.local_addr().unwrap().to_string());
            client.insert(id, cl.local_addr().unwrap().to_string());
            dirs.insert(id, base.join(id.to_string()));
        }
        Cluster { raft, client, dirs, admitted }
    }

    async fn start(&self, id: u64, init: bool, seed: Option<State>) -> Replica {
        let rl = TcpListener::bind(&self.raft[&id]).await.unwrap();
        let cl = TcpListener::bind(&self.client[&id]).await.unwrap();
        let opts = Opts { id, secret: [3u8; 32], dir: Some(self.dirs[&id].clone()), init: init.then(|| self.raft.clone()), seed, timing: Timing::lan(), fast_elect: true };
        Replica::start(opts, Control::new(self.admitted.clone(), None), rl, cl).await.unwrap()
    }

    fn all(&self) -> String {
        self.client.values().cloned().collect::<Vec<_>>().join(",")
    }
}

async fn wait_nodes(r: &Replica, n: usize) {
    for _ in 0..100 {
        if r.ctl.lock().unwrap().state.nodes.len() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("replica {} never reached {n} nodes: has {}", r.id, r.ctl.lock().unwrap().state.nodes.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replica_restarts_from_its_raft_dir_and_catches_up() {
    let (a, b, c) = (key(11), key(12), key(13));
    let cl = Cluster::new("restart", [&a, &b, &c].iter().map(|k| node_id(k)).collect()).await;
    let mut reps = BTreeMap::new();
    for id in 1..=3 {
        // the other two must be listening before node 1 initializes, so start 2 and 3 first
        if id == 1 { continue; }
        reps.insert(id, cl.start(id, false, None).await);
    }
    reps.insert(1, cl.start(1, true, None).await);
    let leader = wait_leader(&reps.values().collect::<Vec<_>>(), None).await;
    let t = now();
    let ra = call_async(cl.all(), Request::signed(&a, "register", t, "wgA", vec![])).await.unwrap();
    assert!(ra.ok, "{ra:?}");

    // a follower takes a snapshot (snapshot.json), stops, misses b's registration, restarts from its dir
    let f = (1..=3).find(|&i| i != leader).unwrap();
    wait_nodes(&reps[&f], 1).await;
    reps[&f].raft.trigger().snapshot().await.unwrap();
    for _ in 0..50 {
        if cl.dirs[&f].join("snapshot.json").exists() { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for n in ["vote.json", "log.jsonl", "snapshot.json"] {
        assert!(cl.dirs[&f].join(n).exists(), "replica {f} has no {n}");
    }
    reps.remove(&f).unwrap().stop().await;
    let rb = call_async(cl.all(), Request::signed(&b, "register", t, "wgB", vec![])).await.unwrap();
    assert!(rb.ok, "{rb:?}");
    let back = cl.start(f, false, None).await;
    wait_nodes(&back, 2).await;
    assert_eq!(back.ctl.lock().unwrap().state.nodes[&node_id(&a)].addr, ra.addr);
    reps.insert(f, back);

    // the whole cluster stops and comes back from disk alone (no init), state intact, new writes work
    let before = reps[&leader].ctl.lock().unwrap().state.clone();
    for (_, r) in std::mem::take(&mut reps) {
        r.stop().await;
    }
    for id in 1..=3 {
        reps.insert(id, cl.start(id, false, None).await);
    }
    wait_leader(&reps.values().collect::<Vec<_>>(), None).await;
    let rc = call_async(cl.all(), Request::signed(&c, "register", t + 1, "wgC", vec![])).await.unwrap();
    assert!(rc.ok && rc.peers.len() == 2, "{rc:?}");
    for r in reps.values() {
        wait_nodes(r, 3).await;
        let st = r.ctl.lock().unwrap().state.clone();
        for (n, p) in &before.nodes {
            assert_eq!(st.nodes[n].addr, p.addr, "replica {} lost {n}", r.id);
        }
    }
    // the replay guard survived the restart too
    let replay = call_async(cl.all(), Request::signed(&a, "register", t, "wgA", vec![])).await.unwrap();
    assert_eq!(replay.err, "replay");
    for (_, r) in reps {
        r.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raft_init_seeds_the_pre_raft_state_so_addresses_stay() {
    let (a, b) = (key(21), key(22));
    let admitted: BTreeSet<String> = [&a, &b].iter().map(|k| node_id(k)).collect();
    // today's single server: a registered, with its address
    let mut old = Control::new(admitted.clone(), None);
    let t = now() - 5;
    let ra = old.handle(&Request::signed(&a, "register", t, "wgA", vec!["192.0.2.8:51877".into()]), t);
    assert!(ra.ok);
    let cl = Cluster::new("seed", admitted).await;
    let mut reps = vec![cl.start(2, false, None).await, cl.start(3, false, None).await];
    reps.push(cl.start(1, true, Some(old.state.clone())).await);
    for r in &reps {
        wait_nodes(r, 1).await;
        assert_eq!(r.ctl.lock().unwrap().state, old.state, "replica {}", r.id);
    }
    let rb = call_async(cl.all(), Request::signed(&b, "register", now(), "wgB", vec![])).await.unwrap();
    assert!(rb.ok && rb.peers.len() == 1 && rb.peers[0].addr == ra.addr, "{rb:?}");
    let pa = call_async(cl.all(), Request::signed(&a, "peers", now() + 1, "", vec![])).await.unwrap();
    assert_eq!(pa.addr, ra.addr);
    // a restart with --raft-init again does not re-seed (initialize is refused, the log already holds it)
    let one = reps.pop().unwrap();
    one.stop().await;
    let one = cl.start(1, true, Some(State::default())).await;
    wait_nodes(&one, 2).await;
    reps.push(one);
    for r in reps {
        r.stop().await;
    }
}
