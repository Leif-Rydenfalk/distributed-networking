//! netmesh-control: the net.mesh control server. One JSON line in, one out, per TCP connection.
//!
//!   netmesh-control --listen 127.0.0.1:7741 --admitted admitted.json [--state state/control.json]
//!                   [--cap-action net.mesh:join [--iam CMD] [--iam-data-dir DIR]]
//!
//! Raft mode: one of 3 replicas; the state lives in the Raft log and snapshot, not --state.
//!   netmesh-control --listen ADDR --admitted admitted.json --raft-id N --raft-listen ADDR
//!                   --raft-peers 1=ADDR,2=ADDR,3=ADDR --raft-dir DIR --raft-secret FILE [--raft-init]
//!                   [--raft-heartbeat-ms 500] [--raft-election-ms 1500-3000] [--raft-no-fast-elect]
//!
//! --iam defaults to $NETMESH_IAM, else `iam`: an external verifier command (see `cap_ok` for its interface).
//!
//! Binds where it is told; a host is closed by default, so bind 127.0.0.1 or the mesh address, never 0.0.0.0.

use net_mesh::*;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn main() {
    let listen = arg("--listen").unwrap_or_else(|| "127.0.0.1:7741".into());
    if listen.starts_with("0.0.0.0") || listen.starts_with("[::]") {
        eprintln!("refusing to bind {listen}: a host is closed by default (bind 127.0.0.1 or a mesh address)");
        std::process::exit(2);
    }
    let admitted_path = PathBuf::from(arg("--admitted").unwrap_or_else(|| "admitted.json".into()));
    let admitted = load_admitted(&admitted_path).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(2) });
    let state = arg("--state").map(PathBuf::from);
    if let Some(p) = &state {
        if let Some(d) = p.parent() { let _ = std::fs::create_dir_all(d); }
    }
    let mut control = Control::new(admitted, state);
    // --cap-action ACTION admits a node not on the list when `<iam> verify` (accepted roots, fail-closed) says its
    // presented grant authorizes ACTION for that node id. Without the flag only the admitted list counts.
    if let Some(action) = arg("--cap-action") {
        let iam = arg("--iam").or_else(|| std::env::var("NETMESH_IAM").ok()).unwrap_or_else(|| "iam".into());
        let data_dir = arg("--iam-data-dir");
        eprintln!("capability joins: action {action} via {iam}");
        control.cap_verifier = Some(Box::new(move |cap: &str, node: &str| cap_ok(&iam, data_dir.as_deref(), &action, cap, node)));
    }
    if let Some(id) = arg("--raft-id") {
        return raft_main(id, &listen, control);
    }
    let ctl = Arc::new(Mutex::new(control));
    let l = TcpListener::bind(&listen).unwrap_or_else(|e| { eprintln!("{listen}: {e}"); std::process::exit(2) });
    eprintln!("netmesh-control on {} ({} admitted)", l.local_addr().unwrap(), ctl.lock().unwrap().admitted.len());
    for s in l.incoming().flatten() {
        let ctl = ctl.clone();
        std::thread::spawn(move || {
            s.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
            let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            let mut line = String::new();
            let mut r = BufReader::new(s.try_clone().unwrap()).take(64 * 1024);
            if r.read_line(&mut line).is_err() { return; }
            let resp = match serde_json::from_str::<Request>(&line) {
                Ok(req) => {
                    let out = ctl.lock().unwrap().handle(&req, now());
                    eprintln!("{peer} {} {}.. -> {}", req.op, &req.node.get(..12).unwrap_or(""), if out.ok { "ok" } else { &out.err });
                    out
                }
                Err(e) => Response { ok: false, err: format!("bad request: {e}"), ..Default::default() },
            };
            let mut w = s;
            let _ = w.write_all((serde_json::to_string(&resp).unwrap() + "\n").as_bytes());
        });
    }
}

use std::io::Read;

fn raft_main(id: String, listen: &str, mut control: Control) {
    use net_mesh::raft::*;
    let die = |e: String| -> ! { eprintln!("{e}"); std::process::exit(2) };
    let id: u64 = id.parse().unwrap_or_else(|_| die(format!("--raft-id: want a number, got {id}")));
    let raft_listen = arg("--raft-listen").unwrap_or_else(|| die("--raft-listen ADDR is required".into()));
    check_bind(&raft_listen).unwrap_or_else(|e| die(e));
    let peers = parse_peers(&arg("--raft-peers").unwrap_or_default()).unwrap_or_else(|e| die(e));
    if !peers.contains_key(&id) {
        die(format!("--raft-peers has no entry for --raft-id {id}"));
    }
    let secret = load_secret(&PathBuf::from(arg("--raft-secret").unwrap_or_else(|| die("--raft-secret FILE is required".into()))))
        .unwrap_or_else(|e| die(e));
    let dir = PathBuf::from(arg("--raft-dir").unwrap_or_else(|| die("--raft-dir DIR is required".into())));
    let init = std::env::args().any(|a| a == "--raft-init").then(|| peers.clone());
    // the Raft store and its snapshot hold the state; a --state file would diverge the replicas
    // with --raft-init, a pre-Raft --state file becomes the cluster's first log entry (Cmd::Seed)
    control.state_path = None;
    let st = std::mem::take(&mut control.state);
    let seed = (init.is_some() && !st.nodes.is_empty()).then_some(st);
    // --raft-heartbeat-ms N --raft-election-ms MIN-MAX; default Timing::wan() (500, 1500-3000), see raft::Timing
    let mut timing = Timing::wan();
    if let Some(h) = arg("--raft-heartbeat-ms") {
        timing.heartbeat = h.parse().unwrap_or_else(|_| die(format!("--raft-heartbeat-ms: want ms, got {h}")));
    }
    if let Some(e) = arg("--raft-election-ms") {
        let (a, b) = e.split_once('-').unwrap_or_else(|| die(format!("--raft-election-ms: want MIN-MAX, got {e}")));
        timing.election_min = a.parse().unwrap_or_else(|_| die(format!("--raft-election-ms: bad min {a}")));
        timing.election_max = b.parse().unwrap_or_else(|_| die(format!("--raft-election-ms: bad max {b}")));
    }
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| die(e.to_string()));
    rt.block_on(async move {
        let rl = tokio::net::TcpListener::bind(&raft_listen).await.unwrap_or_else(|e| die(format!("{raft_listen}: {e}")));
        let cl = tokio::net::TcpListener::bind(listen).await.unwrap_or_else(|e| die(format!("{listen}: {e}")));
        let n = control.admitted.len();
        let r = Replica::start(Opts { id, secret, dir: Some(dir), init, seed, timing, fast_elect: !std::env::args().any(|a| a == "--raft-no-fast-elect") }, control, rl, cl).await.unwrap_or_else(|e| die(e));
        eprintln!("netmesh-control raft replica {id} on {listen}, raft {raft_listen}, {} peers ({n} admitted)", peers.len());
        let _ = tokio::signal::ctrl_c().await;
        r.stop().await;
    });
}

/// `<iam> verify --token HEX --requester NODE --action ACTION --use-roots --fail-closed --json` against this node's
/// accepted roots, fail-closed: exit 0 and (when it prints JSON) an affirmative verdict. Any error or doubt is a refusal.
fn cap_ok(iam: &str, data_dir: Option<&str>, action: &str, cap: &str, node: &str) -> bool {
    if cap.is_empty() || !cap.chars().all(|c| c.is_ascii_hexdigit()) || node.len() != 64 {
        return false;
    }
    let mut c = std::process::Command::new(iam);
    c.args(["verify", "--token", cap, "--requester", node, "--action", action, "--use-roots", "--fail-closed", "--json"]);
    if let Some(d) = data_dir { c.args(["--data-dir", d]); }
    let Ok(out) = c.stdin(std::process::Stdio::null()).output() else { return false };
    if !out.status.success() { return false; }
    let text = String::from_utf8_lossy(&out.stdout);
    match serde_json::from_str::<serde_json::Value>(text.trim()) {
        Ok(v) => ["authorized", "allowed", "ok", "granted"].iter().find_map(|k| v.get(*k)).map_or(true, |b| b.as_bool() == Some(true)),
        Err(_) => text.trim().is_empty(),
    }
}
