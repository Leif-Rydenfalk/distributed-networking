//! netmesh-path: keep each peer's WireGuard endpoint on the best live path (src/path.rs).
//!
//!   netmesh-path --listen IP:PORT --peers PEERS.json [--wg-key PATH] (--uapi SOCK | --wg-iface IF) [--log FILE.jsonl]
//!                [--every-ms 200] [--dead-ms 500]
//!
//! PEERS.json: [{"name": "peer-a", "wg_public": "<b64>", "candidates": ["192.0.2.10:51878"], "wg_port": 51877,
//!               "fallback": "127.0.0.1:50599"}]
//!
//! --listen binds a private address only (RFC 1918 LAN or cable, loopback, CGNAT 100.64/10 or mesh), never 0.0.0.0:
//! the socket answers only peers whose pair key verifies, so a stranger on the LAN gets silence. Use it for peers
//! reached over a LAN or a cable; a peer reached through the relay leg uses the leg client (`netmesh-leg --peer`), which
//! already chooses between the UDP door and the leg.

use net_mesh::path::*;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

fn args() -> Vec<String> { std::env::args().collect() }
fn arg(name: &str) -> Option<String> {
    let a = args();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}
fn die(e: impl std::fmt::Display) -> ! { eprintln!("netmesh-path: {e}"); std::process::exit(2) }

fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback() || v.is_private() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v) => v.is_loopback(),
    }
}

fn key32(b64: &str) -> Key {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| die(format!("not a 32-byte base64 key: {b64}")))
}

#[derive(serde::Deserialize)]
struct PeerJson {
    name: String,
    wg_public: String,
    candidates: Vec<SocketAddr>,
    #[serde(default = "wg_port")]
    wg_port: u16,
    fallback: SocketAddr,
}
fn wg_port() -> u16 { 51877 }

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listen: SocketAddr = arg("--listen").unwrap_or_else(|| die("--listen IP:PORT")).parse().unwrap_or_else(|e| die(e));
    if !private(listen.ip()) {
        die(format!("refusing to listen on {listen}: private addresses only"));
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let wg_path = arg("--wg-key").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(&home).join(".local/share/net-mesh/wg.key"));
    let my_private = key32(&std::fs::read_to_string(&wg_path).unwrap_or_else(|e| die(format!("{}: {e}", wg_path.display()))));
    let pf = arg("--peers").unwrap_or_else(|| die("--peers PEERS.json"));
    let pj: Vec<PeerJson> = serde_json::from_str(&std::fs::read_to_string(&pf).unwrap_or_else(|e| die(format!("{pf}: {e}"))))
        .unwrap_or_else(|e| die(format!("{pf}: {e}")));
    let peers: Vec<PeerCfg> = pj
        .into_iter()
        .map(|p| PeerCfg { name: p.name, wg_public: key32(&p.wg_public), candidates: p.candidates, wg_port: p.wg_port, fallback: p.fallback })
        .collect();
    let apply: Box<dyn Apply> = match (arg("--uapi"), arg("--wg-iface")) {
        (Some(s), _) => Box::new(Uapi(PathBuf::from(s))),
        (None, Some(i)) => Box::new(WgCli(i)),
        _ => die("--uapi SOCK or --wg-iface IF"),
    };
    let mut tuning = Tuning::default();
    if let Some(ms) = arg("--every-ms").and_then(|v| v.parse().ok()) { tuning.every = Duration::from_millis(ms); }
    if let Some(ms) = arg("--dead-ms").and_then(|v| v.parse().ok()) { tuning.dead_after = Duration::from_millis(ms); }
    let sock = tokio::net::UdpSocket::bind(listen).await.unwrap_or_else(|e| die(format!("{listen}: {e}")));
    let logf = arg("--log");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Switch>();
    tokio::spawn(async move {
        while let Some(s) = rx.recv().await {
            let line = serde_json::json!({"t_ms": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
                "peer": s.peer, "to": s.to.to_string(), "direct": s.direct}).to_string();
            eprintln!("{line}");
            if let Some(f) = &logf {
                use std::io::Write;
                if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(f) {
                    let _ = writeln!(fh, "{line}");
                }
            }
        }
    });
    eprintln!("netmesh-path: {} peers, probing from {listen} every {:?}, dead after {:?}", peers.len(), tuning.every, tuning.dead_after);
    if let Err(e) = run(sock, my_private, peers, tuning, apply, tx).await {
        die(e);
    }
}
