//! netmesh: the net.mesh client.
//!
//!   netmesh id   [--key PATH]                         this node's id (hex ed25519 public key)
//!   netmesh wg   [--wg-key PATH]                      this node's WireGuard public key (created 0600 if missing)
//!   netmesh up   --control HOST:PORT [--endpoint IP:PORT ...] [--port 51877] [--out FILE] [--cap-file GRANT.hex]
//!                                                     register, then print (or write 0600) a wg-quick config
//!   netmesh peers --control HOST:PORT                 the peer list as JSON
//!
//! --control takes one address or a comma-separated list (the Raft replicas). `$HOME/.config/net-mesh/control`, when it
//! exists, adds its comma- or line-separated replicas after them, so a caller with a fixed single address (a root-owned
//! service script) still fails over.

use net_mesh::*;
use std::path::PathBuf;

fn args() -> Vec<String> { std::env::args().collect() }
fn arg(name: &str) -> Option<String> {
    let a = args();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}
fn all(name: &str) -> Vec<String> {
    let a = args();
    a.iter().enumerate().filter(|(_, x)| *x == name).filter_map(|(i, _)| a.get(i + 1).cloned()).collect()
}
fn die(e: impl std::fmt::Display) -> ! { eprintln!("netmesh: {e}"); std::process::exit(1) }

fn main() {
    let cmd = args().get(1).cloned().unwrap_or_default();
    let key = load_node_key(&arg("--key").map(PathBuf::from).unwrap_or_else(default_node_key)).unwrap_or_else(|e| die(e));
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let wg_path = arg("--wg-key").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(&home).join(".local/share/net-mesh/wg.key"));
    match cmd.as_str() {
        "id" => println!("{}", node_id(&key)),
        "wg" => println!("{}", wg_load_or_create(&wg_path).unwrap_or_else(|e| die(e)).1),
        "up" | "peers" => {
            let control = with_replicas(arg("--control").unwrap_or_else(|| die("--control HOST:PORT")));
            let (wg_priv, wg_pub) = wg_load_or_create(&wg_path).unwrap_or_else(|e| die(e));
            let op = if cmd == "up" { "register" } else { "peers" };
            let mut req = Request::signed(&key, op, now(), &wg_pub, all("--endpoint"));
            // --cap-file: a capability grant for the control server's join action, for a node not on its admitted list
            if let Some(f) = arg("--cap-file") {
                req.cap = std::fs::read_to_string(&f).unwrap_or_else(|e| die(format!("{f}: {e}"))).trim().to_string();
            }
            let resp = call(&control, &req).unwrap_or_else(|e| die(e));
            if !resp.ok { die(format!("refused: {}", resp.err)); }
            if cmd == "peers" {
                println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                return;
            }
            let port: u16 = arg("--port").and_then(|p| p.parse().ok()).unwrap_or(51877);
            let conf = wg_quick(&wg_priv, port, &resp);
            match arg("--out") {
                Some(p) => { write_private(&PathBuf::from(&p), &conf).unwrap_or_else(|e| die(e)); eprintln!("{} -> {p} ({} peers)", resp.addr, resp.peers.len()); }
                None => print!("{conf}"),
            }
        }
        _ => { eprintln!("usage: netmesh id|wg|up|peers (see source header)"); std::process::exit(2) }
    }
}

/// --control, then the replicas in $HOME/.config/net-mesh/control that it does not already name
fn with_replicas(control: String) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let extra = std::fs::read_to_string(PathBuf::from(home).join(".config/net-mesh/control")).unwrap_or_default();
    let mut all: Vec<String> = control.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
    for e in extra.split(|c: char| c == ',' || c.is_whitespace()).filter(|x| !x.is_empty() && !x.starts_with('#')) {
        if !all.iter().any(|a| a == e) {
            all.push(e.to_string());
        }
    }
    all.join(",")
}
