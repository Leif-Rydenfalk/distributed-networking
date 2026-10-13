//! netmesh-leg: the relay leg (WireGuard over one TLS/WebSocket stream). See src/leg.rs.
//!
//!   netmesh-leg server --listen 127.0.0.1:7742 --admitted admitted.json [--wg 127.0.0.1:51877] [--udp-in PRIVATE_IP:51879]
//!                      [--udp-door LAN_IP:51880 [--natpmp GW_IP] [--stun HOST:PORT]] [--no-hedge]
//!   netmesh-leg client --url wss://relay.example.com/v1/leg [--key PATH] [--listen 127.0.0.1:51878] [--wg 127.0.0.1:51877]
//!                      [--peer <wg pubkey b64> --udp-endpoint HOST:PORT [--uapi auto|SOCK | --wg-iface IF]
//!                       [--mode auto|leg|udp] [--loss-max 5]] [--up-udp HOST:51879]
//!                       [--alt-urls URL,URL] [--dead-after SECS]   (more relays, failover on close/refuse/silence)
//!                       [--door]   (send up the punched public door the server announces, before --up-udp)
//!
//! --udp-in / --up-udp: split mode (src/leg.rs header): the client sends up plain UDP, the leg carries only the downlink.
//! --udp-door: the same split ingress on its own socket at a private LAN address, for the router's port-forward
//! Firewall it to the one port (nftables or equivalent). Closing it = drop the flag.
//! --natpmp / --stun (src/punch.rs): the door behind a CGNAT. The server leases the door port on the home router
//! by NAT-PMP (120 s, renewed every 40 s, removed on SIGTERM/SIGINT), learns its public address by STUN from the door
//! socket, announces it to each client and punches toward the client's IP. Downlink datagrams go over the leg and,
//! hedged, over each node's bound UDP source; WireGuard drops the second copy. --no-hedge turns the UDP copy off.
//! The admitted file is re-read every 5 s; a node taken off is cut at once (leg closed, beacon key and udp source gone).
//!
//! With --peer the client also picks that peer's WireGuard endpoint: the leg (its --listen address) while the leg is
//! up and the UDP path loses more than --loss-max percent of 20 pings, the UDP endpoint again once loss is under 1 %
//! twice in a row or the leg is down. Checked every 60 s.

use net_mesh::leg::*;
use net_mesh::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

fn args() -> Vec<String> { std::env::args().collect() }
fn arg(name: &str) -> Option<String> {
    let a = args();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}
fn die(e: impl std::fmt::Display) -> ! { eprintln!("netmesh-leg: {e}"); std::process::exit(2) }
fn addr(name: &str, def: &str) -> SocketAddr {
    arg(name).unwrap_or_else(|| def.into()).parse().unwrap_or_else(|e| die(format!("{name}: {e}")))
}

#[tokio::main]
async fn main() {
    match args().get(1).map(String::as_str) {
        Some("server") => {
            let listen = addr("--listen", "127.0.0.1:7742");
            closed_by_default(&listen).unwrap_or_else(|e| die(e));
            let admitted = load_admitted(&PathBuf::from(arg("--admitted").unwrap_or_else(|| die("--admitted FILE"))))
                .unwrap_or_else(|e| die(e));
            let l = tokio::net::TcpListener::bind(listen).await.unwrap_or_else(|e| die(format!("{listen}: {e}")));
            eprintln!("leg server on {listen}, {} admitted", admitted.len());
            let wg = addr("--wg", "127.0.0.1:51877");
            let srv = if arg("--udp-in").is_some() || arg("--udp-door").is_some() { Server::with_udp_in(admitted, wg) } else { Server::new(admitted, wg) };
            if let Some(u) = arg("--udp-in") {
                let u: SocketAddr = u.parse().unwrap_or_else(|e| die(format!("--udp-in: {e}")));
                closed_by_default(&u).unwrap_or_else(|e| die(e));
                let sock = tokio::net::UdpSocket::bind(u).await.unwrap_or_else(|e| die(format!("{u}: {e}")));
                eprintln!("leg server: split mode, udp up on {u}");
                tokio::spawn(srv.clone().serve_udp(sock));
            }
            if let Some(u) = arg("--udp-door") {
                let u: SocketAddr = u.parse().unwrap_or_else(|e| die(format!("--udp-door: {e}")));
                door_addr_ok(&u).unwrap_or_else(|e| die(e));
                let sock = tokio::net::UdpSocket::bind(u).await.unwrap_or_else(|e| die(format!("{u}: {e}")));
                let gw: Option<std::net::Ipv4Addr> = arg("--natpmp").map(|g| g.parse().unwrap_or_else(|e| die(format!("--natpmp: {e}"))));
                eprintln!("leg server: public udp door on {u} (nat-pmp {gw:?}, stun {:?})", arg("--stun"));
                tokio::spawn(srv.clone().serve_door(sock, gw, arg("--stun")));
                if let Some(gw) = gw {
                    // release the lease on stop; a crash leaves it to lapse within LEASE_S
                    tokio::spawn(async move {
                        use tokio::signal::unix::{signal, SignalKind};
                        let (mut t, mut i) = (signal(SignalKind::terminate()).unwrap(), signal(SignalKind::interrupt()).unwrap());
                        tokio::select! { _ = t.recv() => {}, _ = i.recv() => {} }
                        let r = net_mesh::punch::natpmp_lease(gw, u.ip(), u.port(), 0).await;
                        eprintln!("leg server: stopping, nat-pmp lease released: {r:?}");
                        std::process::exit(0);
                    });
                }
            }
            if args().iter().any(|a| a == "--no-hedge") { srv.hedge_down.store(false, std::sync::atomic::Ordering::Relaxed); }
            let (s2, path) = (srv.clone(), PathBuf::from(arg("--admitted").unwrap()));
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    // a file that fails to read keeps the old list: a half-written file must not admit or cut anyone
                    let Ok(new) = load_admitted(&path) else { continue };
                    for n in s2.set_admitted(new).await {
                        eprintln!("leg server: {} no longer admitted, cut", &n[..12.min(n.len())]);
                    }
                }
            });
            srv.serve(l).await;
        }
        Some("client") => {
            let key = load_node_key(&arg("--key").map(PathBuf::from).unwrap_or_else(default_node_key)).unwrap_or_else(|e| die(e));
            let cfg = ClientCfg {
                url: arg("--url").unwrap_or_else(|| die("--url wss://HOST/v1/leg")),
                listen: addr("--listen", "127.0.0.1:51878"),
                wg: addr("--wg", "127.0.0.1:51877"),
                key,
                door: args().iter().any(|a| a == "--door"),
                up_udp: arg("--up-udp").map(|u| u.parse().unwrap_or_else(|e| die(format!("--up-udp: {e}")))),
                alt_urls: arg("--alt-urls").map(|v| v.split(',').filter(|x| !x.is_empty()).map(String::from).collect()).unwrap_or_default(),
                dead_after: arg("--dead-after").map(|v| Duration::from_secs_f64(v.parse().unwrap_or_else(|e| die(format!("--dead-after: {e}"))))).unwrap_or(DEAD_AFTER),
            };
            closed_by_default(&cfg.listen).unwrap_or_else(|e| die(e));
            let (up_tx, up_rx) = tokio::sync::watch::channel(false);
            if let Some(peer) = arg("--peer") {
                let p = Picker {
                    peer_hex: wg_hex(&peer).unwrap_or_else(|| die("--peer: base64 WireGuard key")),
                    udp: arg("--udp-endpoint").unwrap_or_else(|| die("--udp-endpoint HOST:PORT")),
                    leg: cfg.listen.to_string(),
                    uapi: arg("--uapi"),
                    iface: arg("--wg-iface"),
                    mode: arg("--mode").unwrap_or_else(|| "auto".into()),
                    loss_max: arg("--loss-max").and_then(|x| x.parse().ok()).unwrap_or(5.0),
                };
                tokio::spawn(p.run(up_rx));
            }
            client_run(cfg, up_tx).await;
        }
        Some("probe") => probe().await,
        Some("probe-id") => println!("{}", node_id(&load_node_key(&PathBuf::from(arg("--key").unwrap_or_else(|| die("--key FILE")))).unwrap_or_else(|e| die(e)))),
        _ => { eprintln!("usage: netmesh-leg server|client|probe (see source header)"); std::process::exit(2) }
    }
}

/// `netmesh-leg probe --url ws://127.0.0.1:7742/v1/leg --key K`: pass the hello door, print the beacon key the
/// server hands out (`udp2 <tid> <key> <node>`), then `closed <why>` when the server ends the leg. For a door
/// stranger test: a positive control and the revoked-node case. Never forwards a datagram.
async fn probe() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let key = load_node_key(&arg("--key").map(PathBuf::from).unwrap_or_else(default_node_key)).unwrap_or_else(|e| die(e));
    let url = arg("--url").unwrap_or_else(|| die("--url ws://127.0.0.1:7742/v1/leg"));
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap_or_else(|e| die(format!("{url}: {e}")));
    let Some(Ok(Message::Text(ch))) = ws.next().await else { die("no challenge") };
    let n = ch.rsplit(' ').next().unwrap_or("").to_string();
    let h = Hello::signed(&key, &n, now());
    ws.send(Message::Text(serde_json::to_string(&h).unwrap())).await.unwrap_or_else(|e| die(e));
    let why = loop {
        match tokio::time::timeout(Duration::from_secs(120), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) if t.starts_with("udp2 ") => {
                // stranger tests split `udp2 <tid> <key> <node>`; the door= token goes on its own line
                let words: Vec<&str> = t.split_whitespace().collect();
                println!("{} {}", words.iter().filter(|w| !w.starts_with("door=")).cloned().collect::<Vec<_>>().join(" "), h.node);
                if let Some(d) = words.iter().find(|w| w.starts_with("door=")) { eprintln!("{d}"); }
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
            Ok(Some(Ok(Message::Text(t)))) if t.starts_with("refused") => break t.to_string(),
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break "eof".into(),
            Ok(Some(Err(e))) => break format!("ws: {e}"),
            Err(_) => { let _ = ws.send(Message::Ping(vec![])).await; }
            _ => {}
        }
    };
    println!("closed {why}");
}

fn wg_hex(b64: &str) -> Option<String> {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    (b.len() == 32).then(|| hex(&b))
}

struct Picker {
    peer_hex: String,
    udp: String,
    leg: String,
    uapi: Option<String>,
    iface: Option<String>,
    mode: String,
    loss_max: f64,
}

impl Picker {
    async fn run(self, mut up: tokio::sync::watch::Receiver<bool>) {
        let mut cur = String::new();
        let mut good = 0;
        loop {
            let leg_up = *up.borrow();
            let host = self.udp.rsplit_once(':').map(|x| x.0).unwrap_or(&self.udp).to_string();
            let loss = if self.mode == "auto" { ping_loss(&host).await } else { None };
            let want = match (self.mode.as_str(), leg_up) {
                ("leg", true) => &self.leg,
                ("udp", _) | (_, false) => &self.udp,
                _ => match loss {
                    Some(l) if l > self.loss_max => { good = 0; &self.leg }
                    Some(l) if l < 1.0 => { good += 1; if good >= 2 || cur.is_empty() { &self.udp } else { &cur } }
                    _ => if cur.is_empty() { &self.leg } else { &cur }, // in between or unmeasured: stay
                },
            }
            .clone();
            // set it every round, not only on a change: a restarted boringtun comes back with the default endpoint
            match self.set(&want) {
                Ok(()) if want != cur => { eprintln!("leg pick: endpoint {want} (udp loss {loss:?} %, leg up {leg_up})"); cur = want; }
                Ok(()) => {}
                Err(e) => eprintln!("leg pick: {e}"),
            }
            // re-check at once when the leg goes up or down, else every 60 s
            let _ = tokio::time::timeout(Duration::from_secs(60), up.changed()).await;
        }
    }

    fn set(&self, ep: &str) -> Result<(), String> {
        if let Some(i) = &self.iface {
            use base64::Engine;
            let b = unhex(&self.peer_hex).unwrap();
            let k = base64::engine::general_purpose::STANDARD.encode(b);
            let o = std::process::Command::new("wg").args(["set", i, "peer", &k, "endpoint", ep]).output().map_err(|e| e.to_string())?;
            return if o.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&o.stderr).into()) };
        }
        let sock = match self.uapi.as_deref() {
            Some(s) if s != "auto" => s.to_string(),
            _ => std::fs::read_dir("/var/run/wireguard").map_err(|e| e.to_string())?
                .filter_map(|e| e.ok()).map(|e| e.path().display().to_string()).find(|p| p.ends_with(".sock"))
                .ok_or("no UAPI socket in /var/run/wireguard")?,
        };
        uapi_set_endpoint(&sock, &self.peer_hex, ep)
    }
}

/// percent loss of 20 pings at 0.2 s (root may ping that fast on macOS and Linux)
async fn ping_loss(host: &str) -> Option<f64> {
    let o = tokio::process::Command::new("ping").args(["-c", "20", "-i", "0.2", "-q", host]).output().await.ok()?;
    let s = String::from_utf8_lossy(&o.stdout);
    let w = s.split_whitespace().collect::<Vec<_>>();
    w.windows(2).find(|p| p[0].ends_with('%') && p[1] == "packet")?[0].trim_end_matches('%').parse().ok()
}
