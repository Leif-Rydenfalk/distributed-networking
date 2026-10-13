//! net.mesh relay leg. WireGuard datagrams over one long-lived TLS stream.
//!
//! On some long-haul paths UDP loses 10-30 % and is throttled to ~10 KB/s, while TCP/HTTPS on the same path runs at
//! Mbit speeds. So a node behind such a path (the client) carries its WireGuard packets to a well-connected server
//! over a WebSocket inside TLS (CDN edge or reverse proxy -> this server on 127.0.0.1). On the wire it is one HTTPS
//! connection to an ordinary hostname.
//!
//!   client: wireguard --udp--> 127.0.0.1:51878 [leg client] ==wss==> TLS edge / reverse proxy
//!   server: proxy --ws--> 127.0.0.1:7742 [leg server] --udp from 127.0.0.1:<per node>--> kernel wg 127.0.0.1:51877
//!
//! Kernel WireGuard on the server roams the peer's endpoint to the per-node loopback port by itself (WireGuard
//! follows the last authenticated source), so the server's config does not change.
//!
//! Framing: each WebSocket binary message carries one or more datagrams, each `u16 big-endian length || bytes`
//! (batched while a queue is non-empty, up to `BATCH_MAX` bytes).
//!
//! Split (`--udp-in` on the server, `--up-udp` on the client): on asymmetric paths the reverse direction of UDP can be
//! fast (2.2-4.9 MB/s vs 0.18 MB/s up the leg, measured), so the client may send its datagrams up plain UDP to a server address and
//! keep only the downlink on the leg. The server hands each leg connection a key id and a 32-byte key
//! (`udp2 <tid hex> <key hex>` text message); every 10 s the client sends a beacon `0xFE 'N' '2' || tid(8) || seq(8) ||
//! HMAC-SHA256(key, "net.mesh/beacon/v1" || node || seq)[..16]` with a rising seq from its UDP socket. The server binds
//! that source address to the node only on a beacon whose MAC checks and whose seq is above the last one, so a beacon
//! copied off the path and replayed from elsewhere changes nothing. Those datagrams go to WireGuard from the node's same loopback socket, so the server's
//! WireGuard never roams the endpoint away from the leg and its replies keep coming down the stream. Datagrams from
//! an unknown source are dropped.
//!
//! Door: the server sends a 32-byte nonce; the client answers `{node, ts, sig}` with sig = ed25519 by its node key
//! over `net.mesh/leg/v1\n<nonce>\n<node>\n<ts>`. Only nodes on the admitted list pass; anything else is closed
//! before a single datagram is forwarded. The payload is WireGuard-encrypted end to end anyway; the door stops a
//! stranger from using the server as a UDP reflector into the WireGuard port.

use crate::{hex, node_id, now, unhex, MAX_SKEW_S};
use sha2::{Digest, Sha256};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;

pub const LEG_PROTO: &str = "net.mesh/leg/v1";
pub const BATCH_MAX: usize = 32 * 1024;
const QUEUE: usize = 1024;
const IDLE: Duration = Duration::from_secs(60);
const PING_EVERY: Duration = Duration::from_secs(20);

// ---------- framing ----------

pub fn pack(out: &mut Vec<u8>, pkt: &[u8]) {
    out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    out.extend_from_slice(pkt);
}

/// split a batch back into datagrams; a truncated tail is dropped (never panics on hostile input)
pub fn unpack(mut b: &[u8]) -> Vec<&[u8]> {
    let mut v = Vec::new();
    while b.len() >= 2 {
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        if b.len() < 2 + n {
            break;
        }
        v.push(&b[2..2 + n]);
        b = &b[2 + n..];
    }
    v
}

// ---------- the door ----------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hello {
    pub node: String,
    pub ts: u64,
    pub sig: String,
}

fn hello_bytes(nonce: &str, node: &str, ts: u64) -> Vec<u8> {
    format!("{LEG_PROTO}\n{nonce}\n{node}\n{ts}").into_bytes()
}

impl Hello {
    pub fn signed(k: &SigningKey, nonce: &str, ts: u64) -> Hello {
        let node = node_id(k);
        let sig = hex(&k.sign(&hello_bytes(nonce, &node, ts)).to_bytes());
        Hello { node, ts, sig }
    }

    pub fn check(&self, nonce: &str, admitted: &BTreeSet<String>, now: u64) -> Result<(), &'static str> {
        if !admitted.contains(&self.node) {
            return Err("not admitted");
        }
        if self.ts + MAX_SKEW_S < now || self.ts > now + MAX_SKEW_S {
            return Err("timestamp outside window");
        }
        let pk: [u8; 32] = unhex(&self.node).and_then(|v| v.try_into().ok()).ok_or("bad node id")?;
        let sig: [u8; 64] = unhex(&self.sig).and_then(|v| v.try_into().ok()).ok_or("bad signature encoding")?;
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad node id")?;
        vk.verify(&hello_bytes(nonce, &self.node, self.ts), &Signature::from_bytes(&sig)).map_err(|_| "bad signature")
    }
}

pub fn nonce() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("getrandom");
    hex(&b)
}

/// refuse any listen address that is not loopback, a tailnet (100.64/10) or a mesh (10.77/16) address
pub fn closed_by_default(addr: &SocketAddr) -> Result<(), String> {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            let o = ip.octets();
            if ip.is_loopback() || (o[0] == 100 && (64..128).contains(&o[1])) || (o[0] == 10 && o[1] == 77) {
                Ok(())
            } else {
                Err(format!("refusing to listen on {addr}: loopback, tailnet or mesh addresses only"))
            }
        }
        std::net::IpAddr::V6(ip) if ip.is_loopback() => Ok(()),
        _ => Err(format!("refusing to listen on {addr}: loopback, tailnet or mesh addresses only")),
    }
}

/// the public UDP door binds a private LAN address only (RFC 1918), never 0.0.0.0 or a public one: the router's
/// port-forward is the one way in, and a host firewall (nftables) should rate-limit it
pub fn door_addr_ok(addr: &SocketAddr) -> Result<(), String> {
    match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_private() && !(ip.octets()[0] == 10 && ip.octets()[1] == 77) => Ok(()),
        _ => Err(format!("refusing the udp door on {addr}: a private LAN address only (the router forwards to it)")),
    }
}

// ---------- server ----------

/// one per admitted node, kept across reconnects so kernel WireGuard sees the same loopback endpoint
pub const BEACON: [u8; 3] = [0xFE, b'N', b'2'];
pub const BEACON_LEN: usize = 3 + 8 + 8 + 16;
/// a datagram larger than this is dropped before anything looks at it (WireGuard over a 1500 MTU never needs more)
pub const DATAGRAM_MAX: usize = 1500;
const BEACON_EVERY: Duration = Duration::from_secs(2);
/// split mode: no echo for this long and the client sends up the leg again (until echoes return)
const UDP_STALE: Duration = Duration::from_secs(7);

fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let (mut ip, mut op) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..32 { ip[i] ^= key[i]; op[i] ^= key[i]; }
    let inner = Sha256::new().chain_update(ip).chain_update(msg).finalize();
    Sha256::new().chain_update(op).chain_update(inner).finalize().into()
}

fn beacon_mac(key: &[u8; 32], node: &str, seq: u64) -> [u8; 16] {
    let mut m = b"net.mesh/beacon/v1".to_vec();
    m.extend_from_slice(node.as_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    hmac_sha256(key, &m)[..16].try_into().unwrap()
}

/// `0xFE 'N' '2' || tid || seq || mac`
pub fn beacon(tid: &[u8; 8], key: &[u8; 32], node: &str, seq: u64) -> Vec<u8> {
    let mut b = BEACON.to_vec();
    b.extend_from_slice(tid);
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&beacon_mac(key, node, seq));
    b
}

/// (tid, seq, mac) of a datagram shaped like a beacon
pub fn beacon_parts(p: &[u8]) -> Option<([u8; 8], u64, [u8; 16])> {
    (p.len() == BEACON_LEN && p[..3] == BEACON).then(|| {
        (p[3..11].try_into().unwrap(), u64::from_be_bytes(p[11..19].try_into().unwrap()), p[19..35].try_into().unwrap())
    })
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// split mode: one live beacon key per node, issued per leg connection
struct Tok {
    node: String,
    key: [u8; 32],
    seq: u64,
    /// bit i set = beacon seq-i already seen. A client beacons on two paths (door and a private network), which can arrive out
    /// of order, so a seq is fresh when above the highest one or inside the last 64 and not yet seen (the WireGuard
    /// replay-window idea). A beacon copied off a path and replayed is always a seq already seen.
    win: u64,
}

impl Tok {
    /// accept `seq` once; false for a replay or one older than the 64-wide window
    fn fresh(&mut self, seq: u64) -> bool {
        if seq > self.seq {
            let shift = seq - self.seq;
            self.win = if shift >= 64 { 0 } else { self.win << shift };
            self.win |= 1;
            self.seq = seq;
            return true;
        }
        let back = self.seq - seq;
        if back >= 64 || self.win & (1 << back) != 0 { return false; }
        self.win |= 1 << back;
        true
    }
}

/// the replay window alone, for tests
pub fn beacon_window_accepts(seqs: &[u64]) -> Vec<bool> {
    let mut t = Tok { node: String::new(), key: [0; 32], seq: 0, win: 0 };
    seqs.iter().map(|&s| s > 0 && t.fresh(s)).collect()
}

/// a node may bind this many UDP sources at once (door + private network); the least recently beaconed one goes first
pub const SOURCES_PER_NODE: usize = 2;

struct Pipe {
    udp: Arc<UdpSocket>,
    tx: Mutex<Option<(u64, mpsc::Sender<Vec<u8>>)>>,
    /// hedged downlink: the UDP socket and bound source this node beacons from. Every downlink datagram also
    /// goes there; WireGuard's replay window drops whichever copy comes second, so latency = min(udp, leg).
    down: std::sync::Mutex<Vec<(Arc<UdpSocket>, SocketAddr, std::time::Instant)>>,
}

pub struct Server {
    /// replaced by `set_admitted`; a node taken off is cut at once (leg, beacon key, udp source)
    admitted: std::sync::RwLock<BTreeSet<String>>,
    revoked: tokio::sync::Notify,
    pub wg: SocketAddr,
    pipes: Mutex<HashMap<String, Arc<Pipe>>>,
    conn_seq: std::sync::atomic::AtomicU64,
    /// split mode: key id -> beacon key (issued per leg connection), UDP source -> node (learned from beacons)
    tokens: Mutex<HashMap<[u8; 8], Tok>>,
    sources: Mutex<HashMap<SocketAddr, String>>,
    pub udp_in: bool,
    /// door: the public door socket, its address as the CGNAT shows it (STUN), the pending STUN transaction
    door: std::sync::Mutex<Option<Arc<UdpSocket>>>,
    door_public: std::sync::Mutex<Option<SocketAddr>>,
    stun_tid: std::sync::Mutex<[u8; 12]>,
    /// send downlink datagrams over the bound UDP source as well as the leg (default on)
    pub hedge_down: std::sync::atomic::AtomicBool,
    /// browser tabs: set once with `set_tabs`; without it a tab hello is refused
    tabs: std::sync::OnceLock<Arc<Tabs>>,
}

impl Server {
    pub fn new(admitted: BTreeSet<String>, wg: SocketAddr) -> Arc<Server> {
        Arc::new(Server { admitted: admitted.into(), revoked: tokio::sync::Notify::new(), wg, pipes: Mutex::new(HashMap::new()), conn_seq: 0.into(),
                          tokens: Mutex::new(HashMap::new()), sources: Mutex::new(HashMap::new()), udp_in: false,
                          door: None.into(), door_public: None.into(), stun_tid: crate::punch::tid().into(), hedge_down: true.into(),
                          tabs: std::sync::OnceLock::new() })
    }

    pub fn with_udp_in(admitted: BTreeSet<String>, wg: SocketAddr) -> Arc<Server> {
        let mut s = Arc::try_unwrap(Server::new(admitted, wg)).ok().unwrap();
        s.udp_in = true;
        Arc::new(s)
    }

    /// open the tab door (once; a second call is ignored)
    pub fn set_tabs(&self, t: Arc<Tabs>) { let _ = self.tabs.set(t); }

    pub fn is_admitted(&self, node: &str) -> bool { self.admitted.read().unwrap().contains(node) }
    pub fn admitted_len(&self) -> usize { self.admitted.read().unwrap().len() }

    /// replace the admitted list. A node no longer on it loses its beacon key and udp source here, and its leg is
    /// closed by its own connection task on the notify. Returns the nodes cut.
    pub async fn set_admitted(&self, new: BTreeSet<String>) -> Vec<String> {
        let gone: Vec<String> = {
            let mut a = self.admitted.write().unwrap();
            let gone = a.difference(&new).cloned().collect();
            *a = new;
            gone
        };
        if !gone.is_empty() {
            self.tokens.lock().await.retain(|_, t| !gone.contains(&t.node));
            self.sources.lock().await.retain(|_, n| !gone.contains(n));
            for n in &gone {
                if let Some(p) = self.pipes.lock().await.get(n) {
                    *p.tx.lock().await = None;
                    p.down.lock().unwrap().clear();
                }
            }
            self.revoked.notify_waiters();
        }
        gone
    }

    /// split mode: how many nodes currently send up plain UDP
    pub async fn udp_sources(&self) -> usize { self.sources.lock().await.len() }

    /// split mode: datagrams sent up plain UDP. A beacon binds its source to the node its token names; anything else
    /// from a bound source goes to WireGuard through that node's pipe; the rest is dropped.
    pub async fn serve_udp(self: Arc<Self>, sock: UdpSocket) { self.serve_udp_arc(Arc::new(sock)).await }

    async fn serve_udp_arc(self: Arc<Self>, sock: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else { continue };
            if n > DATAGRAM_MAX { continue; } // a host firewall drops these first on the public door; this is the second wall
            let pkt = &buf[..n];
            if crate::punch::is_stun(pkt) {
                // only the answer to our own pending request counts; any other STUN-shaped packet is dropped unanswered
                let tid = *self.stun_tid.lock().unwrap();
                if let Some(a) = crate::punch::stun_parse(pkt, &tid) {
                    let mut d = self.door_public.lock().unwrap();
                    if *d != Some(a) { eprintln!("leg: door is public at {a} (stun {src})"); }
                    *d = Some(a);
                }
                continue;
            }
            if let Some((tid, seq, mac)) = beacon_parts(pkt) {
                let node = {
                    let mut t = self.tokens.lock().await;
                    match t.get_mut(&tid) {
                        // MAC first, so a forged beacon never moves the window
                        Some(k) if ct_eq(&beacon_mac(&k.key, &k.node, seq), &mac) => k.fresh(seq).then(|| k.node.clone()),
                        _ => None, // unknown key id, bad MAC, or a seq already seen: no rebind, no echo
                    }
                };
                if let Some(node) = node {
                    let Ok(p) = self.pipe(&node).await else { continue };
                    let mut m = self.sources.lock().await;
                    let evict = {
                        let mut d = p.down.lock().unwrap();
                        let now = std::time::Instant::now();
                        if let Some(e) = d.iter_mut().find(|e| e.1 == src) {
                            e.2 = now;
                            e.0 = sock.clone();
                            None
                        } else {
                            d.push((sock.clone(), src, now));
                            d.sort_by_key(|e| std::cmp::Reverse(e.2));
                            // a NAT rebind or a third path replaces the least recently beaconed source
                            let gone: Vec<SocketAddr> = { let keep = SOURCES_PER_NODE.min(d.len()); d.drain(keep..) }.map(|e| e.1).collect();
                            Some(gone)
                        }
                    };
                    if let Some(gone) = evict {
                        for g in gone { m.remove(&g); }
                        // a source whose pipe entry was lost must not linger either
                        let keep: Vec<SocketAddr> = p.down.lock().unwrap().iter().map(|e| e.1).collect();
                        m.retain(|a, v| *v != node || keep.contains(a));
                        eprintln!("leg: {} sends up udp from {src}", &node[..12]);
                        m.insert(src, node.clone());
                    }
                    drop(m);
                    // echo it: the client's proof that the up path works; it falls back to the leg when echoes stop.
                    // Only a fresh valid beacon is echoed, same size, so the door cannot be used to reflect traffic.
                    let _ = sock.send_to(pkt, src).await;
                }
                continue;
            }
            let node = self.sources.lock().await.get(&src).cloned();
            if let Some(node) = node {
                if let Ok(p) = self.pipe(&node).await {
                    let _ = p.udp.send(pkt).await;
                }
            }
        }
    }

    /// the loopback port the WireGuard side sees for this node, once it has connected
    pub async fn pipe_port(&self, node: &str) -> Option<u16> {
        self.pipes.lock().await.get(node).and_then(|p| p.udp.local_addr().ok()).map(|a| a.port())
    }

    async fn pipe(self: &Arc<Self>, node: &str) -> std::io::Result<Arc<Pipe>> {
        let mut m = self.pipes.lock().await;
        if let Some(p) = m.get(node) {
            return Ok(p.clone());
        }
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        udp.connect(self.wg).await?;
        let p = Arc::new(Pipe { udp: udp.clone(), tx: Mutex::new(None), down: Vec::new().into() });
        let pc = p.clone();
        let me = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let n = match pc.udp.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => { tokio::time::sleep(Duration::from_millis(50)).await; continue; } // ICMP refused etc.
                };
                if me.hedge_down.load(std::sync::atomic::Ordering::Relaxed) {
                    let down = pc.down.lock().unwrap().clone();
                    for (s, a, t) in down {
                        if t.elapsed() < UDP_STALE { let _ = s.try_send_to(&buf[..n], a); }
                    }
                }
                if let Some((_, tx)) = &*pc.tx.lock().await {
                    let _ = tx.try_send(buf[..n].to_vec()); // full queue = drop, like a congested UDP path
                }
            }
        });
        m.insert(node.to_string(), p.clone());
        Ok(p)
    }

    /// the door's public address as STUN last saw it
    pub fn door_public(&self) -> Option<SocketAddr> { *self.door_public.lock().unwrap() }

    /// open the CGNAT's address filter toward an admitted client: a few `PUNCH` packets from the door socket to
    /// the client's IP over 5 s, stopping once that node's beacon has bound a source. Port 9 (discard): the filter
    /// keys on the address only (measured), and the client's own NAT drops it.
    fn punch(self: &Arc<Self>, ip: Option<std::net::IpAddr>, node: &str) {
        let (Some(ip), Some(door)) = (ip, self.door.lock().unwrap().clone()) else { return };
        let (me, node) = (self.clone(), node.to_string());
        tokio::spawn(async move {
            for _ in 0..20 {
                if me.sources.lock().await.values().any(|n| *n == node) { break; }
                let _ = door.send_to(crate::punch::PUNCH, SocketAddr::new(ip, 9)).await;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }

    /// the public door. Serves it like `serve_udp`, and every `RENEW_EVERY` renews the NAT-PMP lease on `gw`
    /// (short lifetime, so a dead server's door lapses by itself) and asks `stun` for the public address.
    pub async fn serve_door(self: Arc<Self>, sock: UdpSocket, gw: Option<std::net::Ipv4Addr>, stun: Option<String>) {
        let local = sock.local_addr().expect("door addr");
        let sock = Arc::new(sock);
        *self.door.lock().unwrap() = Some(sock.clone());
        let me = self.clone();
        let s2 = sock.clone();
        tokio::spawn(async move {
            loop {
                if let Some(gw) = gw {
                    match crate::punch::natpmp_lease(gw, local.ip(), local.port(), crate::punch::LEASE_S).await {
                        Ok((ext, life)) => eprintln!("leg: nat-pmp lease udp {} -> {ext} for {life} s", local.port()),
                        Err(e) => eprintln!("leg: nat-pmp: {e}"),
                    }
                }
                if let Some(h) = &stun {
                    if let Some(to) = crate::punch::resolve4(h).await {
                        let t = crate::punch::tid();
                        *me.stun_tid.lock().unwrap() = t;
                        let _ = s2.send_to(&crate::punch::stun_request(&t), to).await;
                    }
                }
                tokio::time::sleep(crate::punch::RENEW_EVERY).await;
            }
        });
        self.serve_udp_arc(sock).await
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { continue };
            let s = self.clone();
            tokio::spawn(async move {
                if let Err(e) = s.conn(tcp).await {
                    eprintln!("leg: {e}");
                }
            });
        }
    }

    async fn conn(self: Arc<Self>, tcp: tokio::net::TcpStream) -> Result<(), String> {
        let _ = tcp.set_nodelay(true);
        // cloudflared puts the client's public IP in Cf-Connecting-Ip; the door punches toward it
        let mut peer_ip: Option<std::net::IpAddr> = None;
        let cb = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                  resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            peer_ip = req.headers().get("cf-connecting-ip").and_then(|v| v.to_str().ok()).and_then(crate::punch::client_ip);
            Ok(resp)
        };
        let mut ws = tokio_tungstenite::accept_hdr_async(tcp, cb).await.map_err(|e| format!("ws accept: {e}"))?;
        let n = nonce();
        ws.send(Message::Text(format!("{LEG_PROTO} {n}"))).await.map_err(|e| e.to_string())?;
        let first = match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => Some(t),
            _ => None,
        };
        // a browser tab's hello names its proto; a node's hello has no such field
        if let Some(th) = first.as_deref().and_then(|t| serde_json::from_str::<TabHello>(t).ok()).filter(|h| h.proto == TAB_PROTO) {
            return self.tab_conn(ws, &n, th).await;
        }
        let hello = match first {
            Some(t) => serde_json::from_str::<Hello>(&t).map_err(|_| "bad hello".to_string()),
            None => Err("no hello".to_string()),
        };
        let admitted = self.admitted.read().unwrap().clone();
        let hello = match hello.and_then(|h| h.check(&n, &admitted, now()).map(|_| h).map_err(String::from)) {
            Ok(h) => h,
            Err(e) => {
                let _ = ws.send(Message::Text(format!("refused: {e}"))).await;
                let _ = ws.close(None).await;
                return Err(format!("refused: {e}"));
            }
        };
        ws.send(Message::Text("ok".into())).await.map_err(|e| e.to_string())?;
        if self.udp_in {
            let (mut tid, mut key) = ([0u8; 8], [0u8; 32]);
            getrandom::getrandom(&mut tid).expect("getrandom");
            getrandom::getrandom(&mut key).expect("getrandom");
            let mut t = self.tokens.lock().await;
            t.retain(|_, k| k.node != hello.node); // a node holds one live beacon key
            t.insert(tid, Tok { node: hello.node.clone(), key, seq: 0, win: 0 });
            drop(t);
            let door = *self.door_public.lock().unwrap();
            let line = match door {
                Some(d) => format!("udp2 {} {} door={d}", hex(&tid), hex(&key)),
                None => format!("udp2 {} {}", hex(&tid), hex(&key)),
            };
            ws.send(Message::Text(line)).await.map_err(|e| e.to_string())?;
            self.punch(peer_ip, &hello.node);
        }
        let pipe = self.pipe(&hello.node).await.map_err(|e| e.to_string())?;
        let id = self.conn_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(QUEUE);
        *pipe.tx.lock().await = Some((id, tx)); // a newer connection from the same node takes over
        eprintln!("leg: {} connected (loopback port {})", &hello.node[..12], pipe.udp.local_addr().map(|a| a.port()).unwrap_or(0));
        let (sink, mut stream) = ws.split();
        let writer = tokio::spawn(write_loop(sink, rx, PING_EVERY));
        loop {
            if !self.is_admitted(&hello.node) { eprintln!("leg: {} revoked, closing", &hello.node[..12]); break; }
            let next = tokio::select! {
                r = tokio::time::timeout(IDLE, stream.next()) => r,
                _ = self.revoked.notified() => continue,
            };
            match next {
                Ok(Some(Ok(Message::Binary(b)))) => {
                    for p in unpack(&b) {
                        let _ = pipe.udp.send(p).await;
                    }
                }
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) | Err(_) => break,
                Ok(Some(Ok(_))) => {} // ping/pong/text
            }
        }
        writer.abort();
        if !self.is_admitted(&hello.node) { self.tokens.lock().await.retain(|_, k| k.node != hello.node); }
        let mut cur = pipe.tx.lock().await;
        if cur.as_ref().is_some_and(|(i, _)| *i == id) {
            *cur = None;
        }
        eprintln!("leg: {} gone", &hello.node[..12]);
        Ok(())
    }
}

/// batch datagrams from `rx` into binary messages; ping on quiet so Cloudflare (100 s idle cut) keeps the stream
async fn write_loop<S>(mut sink: S, mut rx: mpsc::Receiver<Vec<u8>>, ping: Duration)
where
    S: futures_util::Sink<Message> + Unpin,
{
    loop {
        let first = match tokio::time::timeout(ping, rx.recv()).await {
            Ok(Some(p)) => p,
            Ok(None) => return,
            Err(_) => {
                if sink.send(Message::Ping(vec![])).await.is_err() { return; }
                continue;
            }
        };
        let mut b = Vec::with_capacity(first.len() + 2);
        pack(&mut b, &first);
        while b.len() < BATCH_MAX {
            match rx.try_recv() {
                Ok(p) => pack(&mut b, &p),
                Err(_) => break,
            }
        }
        if sink.send(Message::Binary(b)).await.is_err() {
            return;
        }
    }
}

// ---------- client ----------

pub struct ClientCfg {
    pub url: String,
    pub listen: SocketAddr, // 127.0.0.1:51878: WireGuard sends the server peer's packets here
    pub wg: SocketAddr,     // 127.0.0.1:51877: where packets from the server are delivered
    pub key: SigningKey,
    /// split mode: send datagrams up plain UDP to this server address (its `--udp-in`), keep the downlink on the leg
    pub up_udp: Option<SocketAddr>,
    /// use the punched public door the server announces (`udp2 ... door=IP:PORT`) before `up_udp`
    pub door: bool,
    /// more relays to the same server: a leg that closes, is refused or goes quiet moves to the next one at once
    pub alt_urls: Vec<String>,
    /// a leg with nothing received for this long is dead; the client pings every third of it (default 60 s)
    pub dead_after: Duration,
}

pub const DEAD_AFTER: Duration = IDLE;

/// one connection attempt: handshake, then pump until the stream dies. Returns why it ended.
pub async fn client_once(cfg: &ClientCfg, url: &str, udp: &Arc<UdpSocket>, up: &tokio::sync::watch::Sender<bool>) -> String {
    // disable_nagle = true: plain connect_async leaves Nagle on, and Nagle plus delayed ACKs held small WireGuard
    // packets back by up to ~200 ms (idle rtt 445-750 ms against a 253-307 ms floor, measured)
    let (mut ws, _) = match tokio_tungstenite::connect_async_with_config(url, None, true).await {
        Ok(x) => x,
        Err(e) => return format!("connect: {e}"),
    };
    let n = match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) if t.starts_with(LEG_PROTO) => t[LEG_PROTO.len()..].trim().to_string(),
        _ => return "no challenge".into(),
    };
    let h = Hello::signed(&cfg.key, &n, now());
    if ws.send(Message::Text(serde_json::to_string(&h).unwrap())).await.is_err() {
        return "send hello".into();
    }
    match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) if t == "ok" => {}
        Ok(Some(Ok(Message::Text(t)))) => return t,
        _ => return "no answer to hello".into(),
    }
    let _ = up.send(true);
    let (tx, rx) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (sink, mut stream) = ws.split();
    let writer = tokio::spawn(write_loop(sink, rx, (cfg.dead_after / 3).min(PING_EVERY)));
    let u = udp.clone();
    // split mode: set once the server hands a token; until then (or with an old server) everything rides the leg
    let up_sock: Arc<std::sync::Mutex<Option<Arc<UdpSocket>>>> = Arc::new(std::sync::Mutex::new(None));
    let us = up_sock.clone();
    let reader_udp = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            if let Ok(n) = u.recv(&mut buf).await {
                let direct = us.lock().unwrap().clone();
                if let Some(d) = direct {
                    let _ = d.send(&buf[..n]).await;
                } else if tx.try_send(buf[..n].to_vec()).is_err() && tx.is_closed() {
                    return;
                }
            }
        }
    });
    let mut beacon: Option<tokio::task::JoinHandle<()>> = None;
    let why = loop {
        match tokio::time::timeout(cfg.dead_after, stream.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => {
                for p in unpack(&b) {
                    let _ = udp.send_to(p, cfg.wg).await;
                }
            }
            Ok(Some(Ok(Message::Close(f)))) => break format!("closed {f:?}"),
            Ok(None) => break "eof".into(),
            Ok(Some(Err(e))) => break format!("ws: {e}"),
            Err(_) => break format!("idle {} s", cfg.dead_after.as_secs_f32()),
            Ok(Some(Ok(Message::Text(t)))) if t.starts_with("udp2 ") && (cfg.up_udp.is_some() || cfg.door) && beacon.is_none() => {
                let mut it = t[5..].split_whitespace();
                let tid: Option<[u8; 8]> = it.next().and_then(unhex).and_then(|v| v.try_into().ok());
                let bkey: Option<[u8; 32]> = it.next().and_then(unhex).and_then(|v| v.try_into().ok());
                let (Some(tid), Some(bkey)) = (tid, bkey) else { continue };
                let node = node_id(&cfg.key);
                // candidates in preference order: the punched public door, then the configured up address
                let mut targets: Vec<SocketAddr> = Vec::new();
                if cfg.door {
                    if let Some(d) = crate::punch::announced_door(&t) { targets.push(d); }
                }
                if let Some(u) = cfg.up_udp {
                    if !targets.contains(&u) { targets.push(u); }
                }
                let mut socks: Vec<(SocketAddr, Arc<UdpSocket>)> = Vec::new();
                for to in targets {
                    let bind = if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                    match UdpSocket::bind(bind).await {
                        Ok(x) if x.connect(to).await.is_ok() => socks.push((to, Arc::new(x))),
                        _ => eprintln!("leg client: udp to {to} unavailable"),
                    }
                }
                if socks.is_empty() { eprintln!("leg client: no udp path, staying on the leg"); continue }
                // the uplink uses the first candidate with a fresh echo, and the leg when none has one
                let echoes: Arc<Vec<std::sync::Mutex<Option<std::time::Instant>>>> =
                    Arc::new(socks.iter().map(|_| std::sync::Mutex::new(None)).collect());
                let mut readers = Vec::new();
                for (i, (to, bs)) in socks.iter().cloned().enumerate() {
                    let (le, en, wgu, wg) = (echoes.clone(), node.clone(), udp.clone(), cfg.wg);
                    readers.push(AbortOnDrop(tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        let mut seen = 0u64;
                        let mut first = true;
                        loop {
                            let Ok(n) = bs.recv(&mut buf).await else { tokio::time::sleep(Duration::from_millis(200)).await; continue };
                            let p = &buf[..n];
                            // a connected socket hears only `to`. Our own beacon coming back = an echo; anything
                            // else from the server is a hedged downlink datagram for WireGuard, which drops a
                            // second copy of anything the leg already delivered.
                            if let Some((et, seq, mac)) = beacon_parts(p) {
                                if et != tid || seq <= seen || !ct_eq(&beacon_mac(&bkey, &en, seq), &mac) { continue; }
                                seen = seq;
                                *le[i].lock().unwrap() = Some(std::time::Instant::now());
                                if first { eprintln!("leg client: udp path {to} answers"); first = false; }
                            } else if p != crate::punch::PUNCH && !p.is_empty() {
                                let _ = wgu.send_to(p, wg).await;
                            }
                        }
                    })));
                }
                let slot = up_sock.clone();
                beacon = Some(tokio::spawn(async move {
                    let _readers = readers;
                    let mut seq = 0u64;
                    let mut using: Option<usize> = None;
                    loop {
                        for (_, bs) in &socks {
                            seq += 1;
                            let _ = bs.send(&self::beacon(&tid, &bkey, &node, seq)).await;
                        }
                        tokio::time::sleep(BEACON_EVERY).await;
                        let pick = (0..socks.len())
                            .find(|&i| echoes[i].lock().unwrap().is_some_and(|t| t.elapsed() < UDP_STALE));
                        if pick != using {
                            *slot.lock().unwrap() = pick.map(|i| socks[i].1.clone());
                            match pick {
                                Some(i) => eprintln!("leg client: sending up udp to {}, receiving on the leg and udp", socks[i].0),
                                None => eprintln!("leg client: no udp echo for {} s, uplink back on the leg", UDP_STALE.as_secs()),
                            }
                            using = pick;
                        }
                    }
                }));
            }
            Ok(Some(Ok(_))) => {}
        }
    };
    if let Some(b) = beacon { b.abort(); }
    let _ = up.send(false);
    writer.abort();
    reader_udp.abort();
    why
}

/// aborts the task when dropped (so aborting the beacon task also ends its echo reader)
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) { self.0.abort(); }
}

/// run forever. With several relays a leg that ends moves to the next relay at once; backoff 1 s .. 30 s (300 s when
/// every relay refused) starts only after a whole round failed. One relay behaves as before.
pub async fn client_run(cfg: ClientCfg, up: tokio::sync::watch::Sender<bool>) {
    // rustls 0.23 panics at the first TLS connect unless one crypto provider is chosen for the process
    let _ = rustls::crypto::ring::default_provider().install_default();
    closed_by_default(&cfg.listen).expect("listen");
    let udp = Arc::new(UdpSocket::bind(cfg.listen).await.expect("bind leg udp"));
    let urls: Vec<String> = std::iter::once(cfg.url.clone()).chain(cfg.alt_urls.iter().cloned()).collect();
    let (mut i, mut tried, mut refused, mut back) = (0usize, 0usize, 0usize, 1u64);
    loop {
        let t0 = std::time::Instant::now();
        let why = client_once(&cfg, &urls[i], &udp, &up).await;
        eprintln!("leg client: {}: {why}", urls[i]);
        if t0.elapsed() > Duration::from_secs(60) {
            (tried, refused, back) = (0, 0, 1);
        }
        tried += 1;
        refused += why.starts_with("refused") as usize;
        i = (i + 1) % urls.len();
        if tried < urls.len() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        if refused == urls.len() {
            back = 300; // every door said no: do not hammer them
        }
        (tried, refused) = (0, 0);
        tokio::time::sleep(Duration::from_secs(back)).await;
        back = (back * 2).min(30).max(1);
    }
}

// ---------- boringtun UAPI: switch one peer's endpoint ----------

/// Set `peer_hex`'s endpoint to `ep` through a boringtun UAPI socket. boringtun 0.7.1 panics ("Modifying existing peers
/// is not yet supported") on a set that touches an existing peer and answers EINVAL to update_only, so: read the peer,
/// and only when its endpoint differs remove it and add it back with the new endpoint and its own allowed IPs and
/// keepalive. Two sets, because boringtun never resets `remove` between peer sections (a remove and an add in one set
/// removes twice). Re-adding starts a new handshake, so it only happens
/// on a real switch.
pub fn uapi_set_endpoint(sock: &str, peer_hex: &str, ep: &str) -> Result<(), String> {
    let cur = uapi(&sock, "get=1\n\n")?;
    let mut peer: Option<Vec<(String, String)>> = None;
    let mut mine = false;
    for l in cur.lines() {
        let Some((k, v)) = l.split_once('=') else { continue };
        if k == "public_key" {
            if mine { break; }
            mine = v == peer_hex;
            if mine { peer = Some(vec![]); }
            continue;
        }
        if mine { peer.as_mut().unwrap().push((k.to_string(), v.to_string())); }
    }
    let peer = peer.ok_or("peer not on this interface")?;
    if peer.iter().any(|(k, v)| k == "endpoint" && v == ep) {
        return Ok(());
    }
    let r = uapi(&sock, &format!("set=1\npublic_key={}\nremove=true\n\n", peer_hex))?;
    if !r.contains("errno=0") {
        return Err(format!("uapi remove: {}", r.trim()));
    }
    let mut m = format!("set=1\npublic_key={}\nendpoint={ep}\n", peer_hex);
    for (k, v) in &peer {
        if k == "allowed_ip" || k == "persistent_keepalive_interval" {
            m += &format!("{k}={v}\n");
        }
    }
    let r = uapi(&sock, &(m + "\n"))?;
    if r.contains("errno=0") { Ok(()) } else { Err(format!("uapi add: {}", r.trim())) }
}

pub fn uapi(sock: &str, msg: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    let mut s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| format!("{sock}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    s.write_all(msg.as_bytes()).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut b = [0u8; 4096];
    // the answer ends with errno=N and a blank line
    while !String::from_utf8_lossy(&out).contains("errno=") {
        match s.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&b[..n]),
        }
    }
    Ok(String::from_utf8_lossy(&out).into())
}


// ---------- browser tabs ----------
//
// A tab is a node that lives minutes: two keys made in memory (ed25519 identity, x25519 WireGuard), a capability minted by
// the embedding app's backend for that ed25519 key, scoped to `net.mesh:cell:<cell>`, at most 10 minutes. The tab's
// hello on this door carries both keys, the cell and the cap, signed by the ed25519 key over the server's nonce (so a
// hello copied off the wire is useless on any other connection). Admitted, the tab gets a 10.77.255.x address, a
// kernel WireGuard peer (AllowedIPs that /32, endpoint = its own loopback socket here) and one nftables element that
// lets that /32 reach the cell's addr:port over TCP and nothing else. All three go when the cap expires, when the
// WebSocket closes, or after 60 s with no packet from the tab. The wire format matches crates/netmesh-client
// src/hello.rs byte for byte (both ends of the hello live there).

pub const TAB_PROTO: &str = "net.mesh/leg/tab/v1";
/// tabs get addresses from 10.77.255.0/24 (.1 to .254)
pub const TAB_NET: [u8; 3] = [10, 77, 255];
/// a tab never outlives this, whatever its cap says (the cap ceiling)
pub const TAB_MAX: Duration = Duration::from_secs(600);
pub const TAB_IDLE: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TabHello {
    pub proto: String,
    pub node: String,
    pub wg: String,
    pub cell: String,
    pub cap: String,
    pub ts: u64,
    pub sig: String,
}

fn b64_32(s: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()?.try_into().ok()
}

pub fn cell_name_ok(c: &str) -> bool {
    !c.is_empty() && c.len() <= 128 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
}

impl TabHello {
    pub fn signed_bytes(&self, nonce: &str) -> Vec<u8> {
        format!("{}\n{nonce}\n{}\n{}\n{}\n{}\n{}", self.proto, self.node, self.wg, self.cell, self.ts, self.cap).into_bytes()
    }

    /// what a tab sends (the browser uses netmesh-client; this is for tests and native tools)
    pub fn signed(k: &SigningKey, wg_pub_b64: &str, nonce: &str, cell: &str, cap: &str, ts: u64) -> TabHello {
        let mut h = TabHello { proto: TAB_PROTO.into(), node: node_id(k), wg: wg_pub_b64.into(), cell: cell.into(), cap: cap.into(), ts, sig: String::new() };
        h.sig = hex(&k.sign(&h.signed_bytes(nonce)).to_bytes());
        h
    }

    /// everything but the cap: proto, shapes, clock window, signature over this connection's nonce
    pub fn check(&self, nonce: &str, now: u64) -> Result<(), &'static str> {
        if self.proto != TAB_PROTO { return Err("bad proto"); }
        if self.ts + MAX_SKEW_S < now || self.ts > now + MAX_SKEW_S { return Err("timestamp outside window"); }
        if !cell_name_ok(&self.cell) { return Err("bad cell name"); }
        if self.cap.is_empty() { return Err("no cap"); }
        b64_32(&self.wg).ok_or("bad wg key")?;
        let pk: [u8; 32] = unhex(&self.node).and_then(|v| v.try_into().ok()).ok_or("bad node id")?;
        let sig: [u8; 64] = unhex(&self.sig).and_then(|v| v.try_into().ok()).ok_or("bad signature encoding")?;
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad node id")?;
        vk.verify(&self.signed_bytes(nonce), &Signature::from_bytes(&sig)).map_err(|_| "bad signature")
    }
}

/// The host side of admitting a tab, behind a trait so the door logic is tested without root. `KernelTabs` is the
/// real one (an IAM verifier command, `wg`, `nft`).
pub trait TabSys: Send + Sync {
    /// IAM verify of `cap` for `node` and action `net.mesh:cell:<cell>`, fail-closed. Ok(not_after unix s, 0 = none).
    fn verify_cap(&self, cap: &str, node: &str, cell: &str) -> Result<u64, String>;
    /// the cell directory: cell (service) name -> 10.77 addr:port
    fn resolve_cell(&self, cell: &str) -> Option<std::net::SocketAddrV4>;
    fn add_peer(&self, wg_pub: &str, addr: std::net::Ipv4Addr, endpoint: SocketAddr) -> Result<(), String>;
    fn remove_peer(&self, wg_pub: &str) -> Result<(), String>;
    fn allow(&self, tab: std::net::Ipv4Addr, cell: std::net::SocketAddrV4) -> Result<(), String>;
    fn disallow(&self, tab: std::net::Ipv4Addr, cell: std::net::SocketAddrV4) -> Result<(), String>;
}

/// one admitted tab, as the door holds it
#[derive(Debug, Clone, PartialEq)]
pub struct TabLease {
    pub node: String,
    pub wg: String,
    pub addr: std::net::Ipv4Addr,
    pub cell: std::net::SocketAddrV4,
    /// unix s; the earlier of the cap's not_after and admit + TAB_MAX
    pub until: u64,
    conn: u64,
}

pub struct Tabs {
    sys: Arc<dyn TabSys>,
    /// the server's WireGuard public key (base64), told to every tab in the `ok` line
    pub server_wg: String,
    leases: std::sync::Mutex<BTreeMap<std::net::Ipv4Addr, TabLease>>,
    seq: std::sync::atomic::AtomicU64,
}

impl Tabs {
    pub fn new(sys: Arc<dyn TabSys>, server_wg: String) -> Arc<Tabs> {
        Arc::new(Tabs { sys, server_wg, leases: Default::default(), seq: 0.into() })
    }

    pub fn leases(&self) -> Vec<TabLease> { self.leases.lock().unwrap().values().cloned().collect() }

    /// claim the lowest free 10.77.255.x; an older lease of the same ed25519 key is handed back for removal
    fn lease(&self, node: &str, wg: &str, cell: std::net::SocketAddrV4, until: u64) -> Result<(TabLease, Option<TabLease>), String> {
        let mut m = self.leases.lock().unwrap();
        let old = m.iter().find(|(_, l)| l.node == node).map(|(a, _)| *a).and_then(|a| m.remove(&a));
        let addr = (1..=254u8).map(|h| std::net::Ipv4Addr::new(TAB_NET[0], TAB_NET[1], TAB_NET[2], h)).find(|a| !m.contains_key(a))
            .ok_or("no free tab address (254 in use)")?;
        let conn = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let l = TabLease { node: node.into(), wg: wg.into(), addr, cell, until, conn };
        m.insert(addr, l.clone());
        Ok((l, old))
    }

    /// take the lease off, peer and rule with it. Only the connection that holds it may (a newer one took it over).
    fn release(&self, l: &TabLease, why: &str) {
        let mine = {
            let mut m = self.leases.lock().unwrap();
            if m.get(&l.addr).is_some_and(|x| x.conn == l.conn) { m.remove(&l.addr); true } else { false }
        };
        if mine { self.unwire(l, why); }
    }

    fn unwire(&self, l: &TabLease, why: &str) {
        let p = self.sys.remove_peer(&l.wg);
        let r = self.sys.disallow(l.addr, l.cell);
        eprintln!("leg: tab {} removed ({why}): {} -> {} peer {:?} rule {:?}", &l.node[..12], l.addr, l.cell, p, r);
    }

    /// the door decision for a hello on a connection with `nonce`, and the wiring. Ok(lease) = admitted.
    pub fn admit(&self, h: &TabHello, nonce: &str, now: u64, endpoint: SocketAddr) -> Result<TabLease, String> {
        h.check(nonce, now)?;
        let cell = self.sys.resolve_cell(&h.cell).ok_or("unknown cell")?;
        let not_after = self.sys.verify_cap(&h.cap, &h.node, &h.cell).map_err(|e| format!("cap refused: {e}"))?;
        let until = if not_after == 0 { now + TAB_MAX.as_secs() } else { not_after.min(now + TAB_MAX.as_secs()) };
        if until <= now { return Err("cap expired".into()); }
        let (l, old) = self.lease(&h.node, &h.wg, cell, until)?;
        if let Some(o) = old { self.unwire(&o, "replaced by a newer connection"); }
        let wired = self.sys.add_peer(&l.wg, l.addr, endpoint).and_then(|_| self.sys.allow(l.addr, l.cell));
        if let Err(e) = wired {
            self.release(&l, "wiring failed");
            return Err(format!("wiring: {e}"));
        }
        eprintln!("leg: tab {} admitted: {} -> {} (cell {}) for {} s", &l.node[..12], l.addr, l.cell, h.cell, until - now);
        Ok(l)
    }
}

impl Server {
    async fn tab_conn<S>(self: Arc<Self>, mut ws: S, nonce: &str, h: TabHello) -> Result<(), String>
    where
        S: futures_util::Sink<Message> + futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin + Send + 'static,
        <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
    {
        let Some(tabs) = self.tabs.get().cloned() else {
            let _ = ws.send(Message::Text("refused: no tab door here".into())).await;
            return Err("tab refused: no tab door".into());
        };
        // the tab's own loopback socket toward WireGuard: its peer endpoint, so kernel WG answers come back here
        let udp = UdpSocket::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
        udp.connect(self.wg).await.map_err(|e| e.to_string())?;
        let ep = udp.local_addr().map_err(|e| e.to_string())?;
        let (t2, h2, n2) = (tabs.clone(), h.clone(), nonce.to_string());
        // the IAM verifier, wg and nft are subprocesses: off the async threads
        let lease = tokio::task::spawn_blocking(move || t2.admit(&h2, &n2, now(), ep)).await.map_err(|e| e.to_string())?;
        let lease = match lease {
            Ok(l) => l,
            Err(e) => {
                let _ = ws.send(Message::Text(format!("refused: {e}"))).await;
                let _ = ws.close().await;
                return Err(format!("tab {} refused: {e}", &h.node[..12.min(h.node.len())]));
            }
        };
        let ok = format!("ok {} {} {}", lease.addr, tabs.server_wg, lease.cell);
        if ws.send(Message::Text(ok)).await.is_err() {
            let (t, l) = (tabs.clone(), lease.clone());
            let _ = tokio::task::spawn_blocking(move || t.release(&l, "closed before ok")).await;
            return Err("tab: closed before ok".into());
        }
        let (tx, rx) = mpsc::channel(QUEUE);
        let (sink, mut stream) = ws.split();
        let writer = tokio::spawn(write_loop(sink, rx, PING_EVERY));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(lease.until.saturating_sub(now()));
        let mut last_up = tokio::time::Instant::now();
        let mut buf = vec![0u8; 65536];
        let why = loop {
            tokio::select! {
                m = stream.next() => match m {
                    Some(Ok(Message::Binary(b))) => {
                        last_up = tokio::time::Instant::now();
                        for p in unpack(&b) {
                            if p.len() <= DATAGRAM_MAX { let _ = udp.send(p).await; }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break "websocket closed",
                    Some(Ok(_)) => {}
                },
                r = udp.recv(&mut buf) => if let Ok(n) = r { let _ = tx.try_send(buf[..n].to_vec()); },
                _ = tokio::time::sleep_until(deadline) => break "cap expired",
                _ = tokio::time::sleep_until(last_up + TAB_IDLE) => break "60 s without a packet",
            }
        };
        writer.abort();
        let (t, l) = (tabs.clone(), lease.clone());
        let _ = tokio::task::spawn_blocking(move || t.release(&l, why)).await;
        Ok(())
    }
}

/// The nftables table the tab rules live in. Loaded once by the administrator (`nft -f`), before the leg starts with
/// `--tabs`; the leg only adds and deletes `allow` elements. A packet from a tab /32 passes only when (src, dst,
/// tcp dport) is an element; everything else from 10.77.255.0/24 is dropped, on input (the cell is on this host) and
/// on forward (the cell is behind it). Replies to the tab are not from 10.77.255.0/24, so they pass.
pub fn tab_nft_table(table: &str) -> String {
    format!("table inet {table} {{
  set allow {{ type ipv4_addr . ipv4_addr . inet_service; }}
  chain input {{ type filter hook input priority -10; policy accept;
    ip saddr {n}.0/24 ip saddr . ip daddr . tcp dport @allow accept
    ip saddr {n}.0/24 drop
  }}
  chain forward {{ type filter hook forward priority -10; policy accept;
    ip saddr {n}.0/24 ip saddr . ip daddr . tcp dport @allow accept
    ip saddr {n}.0/24 drop
  }}
}}
", n = format!("{}.{}.{}", TAB_NET[0], TAB_NET[1], TAB_NET[2]))
}

/// the element one tab gets in `allow`
pub fn tab_nft_element(tab: std::net::Ipv4Addr, cell: std::net::SocketAddrV4) -> String {
    format!("{{ {tab} . {} . {} }}", cell.ip(), cell.port())
}

/// What `tab_nft_table` lets through, as a function of the element set: the rule set's meaning, for tests.
pub fn tab_rules_pass(allow: &BTreeSet<(std::net::Ipv4Addr, std::net::SocketAddrV4)>, src: std::net::Ipv4Addr, dst: std::net::SocketAddrV4, tcp: bool) -> bool {
    let o = src.octets();
    if o[..3] != TAB_NET { return true; }
    tcp && allow.contains(&(src, dst))
}

/// The real host side: `<iam> verify` + `<iam> policy inspect`, kernel WireGuard through `wg`, nftables through
/// `nft`. The leg runs as a user without CAP_NET_ADMIN, so `wg`/`nft` go through a command prefix (e.g. `sudo -n`).
pub struct KernelTabs {
    pub iam: String,
    pub iam_data_dir: Option<String>,
    /// extra `<iam> verify` flags; production keeps the default `--use-roots --fail-closed`
    pub verify_flags: Vec<String>,
    pub wg_if: String,
    pub nft_table: String,
    pub priv_prefix: Vec<String>,
    pub cells: BTreeMap<String, std::net::SocketAddrV4>,
}

impl KernelTabs {
    /// `name addr:port` per line, `#` comments; a cell outside 10.77.0.0/16 or a tab address is refused
    pub fn load_cells(path: &Path) -> Result<BTreeMap<String, std::net::SocketAddrV4>, String> {
        let t = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut m = BTreeMap::new();
        for (i, line) in t.lines().enumerate() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() { continue; }
            let mut it = line.split_whitespace();
            let (Some(n), Some(a), None) = (it.next(), it.next(), it.next()) else { return Err(format!("{}:{}: want `name addr:port`", path.display(), i + 1)) };
            let a: std::net::SocketAddrV4 = a.parse().map_err(|e| format!("{}:{}: {e}", path.display(), i + 1))?;
            let o = a.ip().octets();
            if !cell_name_ok(n) || o[..2] != crate::NET || o[..3] == TAB_NET {
                return Err(format!("{}:{}: bad cell {n} {a}", path.display(), i + 1));
            }
            m.insert(n.to_string(), a);
        }
        Ok(m)
    }

    fn run(&self, privileged: bool, prog: &str, args: &[&str]) -> Result<String, String> {
        let mut argv: Vec<String> = if privileged { self.priv_prefix.clone() } else { vec![] };
        argv.push(prog.into());
        argv.extend(args.iter().map(|s| s.to_string()));
        let out = std::process::Command::new(&argv[0]).args(&argv[1..]).stdin(std::process::Stdio::null()).output()
            .map_err(|e| format!("{}: {e}", argv[0]))?;
        if !out.status.success() {
            return Err(format!("{} exit {}: {}", argv.join(" "), out.status, String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl TabSys for KernelTabs {
    fn verify_cap(&self, cap: &str, node: &str, cell: &str) -> Result<u64, String> {
        // same reading as netmesh-control's cap_ok: hex token, 64-hex requester, exit 0 and an affirmative verdict
        if !cap.chars().all(|c| c.is_ascii_hexdigit()) || node.len() != 64 || !cell_name_ok(cell) {
            return Err("malformed".into());
        }
        let action = format!("net.mesh:cell:{cell}");
        let mut a: Vec<&str> = vec!["verify", "--token", cap, "--requester", node, "--action", &action, "--json"];
        a.extend(self.verify_flags.iter().map(String::as_str));
        if let Some(d) = &self.iam_data_dir { a.extend(["--data-dir", d.as_str()]); }
        let text = self.run(false, &self.iam, &a)?;
        let v: serde_json::Value = serde_json::from_str(text.trim()).map_err(|_| "no verdict".to_string())?;
        if v.get("authorized").and_then(|b| b.as_bool()) != Some(true) {
            return Err(v.get("reason").and_then(|r| r.as_str()).unwrap_or("not authorized").to_string());
        }
        let mut a = vec!["policy", "inspect", cap, "--json"];
        if let Some(d) = &self.iam_data_dir { a.extend(["--data-dir", d.as_str()]); }
        let s: serde_json::Value = serde_json::from_str(self.run(false, &self.iam, &a)?.trim()).map_err(|_| "inspect: bad json".to_string())?;
        // scope.not_after is the chain's earliest expiry; missing = refuse (fail-closed), 0 = never (TAB_MAX applies)
        s.get("not_after").or_else(|| s.get("scope").and_then(|x| x.get("not_after"))).and_then(|n| n.as_u64())
            .ok_or_else(|| "inspect: no not_after".to_string())
    }

    fn resolve_cell(&self, cell: &str) -> Option<std::net::SocketAddrV4> { self.cells.get(cell).copied() }

    fn add_peer(&self, wg_pub: &str, addr: std::net::Ipv4Addr, endpoint: SocketAddr) -> Result<(), String> {
        b64_32(wg_pub).ok_or("bad wg key")?;
        self.run(true, "wg", &["set", &self.wg_if, "peer", wg_pub, "allowed-ips", &format!("{addr}/32"), "endpoint", &endpoint.to_string()]).map(|_| ())
    }

    fn remove_peer(&self, wg_pub: &str) -> Result<(), String> {
        b64_32(wg_pub).ok_or("bad wg key")?;
        self.run(true, "wg", &["set", &self.wg_if, "peer", wg_pub, "remove"]).map(|_| ())
    }

    fn allow(&self, tab: std::net::Ipv4Addr, cell: std::net::SocketAddrV4) -> Result<(), String> {
        self.run(true, "nft", &["add", "element", "inet", &self.nft_table, "allow", &tab_nft_element(tab, cell)]).map(|_| ())
    }

    fn disallow(&self, tab: std::net::Ipv4Addr, cell: std::net::SocketAddrV4) -> Result<(), String> {
        self.run(true, "nft", &["delete", "element", "inet", &self.nft_table, "allow", &tab_nft_element(tab, cell)]).map(|_| ())
    }
}
