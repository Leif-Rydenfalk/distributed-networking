//! net.mesh path manager ("as reliable as the local network").
//!
//! Without it, a node's WireGuard endpoint for each peer is picked once at boot and never again: a LAN or cable path that died stayed chosen, and a better one that came up was never used. `netmesh-path`
//! probes every candidate address of every peer several times a second and moves the WireGuard endpoint to the best
//! live one, or back to the fallback (the relay leg) when no direct candidate answers. WireGuard itself is stateless
//! about paths, so TCP inside the tunnel survives a switch; the app sees a short stall, never a reset.
//!
//! Probe packets go on their own UDP socket (WireGuard's port + 1 by default), authenticated per peer pair with a key
//! both sides derive from their WireGuard keys (X25519), so nothing new is distributed and a stranger gets no answer:
//!
//!   ping/pong = "NMP1" | kind u8 | sender wg public key [32] | seq u64 | echo_ns u64 | mac [16]
//!
//! mac = HMAC-SHA256(k, everything before it)[..16], k = SHA256("net.mesh/path/v1" | X25519(mine, theirs)).
//! A ping's seq must rise per sender (replays are dropped); a pong must echo a seq we sent in the last 5 s.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub const MAGIC: [u8; 4] = *b"NMP1";
pub const PING: u8 = 1;
pub const PONG: u8 = 2;
pub const PKT_LEN: usize = 4 + 1 + 32 + 8 + 8 + 16;

pub type Key = [u8; 32];

fn hmac_sha256(key: &Key, msg: &[u8]) -> [u8; 32] {
    let (mut ip, mut op) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..32 {
        ip[i] ^= key[i];
        op[i] ^= key[i];
    }
    let inner = Sha256::new().chain_update(ip).chain_update(msg).finalize();
    Sha256::new().chain_update(op).chain_update(inner).finalize().into()
}

/// The probe key both ends of a pair derive from their WireGuard keys. Symmetric: pair_key(a, B) == pair_key(b, A).
pub fn pair_key(my_wg_private: &Key, peer_wg_public: &Key) -> Key {
    let secret = x25519_dalek::StaticSecret::from(*my_wg_private);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*peer_wg_public));
    Sha256::new().chain_update(b"net.mesh/path/v1").chain_update(shared.as_bytes()).finalize().into()
}

pub fn wg_public(wg_private: &Key) -> Key {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*wg_private)).to_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pkt {
    pub kind: u8,
    pub sender: Key,
    pub seq: u64,
    pub echo_ns: u64,
}

pub fn encode(p: &Pkt, key: &Key) -> [u8; PKT_LEN] {
    let mut b = [0u8; PKT_LEN];
    b[..4].copy_from_slice(&MAGIC);
    b[4] = p.kind;
    b[5..37].copy_from_slice(&p.sender);
    b[37..45].copy_from_slice(&p.seq.to_be_bytes());
    b[45..53].copy_from_slice(&p.echo_ns.to_be_bytes());
    let mac = hmac_sha256(key, &b[..53]);
    b[53..].copy_from_slice(&mac[..16]);
    b
}

/// The sender's WireGuard key without checking anything else: tells the receiver which pair key to verify with.
pub fn peek_sender(b: &[u8]) -> Option<Key> {
    if b.len() != PKT_LEN || b[..4] != MAGIC || !(b[4] == PING || b[4] == PONG) {
        return None;
    }
    b[5..37].try_into().ok()
}

/// Constant-time MAC check; None for anything malformed or forged.
pub fn decode(b: &[u8], key: &Key) -> Option<Pkt> {
    let sender = peek_sender(b)?;
    let mac = hmac_sha256(key, &b[..53]);
    let diff = mac[..16].iter().zip(&b[53..]).fold(0u8, |a, (x, y)| a | (x ^ y));
    if diff != 0 {
        return None;
    }
    Some(Pkt {
        kind: b[4],
        sender,
        seq: u64::from_be_bytes(b[37..45].try_into().unwrap()),
        echo_ns: u64::from_be_bytes(b[45..53].try_into().unwrap()),
    })
}

/// Timing of the selector. Defaults: probe every 200 ms, a candidate is dead 500 ms after its last answer (two missed probes), so a dead
/// path is left in well under 1 s.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    pub every: Duration,
    pub dead_after: Duration,
    /// consecutive answers before a candidate may be chosen (keeps a flapping path out)
    pub up_after: u32,
    /// a live candidate replaces the current live one only when its RTT is lower by this fraction
    pub better_by: f64,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning { every: Duration::from_millis(200), dead_after: Duration::from_millis(500), up_after: 2, better_by: 0.3 }
    }
}

#[derive(Debug, Clone, Default)]
struct Cand {
    last_pong: Option<Instant>,
    streak: u32,
    rtt_ms: Option<f64>,
}

/// Where a peer's traffic goes: a direct candidate, or the fallback (relay) endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Direct(SocketAddr),
    Fallback,
}

/// Per-peer path choice. Pure: time comes in as arguments, so every rule is tested without sleeping.
#[derive(Debug, Clone)]
pub struct Selector {
    pub tuning: Tuning,
    cands: Vec<(SocketAddr, Cand)>,
    pub choice: Choice,
}

impl Selector {
    pub fn new(candidates: &[SocketAddr], tuning: Tuning) -> Self {
        Selector { tuning, cands: candidates.iter().map(|a| (*a, Cand::default())).collect(), choice: Choice::Fallback }
    }

    pub fn candidates(&self) -> Vec<SocketAddr> {
        self.cands.iter().map(|c| c.0).collect()
    }

    /// A probe to `addr` was due and got no answer by now: counted only through `last_pong` age, nothing to record.
    /// A pong from `addr` that took `rtt`.
    pub fn pong(&mut self, addr: SocketAddr, rtt: Duration, now: Instant) {
        if let Some((_, c)) = self.cands.iter_mut().find(|c| c.0 == addr) {
            let ms = rtt.as_secs_f64() * 1000.0;
            // the streak counts answers that came while the candidate was alive; a gap restarts it
            let alive = c.last_pong.map_or(false, |t| now.duration_since(t) <= self.tuning.dead_after);
            c.streak = if alive { c.streak + 1 } else { 1 };
            c.rtt_ms = Some(match c.rtt_ms { Some(r) if alive => r * 0.7 + ms * 0.3, _ => ms });
            c.last_pong = Some(now);
        }
    }

    fn alive(&self, c: &Cand, now: Instant) -> bool {
        c.last_pong.map_or(false, |t| now.duration_since(t) <= self.tuning.dead_after)
    }

    /// Re-decide. Returns the new choice when it changed.
    pub fn decide(&mut self, now: Instant) -> Option<Choice> {
        let ready = |c: &Cand| self.alive(c, now) && c.streak >= self.tuning.up_after;
        let best = self
            .cands
            .iter()
            .filter(|(_, c)| ready(c))
            .min_by(|a, b| a.1.rtt_ms.unwrap_or(f64::MAX).total_cmp(&b.1.rtt_ms.unwrap_or(f64::MAX)))
            .map(|(a, c)| (*a, c.rtt_ms.unwrap_or(f64::MAX)));
        let next = match (&self.choice, best) {
            (Choice::Direct(cur), best) => {
                let cur_c = self.cands.iter().find(|c| c.0 == *cur).map(|c| &c.1);
                match cur_c {
                    Some(c) if self.alive(c, now) => match best {
                        Some((b, rtt)) if b != *cur && rtt < c.rtt_ms.unwrap_or(f64::MAX) * (1.0 - self.tuning.better_by) => {
                            Choice::Direct(b)
                        }
                        _ => Choice::Direct(*cur),
                    },
                    _ => best.map_or(Choice::Fallback, |(b, _)| Choice::Direct(b)),
                }
            }
            (Choice::Fallback, Some((b, _))) => Choice::Direct(b),
            (Choice::Fallback, None) => Choice::Fallback,
        };
        if next != self.choice {
            self.choice = next.clone();
            Some(next)
        } else {
            None
        }
    }
}

/// Replay guard for pings: the highest seq seen per sender.
#[derive(Default)]
pub struct SeqGuard(HashMap<Key, u64>);

impl SeqGuard {
    pub fn accept(&mut self, sender: &Key, seq: u64) -> bool {
        let last = self.0.entry(*sender).or_insert(0);
        if seq > *last {
            *last = seq;
            true
        } else {
            false
        }
    }
}

/// How a chosen endpoint reaches WireGuard.
pub trait Apply: Send {
    fn set_endpoint(&mut self, peer_wg_public: &Key, endpoint: SocketAddr) -> Result<(), String>;
}

/// The plain UAPI text that moves one peer (wireguard-go takes it; boringtun 0.7.1 panics on it, see `Uapi`).
pub fn uapi_set_endpoint(peer_wg_public: &Key, endpoint: SocketAddr) -> String {
    format!("set=1\npublic_key={}\nendpoint={}\n\n", crate::hex(peer_wg_public), endpoint)
}

/// boringtun / wireguard-go: the control socket `/var/run/wireguard/<if>.sock`. Goes through
/// `leg::uapi_set_endpoint`, never a bare `set`: boringtun 0.7.1 panics when a set touches an existing peer, so the
/// peer is removed and re-added with its allowed IPs and keepalive, and only when the endpoint really changes.
pub struct Uapi(pub std::path::PathBuf);

impl Apply for Uapi {
    fn set_endpoint(&mut self, peer: &Key, ep: SocketAddr) -> Result<(), String> {
        crate::leg::uapi_set_endpoint(&self.0.to_string_lossy(), &crate::hex(peer), &ep.to_string())
    }
}

/// Kernel WireGuard on Linux: `wg set <if> peer <b64> endpoint <ep>`.
pub struct WgCli(pub String);

impl Apply for WgCli {
    fn set_endpoint(&mut self, peer: &Key, ep: SocketAddr) -> Result<(), String> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(peer);
        let out = std::process::Command::new("wg")
            .args(["set", &self.0, "peer", &b64, "endpoint", &ep.to_string()])
            .output()
            .map_err(|e| format!("wg: {e}"))?;
        if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().to_string()) }
    }
}

/// One peer as the path manager sees it.
#[derive(Debug, Clone)]
pub struct PeerCfg {
    pub name: String,
    pub wg_public: Key,
    /// probe addresses (IP:probe-port); the WireGuard endpoint used for a candidate is the same IP on `wg_port`
    pub candidates: Vec<SocketAddr>,
    pub wg_port: u16,
    /// where traffic goes when no candidate answers (the relay leg), as WireGuard sees it
    pub fallback: SocketAddr,
}

/// One switch, for the log and the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    pub peer: String,
    pub to: SocketAddr,
    pub direct: bool,
}

/// The probe loop: answers pings from known peers, pings every candidate of every peer, moves endpoints.
/// Runs until the task is dropped. `log` gets every switch.
pub async fn run(
    sock: tokio::net::UdpSocket,
    my_private: Key,
    peers: Vec<PeerCfg>,
    tuning: Tuning,
    mut apply: Box<dyn Apply>,
    log: tokio::sync::mpsc::UnboundedSender<Switch>,
) -> std::io::Result<()> {
    let me = wg_public(&my_private);
    let keys: HashMap<Key, Key> = peers.iter().map(|p| (p.wg_public, pair_key(&my_private, &p.wg_public))).collect();
    let mut sel: Vec<Selector> = peers.iter().map(|p| Selector::new(&p.candidates, tuning)).collect();
    let mut guard = SeqGuard::default();
    // seq -> (peer index, candidate, sent at); pruned after 5 s
    let mut sent: HashMap<u64, (usize, SocketAddr, Instant)> = HashMap::new();
    let mut seq: u64 = (crate::now() as u64) << 20; // rises across restarts, so a peer's replay guard keeps accepting
    let epoch = Instant::now();
    let mut tick = tokio::time::interval(tuning.every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // the fallback is what WireGuard has until a direct path proves itself
    for p in &peers {
        let _ = apply.set_endpoint(&p.wg_public, p.fallback);
    }
    let mut buf = [0u8; 256];
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let now = Instant::now();
                sent.retain(|_, v| now.duration_since(v.2) < Duration::from_secs(5));
                for (i, p) in peers.iter().enumerate() {
                    for c in &p.candidates {
                        seq += 1;
                        let pkt = Pkt { kind: PING, sender: me, seq, echo_ns: now.duration_since(epoch).as_nanos() as u64 };
                        let _ = sock.send_to(&encode(&pkt, &keys[&p.wg_public]), c).await;
                        sent.insert(seq, (i, *c, now));
                    }
                    if let Some(ch) = sel[i].decide(now) {
                        let (to, direct) = match ch {
                            Choice::Direct(a) => (SocketAddr::new(a.ip(), p.wg_port), true),
                            Choice::Fallback => (p.fallback, false),
                        };
                        let _ = apply.set_endpoint(&p.wg_public, to);
                        let _ = log.send(Switch { peer: p.name.clone(), to, direct });
                    }
                }
            }
            r = sock.recv_from(&mut buf) => {
                let (n, from) = match r { Ok(x) => x, Err(_) => continue };
                let Some(sender) = peek_sender(&buf[..n]) else { continue };
                let Some(key) = keys.get(&sender) else { continue };
                let Some(pkt) = decode(&buf[..n], key) else { continue };
                if pkt.kind == PING {
                    if guard.accept(&sender, pkt.seq) {
                        let pong = Pkt { kind: PONG, sender: me, seq: pkt.seq, echo_ns: pkt.echo_ns };
                        let _ = sock.send_to(&encode(&pong, key), from).await;
                    }
                } else if let Some((i, cand, at)) = sent.remove(&pkt.seq) {
                    // the pong must come from the peer we pinged, and from the address we pinged
                    if peers[i].wg_public == sender && cand == from {
                        let now = Instant::now();
                        sel[i].pong(cand, now.duration_since(at), now);
                        if let Some(ch) = sel[i].decide(now) {
                            let p = &peers[i];
                            let (to, direct) = match ch {
                                Choice::Direct(a) => (SocketAddr::new(a.ip(), p.wg_port), true),
                                Choice::Fallback => (p.fallback, false),
                            };
                            let _ = apply.set_endpoint(&p.wg_public, to);
                            let _ = log.send(Switch { peer: p.name.clone(), to, direct });
                        }
                    }
                }
            }
        }
    }
}
