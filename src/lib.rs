//! net.mesh control plane.
//!
//! A node is its ed25519 node key (default `~/.local/share/ce/identity/node.key`, the 32-byte seed; `netmesh id`
//! prints its public half). It signs every request to the control server; the server admits only keys on its
//! admitted list, refuses replays (each node's timestamps must rise, and lie within `MAX_SKEW_S` of the
//! server clock), hands out one stable mesh address per node and returns the peer list a WireGuard
//! data plane needs (peer WireGuard key, mesh address, endpoints).
//!
//! Wire format: one JSON line in, one JSON line out, over TCP.

pub mod leg;
pub mod path;
pub mod punch;
pub mod raft;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROTO: &str = "net.mesh/v1";
pub const MAX_SKEW_S: u64 = 60;
/// Mesh addresses come from 10.77.0.0/16, away from Tailscale's 100.64.0.0/10 so both can run side by side.
pub const NET: [u8; 2] = [10, 77];
/// Tunnel MTU. 1280 so QUIC passes: it pads handshakes to 1200 bytes of UDP payload (RFC 9000 14.1), 1228 on the
/// wire. Over the TLS leg the outer path does not limit it, and over a smaller-MTU outer path the kernel fragments the
/// outer UDP.
pub const MTU: u16 = 1280;
const CAP_REFUSED: &str = "not admitted (no admitted-list entry and the capability grant was refused)";

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// ---------- identity ----------

pub fn load_node_key(path: &Path) -> Result<SigningKey, String> {
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let seed: [u8; 32] = b.as_slice().try_into().map_err(|_| format!("{}: want 32 bytes, got {}", path.display(), b.len()))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn default_node_key() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".local/share/ce/identity/node.key")
}

pub fn node_id(k: &SigningKey) -> String {
    hex(k.verifying_key().as_bytes())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

// ---------- WireGuard key (x25519, base64 like `wg genkey`) ----------

pub fn wg_load_or_create(path: &Path) -> Result<(String, String), String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let secret: [u8; 32] = if path.exists() {
        let s = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        b64.decode(s.trim()).map_err(|e| e.to_string())?.try_into().map_err(|_| "wg key: want 32 bytes".to_string())?
    } else {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).map_err(|e| e.to_string())?;
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        write_private(path, &b64.encode(k))?;
        k
    };
    let sk = x25519_dalek::StaticSecret::from(secret);
    let pk = x25519_dalek::PublicKey::from(&sk);
    Ok((b64.encode(sk.to_bytes()), b64.encode(pk.as_bytes())))
}

pub fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())
}

// ---------- protocol ----------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Request {
    pub op: String, // "register" | "peers"
    pub node: String,
    pub ts: u64,
    #[serde(default)]
    pub wg: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub sig: String,
    /// capability grant (hex chain) for a node not on the admitted list: verified by the control server for its join action,
    /// bound to `node` (the leaf audience) and presented on every call so a revocation lands at the next one. Not signed:
    /// a bearer chain to this node id is useless without the node key that signs the request.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cap: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Peer {
    pub node: String,
    pub wg: String,
    pub addr: String,
    pub endpoints: Vec<String>,
    pub last_seen: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub err: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub addr: String,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

fn signed_bytes(op: &str, node: &str, ts: u64, wg: &str, endpoints: &[String]) -> Vec<u8> {
    format!("{PROTO}\n{op}\n{node}\n{ts}\n{wg}\n{}", endpoints.join(",")).into_bytes()
}

impl Request {
    pub fn signed(k: &SigningKey, op: &str, ts: u64, wg: &str, endpoints: Vec<String>) -> Request {
        let node = node_id(k);
        let sig = k.sign(&signed_bytes(op, &node, ts, wg, &endpoints));
        Request { op: op.into(), node, ts, wg: wg.into(), endpoints, sig: hex(&sig.to_bytes()), cap: String::new() }
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        let pk: [u8; 32] = unhex(&self.node).and_then(|v| v.try_into().ok()).ok_or("bad node id")?;
        let sig: [u8; 64] = unhex(&self.sig).and_then(|v| v.try_into().ok()).ok_or("bad signature encoding")?;
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad node id")?;
        vk.verify(&signed_bytes(&self.op, &self.node, self.ts, &self.wg, &self.endpoints), &Signature::from_bytes(&sig))
            .map_err(|_| "bad signature")
    }
}

// ---------- server state ----------

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct State {
    pub nodes: BTreeMap<String, Peer>,
    /// last accepted timestamp per node: a request must be newer (replay guard)
    pub last_ts: BTreeMap<String, u64>,
    /// nodes admitted by a capability grant rather than the admitted list; re-verified at each of their calls
    #[serde(default)]
    pub cap_members: BTreeSet<String>,
}

/// (cap hex, node id) -> does this grant let that node join. netmesh-control plugs in an external verifier command (`--iam`).
pub type CapVerifier = Box<dyn Fn(&str, &str) -> bool + Send>;

pub struct Control {
    pub admitted: BTreeSet<String>,
    pub state: State,
    pub state_path: Option<PathBuf>,
    pub cap_verifier: Option<CapVerifier>,
}

/// stable address from the node id; linear probe past collisions; host part never .0 or .255
fn pick_addr(node: &str, taken: &BTreeSet<String>) -> String {
    let b = unhex(node).unwrap_or_default();
    let mut h = u16::from_be_bytes([b.first().copied().unwrap_or(0), b.get(1).copied().unwrap_or(1)]);
    loop {
        let (x, y) = ((h >> 8) as u8, h as u8);
        let a = Ipv4Addr::new(NET[0], NET[1], x, y).to_string();
        if y != 0 && y != 255 && !(x == 0 && y == 1) && !taken.contains(&a) {
            return a;
        }
        h = h.wrapping_add(1);
    }
}

impl Control {
    pub fn new(admitted: BTreeSet<String>, state_path: Option<PathBuf>) -> Control {
        let state = state_path.as_ref().and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        Control { admitted, state, state_path, cap_verifier: None }
    }

    pub fn handle(&mut self, req: &Request, now: u64) -> Response {
        match self.precheck(req, now) {
            Ok(cap_ok) => self.apply(req, now, cap_ok),
            Err(r) => r,
        }
    }

    /// Everything that needs no write: signature, admission, clock window, replay and (for a node off the admitted list)
    /// the capability verdict. Runs on the Raft leader only. `Ok(cap_ok)` goes into the log entry; `Err` is the refusal. A node
    /// whose grant fails and that holds no membership is refused here, so strangers never reach the log.
    pub fn precheck(&self, req: &Request, now: u64) -> Result<bool, Response> {
        let refuse = |e: &str| Response { ok: false, err: e.into(), ..Default::default() };
        req.verify().map_err(refuse)?;
        // cheap checks first: a stranger's replay never reaches the (subprocess) cap verifier
        let listed = self.admitted.contains(&req.node);
        if !listed && req.cap.is_empty() {
            return Err(refuse("not admitted"));
        }
        if req.ts + MAX_SKEW_S < now || req.ts > now + MAX_SKEW_S {
            return Err(refuse("timestamp outside window"));
        }
        if self.state.last_ts.get(&req.node).is_some_and(|&t| req.ts <= t) {
            return Err(refuse("replay"));
        }
        if listed {
            return Ok(true);
        }
        let ok = self.cap_verifier.as_ref().is_some_and(|v| v(&req.cap, &req.node));
        if !ok && !self.state.cap_members.contains(&req.node) {
            return Err(refuse(CAP_REFUSED));
        }
        Ok(ok)
    }

    /// The deterministic part: re-runs every state check except the cap verifier, whose verdict `cap_ok` comes from the
    /// log entry, so every replica reaches the same state. `now` is the leader's clock at precheck.
    pub fn apply(&mut self, req: &Request, now: u64, cap_ok: bool) -> Response {
        let refuse = |e: &str| Response { ok: false, err: e.into(), ..Default::default() };
        if let Err(e) = req.verify() {
            return refuse(e);
        }
        if !self.admitted.contains(&req.node) && req.cap.is_empty() {
            return refuse("not admitted");
        }
        if req.ts + MAX_SKEW_S < now || req.ts > now + MAX_SKEW_S {
            return refuse("timestamp outside window");
        }
        if self.state.last_ts.get(&req.node).is_some_and(|&t| req.ts <= t) {
            return refuse("replay");
        }
        if !self.admitted.contains(&req.node) {
            if !cap_ok {
                if self.state.cap_members.remove(&req.node) {
                    self.state.nodes.remove(&req.node);       // a revoked or expired grant drops the node
                    self.save();
                }
                return refuse(CAP_REFUSED);
            }
            self.state.cap_members.insert(req.node.clone());
        }
        self.state.last_ts.insert(req.node.clone(), req.ts);
        match req.op.as_str() {
            "register" => {
                let taken: BTreeSet<String> =
                    self.state.nodes.iter().filter(|(n, _)| **n != req.node).map(|(_, p)| p.addr.clone()).collect();
                let addr = match self.state.nodes.get(&req.node) {
                    Some(p) => p.addr.clone(),
                    None => pick_addr(&req.node, &taken),
                };
                self.state.nodes.insert(req.node.clone(), Peer {
                    node: req.node.clone(), wg: req.wg.clone(), addr, endpoints: req.endpoints.clone(), last_seen: now,
                });
            }
            "peers" => {
                if let Some(p) = self.state.nodes.get_mut(&req.node) {
                    p.last_seen = now;
                }
            }
            _ => return refuse("unknown op"),
        }
        self.save();
        let me = self.state.nodes.get(&req.node).map(|p| p.addr.clone()).unwrap_or_default();
        let peers = self.state.nodes.values()
            .filter(|p| p.node != req.node && (self.admitted.contains(&p.node) || self.state.cap_members.contains(&p.node)))
            .cloned().collect();
        Response { ok: true, err: String::new(), addr: me, peers }
    }

    fn save(&self) {
        if let Some(p) = &self.state_path {
            let tmp = p.with_extension("tmp");
            if write_private(&tmp, &serde_json::to_string_pretty(&self.state).unwrap()).is_ok() {
                let _ = std::fs::rename(&tmp, p);
            }
        }
    }
}

/// admitted list: a JSON array of node ids, or {"nodes":[...]} with optional names
pub fn load_admitted(path: &Path) -> Result<BTreeSet<String>, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&s).map_err(|e| e.to_string())?;
    let arr = v.get("nodes").unwrap_or(&v).as_array().ok_or("admitted: want an array of node ids")?;
    Ok(arr.iter().filter_map(|x| x.as_str().or_else(|| x.get("node").and_then(|n| n.as_str()))).map(String::from).collect())
}

// ---------- client ----------

/// `control` is one address or a comma-separated list (the Raft replicas): each is tried in order on a connect error.
pub fn call(control: &str, req: &Request) -> Result<Response, String> {
    let mut last = String::from("no control address");
    for one in control.split(',').map(str::trim).filter(|x| !x.is_empty()) {
        match call_one(one, req) {
            Err(e) if e.starts_with(CONNECT_ERR) => last = e,
            other => return other,
        }
    }
    Err(last.trim_start_matches(CONNECT_ERR).to_string())
}

const CONNECT_ERR: &str = "\u{1}connect:";

fn call_one(control: &str, req: &Request) -> Result<Response, String> {
    let addr = control.parse().map_err(|e| format!("{control}: {e}"))?;
    // 3 s: a dead replica's host must not hold the client long before it tries the next one (a long-haul WAN connect: ~256 ms)
    let mut s = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3))
        .map_err(|e| format!("{CONNECT_ERR}{control}: {e}"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(20))).ok();
    let mut line = serde_json::to_string(req).unwrap();
    line.push('\n');
    s.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    let mut out = String::new();
    BufReader::new(s).read_line(&mut out).map_err(|e| e.to_string())?;
    serde_json::from_str(&out).map_err(|e| format!("bad reply {out:?}: {e}"))
}

/// wg-quick config for this node from a control reply
pub fn wg_quick(private_key: &str, listen_port: u16, resp: &Response) -> String {
    let mut s = format!("# net.mesh, written by `netmesh up` at {}\n[Interface]\nPrivateKey = {private_key}\nAddress = {}/16\nListenPort = {listen_port}\nMTU = {MTU}\n",
        now(), resp.addr);
    for p in &resp.peers {
        s += &format!("\n# {}\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\n", p.node, p.wg, p.addr);
        if let Some(e) = p.endpoints.first() {
            s += &format!("Endpoint = {e}\n");
        }
        // every endpoint the peer registered, first = default; a client that can reach a later one (for example a
        // direct link-local cable, sub-millisecond vs ~11 ms over the WAN) may pick it. wg-quick ignores comments.
        if p.endpoints.len() > 1 {
            s += &format!("# Endpoints = {}\n", p.endpoints.join(","));
        }
        s += "PersistentKeepalive = 25\n";
    }
    s
}
