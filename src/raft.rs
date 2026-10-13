//! net.mesh control as a Raft group (openraft 0.9, v1 `RaftStorage` behind `storage::Adaptor`).
//!
//! The log entry is `Cmd::Call(Entry { req, now, cap_ok })`: the leader runs `Control::precheck` (signature, admission, clock,
//! replay, the capability-verifier subprocess), then commits the entry; every replica runs the deterministic `Control::apply` on it.
//! The snapshot is the serde JSON of `State`. Reads ("peers") go through the log too, so a reply is linearizable.
//!
//! Raft port: a persistent TCP link per peer stream carrying JSON-line frames `{"op","seq","body","mac"}`,
//! mac = HMAC-SHA256(cluster secret, op "\n" seq "\n" body); seq rises by one per frame on a connection and the server
//! refuses one that does not rise. The reply `{"seq","body","err","mac"}` has mac over "reply\n" seq "\n" body "\n" err.
//! Ops: append_entries, vote, install_snapshot, forward (a follower relays a client line to the leader). A bad MAC or
//! seq closes the connection.

use crate::{write_private, Control, Request, Response, State};
use openraft::error::{
    ClientWriteError, InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError, Unreachable,
};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse, VoteRequest,
    VoteResponse,
};
use openraft::storage::Adaptor;
use openraft::{
    BasicNode, Config, EntryPayload, LogId, LogState, RaftLogReader, RaftNetwork, RaftNetworkFactory,
    RaftSnapshotBuilder, RaftStorage, Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::{Cursor, Write};
use std::ops::RangeBounds;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// The log entry. `now` is the leader's clock at precheck; `cap_ok` is the capability verdict the leader reached.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub req: Request,
    pub now: u64,
    pub cap_ok: bool,
}

/// What the log carries. `Seed` is the cluster's first entry when `--raft-init` finds a pre-Raft `--state` file, so
/// nodes registered before Raft keep their 10.77 addresses; it applies only to an empty state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Cmd {
    Call(Entry),
    Seed(State),
}

openraft::declare_raft_types!(
    pub TC:
        D = Cmd,
        R = Response,
        NodeId = u64,
        Node = BasicNode,
);

pub type Raft = openraft::Raft<TC>;
type REntry = openraft::Entry<TC>;
type SErr = StorageError<u64>;

const CLIENT_LINE_MAX: u64 = 64 * 1024;
const RAFT_LINE_MAX: u64 = 64 * 1024 * 1024;
const RPC_TIMEOUT: Duration = Duration::from_secs(3);
/// the actor's own bound on one frame (write + reply); a peer slower than this is treated as gone and reconnected
const LINK_FRAME_MAX: Duration = Duration::from_secs(10);
/// a peer link with no frame for this long is closed (the leader's heartbeats keep a live one busy)
const RAFT_IDLE: Duration = Duration::from_secs(120);
/// how long `--raft-init` waits for a quorum to commit the seed
const SEED_WAIT: Duration = Duration::from_secs(600);

// ---------- cluster secret and MAC ----------

/// The 32-byte cluster secret: a file of 32 raw bytes or 64 hex chars, mode 600 (no group or other bits).
pub fn load_secret(path: &Path) -> Result<[u8; 32], String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!("{}: mode {:o}, want 600", path.display(), meta.permissions().mode() & 0o777));
    }
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let raw = if b.len() == 32 { b } else {
        crate::unhex(String::from_utf8_lossy(&b).trim()).ok_or_else(|| format!("{}: want 32 bytes or 64 hex", path.display()))?
    };
    raw.as_slice().try_into().map_err(|_| format!("{}: want 32 bytes, got {}", path.display(), raw.len()))
}

pub fn hmac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

fn mac_ok(key: &[u8; 32], msg: &[u8], mac_hex: &str) -> bool {
    let Some(m) = crate::unhex(mac_hex) else { return false };
    let want = hmac(key, msg);
    m.len() == 32 && m.iter().zip(want.iter()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
}

#[derive(Serialize, Deserialize)]
pub struct RaftMsg {
    pub op: String,
    #[serde(default)]
    pub seq: u64,
    pub body: String,
    pub mac: String,
}

#[derive(Serialize, Deserialize, Default)]
struct RaftReply {
    #[serde(default)]
    seq: u64,
    #[serde(default)]
    body: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    err: String,
    #[serde(default)]
    mac: String,
}

impl RaftMsg {
    /// the first frame on a connection
    pub fn new(key: &[u8; 32], op: &str, body: String) -> RaftMsg {
        RaftMsg::with_seq(key, op, 1, body)
    }

    pub fn with_seq(key: &[u8; 32], op: &str, seq: u64, body: String) -> RaftMsg {
        let mac = crate::hex(&hmac(key, format!("{op}\n{seq}\n{body}").as_bytes()));
        RaftMsg { op: op.into(), seq, body, mac }
    }
}

impl RaftReply {
    fn signed(key: &[u8; 32], seq: u64, body: String, err: String) -> RaftReply {
        let mac = crate::hex(&hmac(key, format!("reply\n{seq}\n{body}\n{err}").as_bytes()));
        RaftReply { seq, body, err, mac }
    }

    fn mac_ok(&self, key: &[u8; 32]) -> bool {
        mac_ok(key, format!("reply\n{}\n{}\n{}", self.seq, self.body, self.err).as_bytes(), &self.mac)
    }
}

// ---------- storage: log + vote on disk, state machine = Control ----------

#[derive(Default)]
struct LogData {
    log: BTreeMap<u64, REntry>,
    last_purged: Option<LogId<u64>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SnapFile {
    meta: SnapshotMeta<u64, BasicNode>,
    data: Vec<u8>,
}

#[derive(Default)]
struct Sm {
    last_applied: Option<LogId<u64>>,
    membership: StoredMembership<u64, BasicNode>,
    snapshot: Option<SnapFile>,
    snap_seq: u64,
}

#[derive(Clone)]
pub struct Store {
    ctl: Arc<Mutex<Control>>,
    dir: Option<PathBuf>,
    vote: Arc<Mutex<Option<Vote<u64>>>>,
    log: Arc<Mutex<LogData>>,
    sm: Arc<Mutex<Sm>>,
}

fn io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn write_synced(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    write_private(&tmp, text).map_err(io)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, path)
}

impl Store {
    /// Opens (or creates) the store in `dir`: vote.json, log.jsonl, purged.json, snapshot.json. `None` keeps it in memory.
    pub fn open(ctl: Arc<Mutex<Control>>, dir: Option<PathBuf>) -> Result<Store, String> {
        let s = Store { ctl, dir: dir.clone(), vote: Default::default(), log: Default::default(), sm: Default::default() };
        let Some(d) = dir else { return Ok(s) };
        std::fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        let read = |n: &str| std::fs::read_to_string(d.join(n)).ok();
        if let Some(v) = read("vote.json") {
            *s.vote.lock().unwrap() = serde_json::from_str(&v).map_err(|e| format!("vote.json: {e}"))?;
        }
        if let Some(t) = read("snapshot.json") {
            let f: SnapFile = serde_json::from_str(&t).map_err(|e| format!("snapshot.json: {e}"))?;
            let st: State = serde_json::from_slice(&f.data).map_err(|e| format!("snapshot.json state: {e}"))?;
            s.ctl.lock().unwrap().state = st;
            let mut sm = s.sm.lock().unwrap();
            sm.last_applied = f.meta.last_log_id;
            sm.membership = f.meta.last_membership.clone();
            sm.snapshot = Some(f);
        }
        let mut lg = s.log.lock().unwrap();
        if let Some(p) = read("purged.json") {
            lg.last_purged = serde_json::from_str(&p).map_err(|e| format!("purged.json: {e}"))?;
        }
        for (i, line) in read("log.jsonl").unwrap_or_default().lines().enumerate() {
            if line.trim().is_empty() { continue; }
            // a torn last line (crash mid-append, never fsynced, so never acknowledged) is dropped
            let Ok(e) = serde_json::from_str::<REntry>(line) else {
                eprintln!("raft: log.jsonl line {} unreadable, dropped with the rest", i + 1);
                break;
            };
            lg.log.insert(e.log_id.index, e);
        }
        drop(lg);
        Ok(s)
    }

    fn rewrite_log(&self, lg: &LogData) -> std::io::Result<()> {
        let Some(d) = &self.dir else { return Ok(()) };
        let mut text = String::new();
        for e in lg.log.values() {
            text += &serde_json::to_string(e).map_err(io)?;
            text.push('\n');
        }
        write_synced(&d.join("log.jsonl"), &text)?;
        write_synced(&d.join("purged.json"), &serde_json::to_string(&lg.last_purged).map_err(io)?)
    }

    fn save_snapshot(&self, f: &SnapFile) -> std::io::Result<()> {
        let Some(d) = &self.dir else { return Ok(()) };
        write_synced(&d.join("snapshot.json"), &serde_json::to_string(f).map_err(io)?)
    }
}

fn read_range<RB: RangeBounds<u64>>(log: &Arc<Mutex<LogData>>, range: RB) -> Vec<REntry> {
    log.lock().unwrap().log.range(range).map(|(_, e)| e.clone()).collect()
}

pub struct LogReader(Arc<Mutex<LogData>>);

impl RaftLogReader<TC> for LogReader {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + openraft::OptionalSend>(&mut self, range: RB) -> Result<Vec<REntry>, SErr> {
        Ok(read_range(&self.0, range))
    }
}

impl RaftLogReader<TC> for Store {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + openraft::OptionalSend>(&mut self, range: RB) -> Result<Vec<REntry>, SErr> {
        Ok(read_range(&self.log, range))
    }
}

impl RaftSnapshotBuilder<TC> for Store {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TC>, SErr> {
        let f = {
            let mut sm = self.sm.lock().unwrap();
            let data = serde_json::to_vec(&self.ctl.lock().unwrap().state).map_err(|e| StorageIOError::read_state_machine(&io(e)))?;
            sm.snap_seq += 1;
            let snapshot_id = match sm.last_applied {
                Some(l) => format!("{}-{}-{}", l.leader_id, l.index, sm.snap_seq),
                None => format!("--{}", sm.snap_seq),
            };
            let f = SnapFile { meta: SnapshotMeta { last_log_id: sm.last_applied, last_membership: sm.membership.clone(), snapshot_id }, data };
            sm.snapshot = Some(f.clone());
            f
        };
        self.save_snapshot(&f).map_err(|e| StorageIOError::write_snapshot(Some(f.meta.signature()), &e))?;
        Ok(Snapshot { meta: f.meta, snapshot: Box::new(Cursor::new(f.data)) })
    }
}

impl RaftStorage<TC> for Store {
    type LogReader = LogReader;
    type SnapshotBuilder = Store;

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), SErr> {
        if let Some(d) = &self.dir {
            let t = serde_json::to_string(vote).map_err(|e| StorageIOError::write_vote(&io(e)))?;
            write_synced(&d.join("vote.json"), &t).map_err(|e| StorageIOError::write_vote(&e))?;
        }
        *self.vote.lock().unwrap() = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, SErr> {
        Ok(*self.vote.lock().unwrap())
    }

    async fn get_log_state(&mut self) -> Result<LogState<TC>, SErr> {
        let lg = self.log.lock().unwrap();
        let last = lg.log.values().next_back().map(|e| e.log_id).or(lg.last_purged);
        Ok(LogState { last_purged_log_id: lg.last_purged, last_log_id: last })
    }

    async fn get_log_reader(&mut self) -> LogReader {
        LogReader(self.log.clone())
    }

    async fn append_to_log<I>(&mut self, entries: I) -> Result<(), SErr>
    where I: IntoIterator<Item = REntry> + openraft::OptionalSend {
        let mut lg = self.log.lock().unwrap();
        let mut text = String::new();
        let mut new = Vec::new();
        for e in entries {
            text += &serde_json::to_string(&e).map_err(|x| StorageIOError::write_logs(&io(x)))?;
            text.push('\n');
            new.push(e);
        }
        if let Some(d) = &self.dir {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new().append(true).create(true).mode(0o600).open(d.join("log.jsonl"))
                .map_err(|e| StorageIOError::write_logs(&e))?;
            f.write_all(text.as_bytes()).and_then(|_| f.sync_data()).map_err(|e| StorageIOError::write_logs(&e))?;
        }
        for e in new {
            lg.log.insert(e.log_id.index, e);
        }
        Ok(())
    }

    async fn delete_conflict_logs_since(&mut self, log_id: LogId<u64>) -> Result<(), SErr> {
        let mut lg = self.log.lock().unwrap();
        lg.log.split_off(&log_id.index);
        self.rewrite_log(&lg).map_err(|e| StorageIOError::write_logs(&e))?;
        Ok(())
    }

    async fn purge_logs_upto(&mut self, log_id: LogId<u64>) -> Result<(), SErr> {
        let mut lg = self.log.lock().unwrap();
        lg.log = lg.log.split_off(&(log_id.index + 1));
        lg.last_purged = Some(log_id);
        self.rewrite_log(&lg).map_err(|e| StorageIOError::write_logs(&e))?;
        Ok(())
    }

    async fn last_applied_state(&mut self) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), SErr> {
        let sm = self.sm.lock().unwrap();
        Ok((sm.last_applied, sm.membership.clone()))
    }

    async fn apply_to_state_machine(&mut self, entries: &[REntry]) -> Result<Vec<Response>, SErr> {
        let mut sm = self.sm.lock().unwrap();
        let mut ctl = self.ctl.lock().unwrap();
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            sm.last_applied = Some(e.log_id);
            out.push(match &e.payload {
                EntryPayload::Blank => Response::default(),
                EntryPayload::Normal(Cmd::Call(x)) => ctl.apply(&x.req, x.now, x.cap_ok),
                EntryPayload::Normal(Cmd::Seed(st)) => {
                    let empty = ctl.state.nodes.is_empty() && ctl.state.last_ts.is_empty();
                    if empty {
                        ctl.state = st.clone();
                    }
                    Response { ok: empty, err: if empty { String::new() } else { "seed skipped: state not empty".into() }, ..Default::default() }
                }
                EntryPayload::Membership(m) => {
                    sm.membership = StoredMembership::new(Some(e.log_id), m.clone());
                    Response::default()
                }
            });
        }
        Ok(out)
    }

    async fn get_snapshot_builder(&mut self) -> Store {
        self.clone()
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Cursor<Vec<u8>>>, SErr> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(&mut self, meta: &SnapshotMeta<u64, BasicNode>, snapshot: Box<Cursor<Vec<u8>>>) -> Result<(), SErr> {
        let f = SnapFile { meta: meta.clone(), data: snapshot.into_inner() };
        let st: State = serde_json::from_slice(&f.data).map_err(|e| StorageIOError::read_snapshot(Some(meta.signature()), &io(e)))?;
        {
            let mut sm = self.sm.lock().unwrap();
            self.ctl.lock().unwrap().state = st;
            sm.last_applied = meta.last_log_id;
            sm.membership = meta.last_membership.clone();
            sm.snapshot = Some(f.clone());
        }
        self.save_snapshot(&f).map_err(|e| StorageIOError::write_snapshot(Some(meta.signature()), &e))?;
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<TC>>, SErr> {
        Ok(self.sm.lock().unwrap().snapshot.clone().map(|f| Snapshot { meta: f.meta, snapshot: Box::new(Cursor::new(f.data)) }))
    }
}

// ---------- network ----------

#[derive(Clone)]
pub struct Net {
    secret: Arc<[u8; 32]>,
}

pub struct PeerConn {
    target: u64,
    link: Link,
}

impl RaftNetworkFactory<TC> for Net {
    type Network = PeerConn;
    async fn new_client(&mut self, target: u64, node: &BasicNode) -> PeerConn {
        PeerConn { target, link: Link::new(node.addr.clone(), self.secret.clone()) }
    }
}

enum CallErr {
    Connect(std::io::Error),
    Other(std::io::Error),
    /// the peer answered with a (MAC'd) refusal, e.g. "not leader"; the link stays up
    Refused(String),
}

struct Job {
    op: String,
    body: String,
    reply: tokio::sync::oneshot::Sender<Result<String, CallErr>>,
}

/// One persistent, MAC'd connection to a peer's raft port, owned by its own task (an actor) that is never cancelled.
/// openraft cancels an append_entries at one heartbeat interval; a cancelled caller only drops its reply slot, the
/// actor still reads that frame's reply in order, so the link stays in step and up. A frame nobody waits for any more is
/// skipped before it is sent. On a transport error the link reconnects (once at once if it was a reused connection).
/// The actor ends when the last `Link` handle is dropped.
pub struct Link {
    tx: tokio::sync::mpsc::Sender<Job>,
}

impl Link {
    fn new(addr: String, secret: Arc<[u8; 32]>) -> Link {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(link_actor(addr, secret, rx));
        Link { tx }
    }

    async fn call(&self, op: &str, body: &str) -> Result<String, CallErr> {
        self.call_within(op, body, RPC_TIMEOUT).await
    }

    async fn call_within(&self, op: &str, body: &str, wait: Duration) -> Result<String, CallErr> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.tx.send(Job { op: op.into(), body: body.into(), reply }).await.map_err(|_| CallErr::Other(io("raft link closed")))?;
        match tokio::time::timeout(wait, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(CallErr::Other(io("raft link dropped the call"))),
            Err(_) => Err(CallErr::Other(io("raft rpc timeout"))),
        }
    }
}

async fn link_actor(addr: String, secret: Arc<[u8; 32]>, mut rx: tokio::sync::mpsc::Receiver<Job>) {
    let mut conn: Option<BufReader<TcpStream>> = None;
    let mut seq = 0u64;
    while let Some(job) = rx.recv().await {
        let mut tries = 0;
        let r = loop {
            if job.reply.is_closed() {
                break None;
            }
            let reused = conn.is_some();
            if conn.is_none() {
                match tokio::time::timeout(RPC_TIMEOUT, TcpStream::connect(&addr)).await {
                    Ok(Ok(s)) => {
                        let _ = s.set_nodelay(true);
                        conn = Some(BufReader::new(s));
                        seq = 0;
                    }
                    Ok(Err(e)) => break Some(Err(CallErr::Connect(e))),
                    Err(_) => break Some(Err(CallErr::Connect(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")))),
                }
            }
            seq += 1;
            let c = conn.as_mut().unwrap();
            let r = tokio::time::timeout(LINK_FRAME_MAX, frame(c, &secret, seq, &job.op, &job.body)).await
                .unwrap_or_else(|_| Err(CallErr::Other(io("raft frame timeout"))));
            match r {
                Err(CallErr::Other(e)) => {
                    conn = None;
                    tries += 1;
                    if reused && tries == 1 {
                        continue; // the peer closed a reused connection (it restarted): one fresh try at once
                    }
                    break Some(Err(CallErr::Other(e)));
                }
                other => break Some(other),
            }
        };
        if let Some(r) = r {
            let _ = job.reply.send(r);
        }
    }
}

async fn frame(r: &mut BufReader<TcpStream>, secret: &[u8; 32], seq: u64, op: &str, body: &str) -> Result<String, CallErr> {
    let mut line = serde_json::to_string(&RaftMsg::with_seq(secret, op, seq, body.to_string())).unwrap();
    line.push('\n');
    r.get_mut().write_all(line.as_bytes()).await.map_err(CallErr::Other)?;
    let mut out = String::new();
    if (&mut *r).take(RAFT_LINE_MAX).read_line(&mut out).await.map_err(CallErr::Other)? == 0 {
        return Err(CallErr::Other(io("raft peer closed the connection")));
    }
    let rep: RaftReply = serde_json::from_str(&out).map_err(|e| CallErr::Other(io(format!("bad raft reply: {e}"))))?;
    if !rep.mac_ok(secret) {
        // a refusal of our own MAC comes back unsigned; anything else unsigned is not from the peer
        return Err(CallErr::Other(io(if rep.err.is_empty() { "bad reply mac".into() } else { format!("raft peer refused: {}", rep.err) })));
    }
    if rep.seq != seq {
        return Err(CallErr::Other(io(format!("reply seq {} for frame {seq}", rep.seq))));
    }
    if !rep.err.is_empty() {
        return Err(CallErr::Refused(rep.err));
    }
    Ok(rep.body)
}

impl PeerConn {
    async fn rpc<Q: Serialize, T: for<'de> Deserialize<'de>, E: std::error::Error + for<'de> Deserialize<'de>>(
        &self, op: &str, req: &Q,
    ) -> Result<T, RPCError<u64, BasicNode, E>> {
        let body = serde_json::to_string(req).map_err(|e| RPCError::Network(NetworkError::new(&io(e))))?;
        let out = self.link.call(op, &body).await.map_err(|e| match e {
            CallErr::Connect(e) => RPCError::Unreachable(Unreachable::new(&e)),
            CallErr::Other(e) => RPCError::Network(NetworkError::new(&e)),
            CallErr::Refused(e) => RPCError::Network(NetworkError::new(&io(format!("raft peer refused: {e}")))),
        })?;
        let r: Result<T, E> = serde_json::from_str(&out).map_err(|e| RPCError::Network(NetworkError::new(&io(e))))?;
        r.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

impl RaftNetwork<TC> for PeerConn {
    async fn append_entries(&mut self, rpc: AppendEntriesRequest<TC>, _o: RPCOption)
        -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        self.rpc("append_entries", &rpc).await
    }

    async fn install_snapshot(&mut self, rpc: InstallSnapshotRequest<TC>, _o: RPCOption)
        -> Result<InstallSnapshotResponse<u64>, RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>> {
        self.rpc("install_snapshot", &rpc).await
    }

    async fn vote(&mut self, rpc: VoteRequest<u64>, _o: RPCOption)
        -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        self.rpc("vote", &rpc).await
    }
}

// ---------- one replica ----------

/// Raft timings in ms. openraft 0.9 times an append_entries RPC out after one heartbeat interval
/// (replication/mod.rs:455), so the heartbeat must exceed the slowest replica's RPC: one frame on a persistent link over a
/// long-haul WAN path is one round trip, ~265 ms (a fresh connect adds ~256 ms; measured with 1000 / 3000-6000 ms in a
/// kill-one-replica test). `wan()` is the default; `lan()` for tests.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub heartbeat: u64,
    pub election_min: u64,
    pub election_max: u64,
}

impl Timing {
    pub fn wan() -> Timing { Timing { heartbeat: 500, election_min: 1500, election_max: 3000 } }
    pub fn lan() -> Timing { Timing { heartbeat: 100, election_min: 300, election_max: 600 } }
    /// how long a client call waits for a leader before it gives up: two elections and a margin
    fn leader_wait(&self) -> Duration { Duration::from_millis(2 * self.election_max + 2000) }
}

impl Default for Timing {
    fn default() -> Timing { Timing::wan() }
}

pub struct Opts {
    pub id: u64,
    pub secret: [u8; 32],
    /// None keeps the log in memory (tests)
    pub dir: Option<PathBuf>,
    /// Some(members) on the one node that initializes the cluster, once; a repeat on restart is ignored
    pub init: Option<BTreeMap<u64, String>>,
    /// with `init`, a pre-Raft state to commit as the first entry (only when this call initialized the cluster)
    pub seed: Option<State>,
    pub timing: Timing,
    /// trigger an election when the leader's raft port refuses a forward (see `elect_soon`); off = openraft's own timer
    pub fast_elect: bool,
}

struct Shared {
    id: u64,
    raft: Raft,
    ctl: Arc<Mutex<Control>>,
    secret: [u8; 32],
    leader_wait: Duration,
    /// follower -> leader links for the forward op, one per leader address
    forward: Mutex<BTreeMap<String, Arc<Link>>>,
    /// when this replica last triggered an election because the leader's raft port refused a connection
    last_elect: Mutex<Option<std::time::Instant>>,
    fast_elect: bool,
    /// flips to true at `Replica::stop`: every open peer and client connection ends, as when the process dies
    stop: tokio::sync::watch::Receiver<bool>,
}

pub struct Replica {
    pub id: u64,
    pub raft: Raft,
    pub ctl: Arc<Mutex<Control>>,
    tasks: Vec<JoinHandle<()>>,
    stop: tokio::sync::watch::Sender<bool>,
}

pub fn config(t: Timing) -> Config {
    Config {
        cluster_name: "net.mesh".into(),
        election_timeout_min: t.election_min,
        election_timeout_max: t.election_max,
        heartbeat_interval: t.heartbeat,
        ..Default::default()
    }
}

/// Refuse a wildcard bind, the same rule as --listen: a host is closed by default.
pub fn check_bind(addr: &str) -> Result<(), String> {
    if addr.starts_with("0.0.0.0") || addr.starts_with("[::]") {
        return Err(format!("refusing to bind {addr}: a host is closed by default (bind 127.0.0.1 or a mesh address)"));
    }
    Ok(())
}

impl Replica {
    /// Starts a replica on two bound listeners: `raft_l` for peers, `client_l` for nodes (the control port).
    /// `control.state_path` should be None: the state lives in the Raft store and its snapshot.
    pub async fn start(opts: Opts, control: Control, raft_l: TcpListener, client_l: TcpListener) -> Result<Replica, String> {
        let ctl = Arc::new(Mutex::new(control));
        let store = Store::open(ctl.clone(), opts.dir.clone())?;
        let (log_store, sm) = Adaptor::new(store);
        let cfg = Arc::new(config(opts.timing).validate().map_err(|e| e.to_string())?);
        let raft = Raft::new(opts.id, cfg, Net { secret: Arc::new(opts.secret) }, log_store, sm).await.map_err(|e| e.to_string())?;
        let mut fresh = false;
        if let Some(members) = &opts.init {
            let nodes: BTreeMap<u64, BasicNode> = members.iter().map(|(k, a)| (*k, BasicNode { addr: a.clone() })).collect();
            match raft.initialize(nodes).await {
                Ok(()) => fresh = true,
                Err(e) => eprintln!("raft: initialize skipped: {e}"),
            }
        }
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let sh = Arc::new(Shared { id: opts.id, raft: raft.clone(), ctl: ctl.clone(), secret: opts.secret, leader_wait: opts.timing.leader_wait(), forward: Default::default(), last_elect: Default::default(), fast_elect: opts.fast_elect, stop: stop_rx });
        let s1 = sh.clone();
        let t1 = tokio::spawn(async move {
            loop {
                let Ok((s, _)) = raft_l.accept().await else { continue };
                let sh = s1.clone();
                tokio::spawn(async move { let _ = serve_raft(sh, s).await; });
            }
        });
        // the seed goes in before the client port opens, so no registration can land ahead of it
        if let (true, Some(st)) = (fresh, opts.seed) {
            let n = st.nodes.len();
            // waits for a quorum (the other replicas may start later), at most SEED_WAIT; never forever
            let w = tokio::time::timeout(SEED_WAIT, async {
                let mut tries = 0u64;
                loop {
                    match raft.client_write(Cmd::Seed(st.clone())).await {
                        Err(RaftError::APIError(ClientWriteError::ForwardToLeader(_))) => {
                            tries += 1;
                            if tries % 200 == 0 {
                                eprintln!("raft: seed waiting for a quorum ({} s)", tries / 10);
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await
                        }
                        other => return other.map(|w| w.data).map_err(|e| e.to_string()),
                    }
                }
            }).await;
            match w {
                Ok(Ok(r)) if r.ok => eprintln!("raft: seeded {n} nodes from the pre-Raft state"),
                Ok(Ok(r)) => eprintln!("raft: seed not applied: {}", r.err),
                Ok(Err(e)) => eprintln!("raft: seed failed: {e}"),
                Err(_) => eprintln!("raft: seed timed out after {} s (no quorum); the state starts empty", SEED_WAIT.as_secs()),
            }
        }
        let s2 = sh.clone();
        let t2 = tokio::spawn(async move {
            loop {
                let Ok((s, peer)) = client_l.accept().await else { continue };
                let sh = s2.clone();
                tokio::spawn(async move { let _ = serve_client(sh, s, peer.to_string()).await; });
            }
        });
        Ok(Replica { id: opts.id, raft, ctl, tasks: vec![t1, t2], stop: stop_tx })
    }

    /// Stops this replica: both ports close and Raft shuts down (what a killed process looks like to its peers).
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        for t in &self.tasks {
            t.abort();
        }
        for t in self.tasks {
            let _ = t.await;
        }
        let _ = self.raft.shutdown().await;
    }
}

async fn read_line_max(s: &mut TcpStream, max: u64) -> std::io::Result<String> {
    let mut line = String::new();
    let mut r = BufReader::new(&mut *s).take(max);
    tokio::time::timeout(Duration::from_secs(10), r.read_line(&mut line)).await.map_err(io)??;
    Ok(line)
}

/// A peer link: frames until the peer closes, a frame fails its MAC or seq, or RAFT_IDLE passes with nothing.
async fn serve_raft(sh: Arc<Shared>, s: TcpStream) -> std::io::Result<()> {
    let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    s.set_nodelay(true)?;
    let mut r = BufReader::new(s);
    let mut last = 0u64;
    loop {
        let mut line = String::new();
        let mut stop = sh.stop.clone();
        let mut lim = (&mut r).take(RAFT_LINE_MAX);
        let n = tokio::select! {
            n = tokio::time::timeout(RAFT_IDLE, lim.read_line(&mut line)) => n.map_err(io)??,
            _ = stop.wait_for(|s| *s) => return Ok(()),
        };
        if n == 0 {
            return Ok(());
        }
        let (reply, close) = match serde_json::from_str::<RaftMsg>(&line) {
            Err(e) => (RaftReply { err: format!("bad message: {e}"), ..Default::default() }, true),
            Ok(m) if !mac_ok(&sh.secret, format!("{}\n{}\n{}", m.op, m.seq, m.body).as_bytes(), &m.mac) => {
                eprintln!("raft: refused a frame with a bad mac from {peer}");
                (RaftReply { err: "bad mac".into(), ..Default::default() }, true)
            }
            Ok(m) if m.seq <= last => {
                eprintln!("raft: refused a replayed frame (seq {} after {last}) from {peer}", m.seq);
                (RaftReply::signed(&sh.secret, m.seq, String::new(), "replay".into()), true)
            }
            Ok(m) => {
                last = m.seq;
                match raft_op(&sh, &m.op, &m.body).await {
                    Ok(body) => (RaftReply::signed(&sh.secret, m.seq, body, String::new()), false),
                    Err(e) => (RaftReply::signed(&sh.secret, m.seq, String::new(), e), false),
                }
            }
        };
        r.get_mut().write_all((serde_json::to_string(&reply).unwrap() + "\n").as_bytes()).await?;
        if close {
            return Ok(());
        }
    }
}

async fn raft_op(sh: &Shared, op: &str, body: &str) -> Result<String, String> {
    let j = |e: serde_json::Error| e.to_string();
    Ok(match op {
        "append_entries" => serde_json::to_string(&sh.raft.append_entries(serde_json::from_str(body).map_err(j)?).await),
        "vote" => serde_json::to_string(&sh.raft.vote(serde_json::from_str(body).map_err(j)?).await),
        "install_snapshot" => serde_json::to_string(&sh.raft.install_snapshot(serde_json::from_str(body).map_err(j)?).await),
        "forward" => {
            let req: Request = serde_json::from_str(body).map_err(j)?;
            match as_leader(sh, req).await {
                Some(r) => serde_json::to_string(&r),
                None => return Err(NOT_LEADER.into()),
            }
        }
        _ => return Err(format!("unknown op {op}")),
    }
    .map_err(j)?)
}

const NOT_LEADER: &str = "not leader";

fn refuse(e: &str) -> Response {
    Response { ok: false, err: e.into(), ..Default::default() }
}

/// The leader path: precheck (blocking: it may run the capability-verifier subprocess), commit, reply with apply's Response.
/// None when this replica is not (or stops being) the leader, so the caller retries at the current one.
async fn as_leader(sh: &Shared, req: Request) -> Option<Response> {
    let now = crate::now();
    let ctl = sh.ctl.clone();
    let r2 = req.clone();
    let pre = tokio::task::spawn_blocking(move || ctl.lock().unwrap().precheck(&r2, now)).await;
    let cap_ok = match pre {
        Ok(Ok(c)) => c,
        Ok(Err(r)) => return Some(r),
        Err(e) => return Some(refuse(&format!("precheck failed: {e}"))),
    };
    // bounded: a leader that has lost its quorum (acks never arrive) must answer, not hang the client
    match tokio::time::timeout(sh.leader_wait, sh.raft.client_write(Cmd::Call(Entry { req, now, cap_ok }))).await {
        Ok(Ok(w)) => Some(w.data),
        Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(_)))) => None,
        Ok(Err(e)) => Some(refuse(&format!("raft: {e}"))),
        Err(_) => Some(refuse("raft: commit timed out (no quorum)")),
    }
}

async fn elect_soon(sh: &Shared) {
    {
        let mut t = sh.last_elect.lock().unwrap();
        if t.is_some_and(|t| t.elapsed() < Duration::from_millis(250)) {
            return;
        }
        *t = Some(std::time::Instant::now());
    }
    eprintln!("raft: leader's raft port refused; triggering an election");
    let _ = sh.raft.trigger().elect().await;
}

fn forward_link(sh: &Shared, addr: &str) -> Arc<Link> {
    let secret = Arc::new(sh.secret);
    sh.forward.lock().unwrap().entry(addr.to_string()).or_insert_with(|| Arc::new(Link::new(addr.to_string(), secret))).clone()
}

fn leader_addr(sh: &Shared, leader: u64) -> Option<String> {
    let m = sh.raft.metrics().borrow().membership_config.clone();
    let addr = m.membership().nodes().find(|(id, _)| **id == leader).map(|(_, n)| n.addr.clone());
    addr
}

/// A client line on any replica: run it here if this is the leader, else forward it to the leader's raft port.
/// Retries for up to `Timing::leader_wait` across an election.
async fn client_request(sh: &Shared, req: Request) -> Response {
    let deadline = tokio::time::Instant::now() + sh.leader_wait;
    let mut last = String::from("no raft leader");
    loop {
        match sh.raft.current_leader().await {
            Some(l) if l == sh.id => match as_leader(sh, req.clone()).await {
                Some(r) => return r,
                None => last = NOT_LEADER.into(),
            },
            Some(l) => match leader_addr(sh, l) {
                Some(addr) => match forward_link(sh, &addr).call_within("forward", &serde_json::to_string(&req).unwrap(), sh.leader_wait).await {
                    Ok(body) => match serde_json::from_str::<Response>(&body) {
                        Ok(r) => return r,
                        Err(e) => last = format!("bad forward reply: {e}"),
                    },
                    Err(CallErr::Connect(e)) => {
                        // the leader's host answered but its raft port refused: the process is gone. Elect now rather
                        // than wait out lease + election timeout (openraft core/raft_core.rs:1476, 2 x election_max).
                        // The other voter still refuses until its lease lapses, so this is retried every 250 ms.
                        if sh.fast_elect && e.kind() == std::io::ErrorKind::ConnectionRefused {
                            elect_soon(sh).await;
                        }
                        last = format!("forward to {l}: {e}");
                    }
                    Err(CallErr::Other(e)) => last = format!("forward to {l}: {e}"),
                    Err(CallErr::Refused(e)) => last = format!("forward to {l}: {e}"),
                },
                None => last = format!("leader {l} has no address"),
            },
            None => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return refuse(&last);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn serve_client(sh: Arc<Shared>, mut s: TcpStream, peer: String) -> std::io::Result<()> {
    let line = read_line_max(&mut s, CLIENT_LINE_MAX).await?;
    let resp = match serde_json::from_str::<Request>(&line) {
        Ok(req) => {
            let (op, node) = (req.op.clone(), req.node.get(..12).unwrap_or("").to_string());
            let out = client_request(&sh, req).await;
            eprintln!("{peer} {op} {node}.. -> {}", if out.ok { "ok" } else { &out.err });
            out
        }
        Err(e) => refuse(&format!("bad request: {e}")),
    };
    s.write_all((serde_json::to_string(&resp).unwrap() + "\n").as_bytes()).await
}

/// `1=ADDR,2=ADDR,3=ADDR`
pub fn parse_peers(s: &str) -> Result<BTreeMap<u64, String>, String> {
    s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(|kv| {
        let (k, v) = kv.split_once('=').ok_or_else(|| format!("--raft-peers: want ID=ADDR, got {kv}"))?;
        Ok((k.parse().map_err(|_| format!("--raft-peers: bad id {k}"))?, v.to_string()))
    }).collect()
}
