//! `Mesh`: a node on net.mesh over the leg. The API typed RPC layers build on:
//!
//! ```ignore
//! let id = Identity::ephemeral();                     // in memory, never stored
//! let cap = backend_mints_cap(&id.node_id(), "demo.echo").await;    // the app's logged-in backend
//! let mesh = Mesh::connect("wss://relay.example.com/v1/leg", &id, "demo.echo", &cap).await?;
//! let mut s = mesh.dial_cell("demo.echo").await?;     // duplex bytes; any protocol runs on it
//! ```
//!
//! The leg server resolves the cell named at connect and answers its address in the `ok` line; that is the only
//! place a 10.77 address comes from, so the page never hardcodes one. Other names resolve through a
//! `CellDirectory` the app passes with `with_cells` (later: netmesh-control names).

use crate::hello::{Admitted, Identity, TabHello, LEG_PROTO, unix_now};
use crate::leg::{self, Frame};
use crate::node::Node;
use crate::rt;
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, StreamExt};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

const DOOR_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_S: u16 = 25;

#[derive(Debug, Clone, PartialEq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(s: String) -> Error {
        Error(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Error {
        Error(s.into())
    }
}

/// cell (service) name -> 10.77 addr:port
pub trait CellDirectory: Send + Sync {
    fn resolve(&self, name: &str) -> Option<SocketAddrV4>;
}

impl CellDirectory for HashMap<String, SocketAddrV4> {
    fn resolve(&self, name: &str) -> Option<SocketAddrV4> {
        self.get(name).copied()
    }
}

struct Shared {
    node: Mutex<Node>,
    kick: mpsc::UnboundedSender<()>,
    dead: Mutex<Option<String>>,
}

impl Shared {
    fn kick(&self) {
        let _ = self.kick.unbounded_send(());
    }

    fn dead(&self) -> Option<String> {
        self.dead.lock().unwrap().clone()
    }
}

pub struct Mesh {
    shared: Arc<Shared>,
    admitted: Admitted,
    cell: String,
    cells: Option<Box<dyn CellDirectory>>,
    leg_tx: mpsc::UnboundedSender<Frame>,
}

async fn next_text(rx: &mut mpsc::UnboundedReceiver<Frame>, what: &str) -> Result<String, Error> {
    let f = futures::select_biased! {
        f = rx.next() => f,
        _ = rt::sleep(DOOR_TIMEOUT).fuse() => return Err(format!("leg: no {what} in {} s", DOOR_TIMEOUT.as_secs()).into()),
    };
    match f {
        Some(Frame::Text(t)) => Ok(t),
        Some(Frame::Closed(why)) => Err(format!("leg closed before {what}: {why}").into()),
        Some(Frame::Binary(_)) => Err(format!("leg: binary frame before {what}").into()),
        None => Err(format!("leg gone before {what}").into()),
    }
}

impl Mesh {
    /// Open the leg, pass the door with a hello signed by `id` carrying `cap` for `cell`, then finish the WireGuard
    /// handshake with the leg's server. Returns once the tunnel carries packets.
    pub async fn connect(leg_url: &str, id: &Identity, cell: &str, cap: &str) -> Result<Mesh, Error> {
        let mut leg = leg::open(leg_url).await?;
        let ch = next_text(&mut leg.rx, "challenge").await?;
        let nonce = ch.strip_prefix(LEG_PROTO).map(|n| n.trim().to_string()).ok_or_else(|| Error(format!("leg: bad challenge {ch:?}")))?;
        let hello = TabHello::signed(id, &nonce, cell, cap, unix_now());
        let _ = leg.tx.unbounded_send(Frame::Text(serde_json::to_string(&hello).unwrap()));
        let answer = next_text(&mut leg.rx, "answer to hello").await?;
        let admitted = Admitted::parse(&answer).map_err(|e| Error(format!("leg door: {e}")))?;

        let peer = boringtun::x25519::PublicKey::from(admitted.server_wg);
        let mut node = Node::new(id.wg.clone(), peer, admitted.addr, Some(KEEPALIVE_S));
        node.handshake();
        let (kick_tx, kick_rx) = mpsc::unbounded();
        let shared = Arc::new(Shared { node: Mutex::new(node), kick: kick_tx, dead: Mutex::new(None) });
        let (up_tx, up_rx) = oneshot::channel();
        rt::spawn(drive(shared.clone(), leg.rx, leg.tx.clone(), kick_rx, up_tx));
        let up = futures::select_biased! {
            r = up_rx.fuse() => r.map_err(|_| Error(shared.dead().unwrap_or_else(|| "leg gone".into()))),
            _ = rt::sleep(HANDSHAKE_TIMEOUT).fuse() => Err(Error(format!("WireGuard handshake: no answer in {} s", HANDSHAKE_TIMEOUT.as_secs()))),
        };
        if let Err(e) = up {
            let _ = leg.tx.unbounded_send(Frame::Closed("handshake failed".into()));
            return Err(e);
        }
        Ok(Mesh { shared, admitted, cell: cell.to_string(), cells: None, leg_tx: leg.tx })
    }

    /// more names than the connected cell (static map now, netmesh-control names later)
    pub fn with_cells(mut self, cells: impl CellDirectory + 'static) -> Mesh {
        self.cells = Some(Box::new(cells));
        self
    }

    /// this node's 10.77 address (handed out by the leg server)
    pub fn addr(&self) -> Ipv4Addr {
        self.admitted.addr
    }

    /// set when the leg or the tunnel died; every stream then reads EOF or fails
    pub fn closed(&self) -> Option<String> {
        self.shared.dead()
    }

    pub fn resolve(&self, name: &str) -> Option<SocketAddrV4> {
        if name == self.cell {
            return Some(self.admitted.cell);
        }
        self.cells.as_ref().and_then(|c| c.resolve(name))
    }

    /// a duplex byte stream to the cell by name; any byte protocol runs on it unchanged
    pub async fn dial_cell(&self, name: &str) -> Result<Stream, Error> {
        let at = self.resolve(name).ok_or_else(|| Error(format!("no address for cell {name:?}")))?;
        self.dial_tcp(at).await
    }

    pub async fn dial_tcp(&self, dst: SocketAddrV4) -> Result<Stream, Error> {
        if let Some(d) = self.shared.dead() {
            return Err(Error(format!("mesh closed: {d}")));
        }
        let h = self.shared.node.lock().unwrap().tcp_connect(dst)?;
        self.shared.kick();
        let s = Stream { shared: self.shared.clone(), h, peer: dst, closed: false };
        let est = futures::future::poll_fn(|cx| s.poll_established(cx));
        futures::select_biased! {
            r = est.fuse() => r.map_err(|e| Error(format!("dial {dst}: {e}")))?,
            _ = rt::sleep(DIAL_TIMEOUT).fuse() => return Err(Error(format!("dial {dst}: no answer in {} s", DIAL_TIMEOUT.as_secs()))),
        }
        Ok(s)
    }

    /// a UDP socket on the mesh (`port` 0 picks one)
    pub fn udp(&self, port: u16) -> Result<Datagrams, Error> {
        let h = self.shared.node.lock().unwrap().udp_bind(port)?;
        Ok(Datagrams { shared: self.shared.clone(), h })
    }

    /// close the leg; the server drops the peer
    pub fn close(&self) {
        let _ = self.leg_tx.unbounded_send(Frame::Closed("closed by client".into()));
    }
}

impl Drop for Mesh {
    fn drop(&mut self) {
        self.close();
    }
}

/// the one task that moves packets: leg frames in, timers, the IP stack, leg frames out
async fn drive(
    shared: Arc<Shared>,
    mut rx: mpsc::UnboundedReceiver<Frame>,
    tx: mpsc::UnboundedSender<Frame>,
    mut kick: mpsc::UnboundedReceiver<()>,
    up: oneshot::Sender<()>,
) {
    let mut up = Some(up);
    let why = loop {
        let delay = {
            let mut n = shared.node.lock().unwrap();
            let d = n.poll();
            for b in leg::batches(n.take_out()) {
                let _ = tx.unbounded_send(Frame::Binary(b));
            }
            if n.is_up() {
                if let Some(u) = up.take() {
                    let _ = u.send(());
                }
            }
            d
        };
        futures::select_biased! {
            f = rx.next() => match f {
                Some(Frame::Binary(b)) => {
                    let mut n = shared.node.lock().unwrap();
                    for p in leg::unpack(&b) {
                        n.input(p);
                    }
                }
                Some(Frame::Text(_)) => {} // e.g. `udp2 ...` from a split-mode server; the tab rides the leg only
                Some(Frame::Closed(why)) => break why,
                None => break "leg gone".to_string(),
            },
            k = kick.next() => if k.is_none() { break "mesh dropped".to_string() },
            _ = rt::sleep(delay).fuse() => {}
        }
    };
    *shared.dead.lock().unwrap() = Some(why);
    let mut n = shared.node.lock().unwrap();
    n.abort_all();
    n.poll();
    let _ = tx.unbounded_send(Frame::Closed("driver done".into()));
}

/// a TCP connection over the mesh: futures-io AsyncRead/AsyncWrite everywhere, tokio's natively
pub struct Stream {
    shared: Arc<Shared>,
    h: SocketHandle,
    peer: SocketAddrV4,
    closed: bool,
}

fn dead_err(d: &str) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, format!("mesh closed: {d}"))
}

impl Stream {
    pub fn peer(&self) -> SocketAddrV4 {
        self.peer
    }

    fn poll_established(&self, cx: &mut Context<'_>) -> Poll<Result<(), String>> {
        let mut n = self.shared.node.lock().unwrap();
        let s = n.tcp(self.h);
        match s.state() {
            tcp::State::Established => Poll::Ready(Ok(())),
            tcp::State::SynSent | tcp::State::SynReceived => {
                s.register_send_waker(cx.waker());
                drop(n);
                match self.shared.dead() {
                    Some(d) => Poll::Ready(Err(format!("mesh closed: {d}"))),
                    None => Poll::Pending,
                }
            }
            st => Poll::Ready(Err(format!("refused ({st})"))),
        }
    }

    fn read_inner(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut n = self.shared.node.lock().unwrap();
        let s = n.tcp(self.h);
        if s.can_recv() {
            let r = s.recv_slice(buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));
            drop(n);
            self.shared.kick(); // window update
            return Poll::Ready(r);
        }
        if !s.may_recv() {
            return Poll::Ready(match s.state() {
                tcp::State::Closed if self.shared.dead().is_some() => Err(dead_err(&self.shared.dead().unwrap())),
                _ => Ok(0),
            });
        }
        s.register_recv_waker(cx.waker());
        Poll::Pending
    }

    fn write_inner(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut n = self.shared.node.lock().unwrap();
        let s = n.tcp(self.h);
        if !s.may_send() {
            drop(n);
            return Poll::Ready(Err(match self.shared.dead() {
                Some(d) => dead_err(&d),
                None => io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"),
            }));
        }
        if s.can_send() {
            let r = s.send_slice(buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));
            drop(n);
            self.shared.kick();
            return Poll::Ready(r);
        }
        s.register_send_waker(cx.waker());
        Poll::Pending
    }

    /// done once everything written is acknowledged
    fn flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut n = self.shared.node.lock().unwrap();
        let s = n.tcp(self.h);
        if s.send_queue() == 0 || !s.may_send() {
            return Poll::Ready(Ok(()));
        }
        s.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn close_inner(&mut self) {
        if !self.closed {
            self.closed = true;
            self.shared.node.lock().unwrap().close_tcp(self.h);
            self.shared.kick();
        }
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        futures::future::poll_fn(|cx| self.read_inner(cx, buf)).await
    }

    pub async fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = futures::future::poll_fn(|cx| self.write_inner(cx, buf)).await?;
            buf = &buf[n..];
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        futures::future::poll_fn(|cx| self.flush_inner(cx)).await
    }

    /// send FIN; reads go on until the peer closes
    pub fn close(&mut self) {
        self.close_inner();
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.close_inner();
    }
}

impl futures::io::AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.get_mut().read_inner(cx, buf)
    }
}

impl futures::io::AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().write_inner(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush_inner(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.close_inner();
        me.flush_inner(cx)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl tokio::io::AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.read_inner(cx, buf.initialize_unfilled()) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl tokio::io::AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().write_inner(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush_inner(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.close_inner();
        me.flush_inner(cx)
    }
}

/// a UDP socket on the mesh
pub struct Datagrams {
    shared: Arc<Shared>,
    h: SocketHandle,
}

impl Datagrams {
    pub async fn send_to(&self, buf: &[u8], to: SocketAddrV4) -> io::Result<()> {
        let ep = IpEndpoint::new(IpAddress::Ipv4(*to.ip()), to.port());
        futures::future::poll_fn(|cx| {
            let mut n = self.shared.node.lock().unwrap();
            let s = n.udp(self.h);
            if s.can_send() {
                let r = s.send_slice(buf, ep).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));
                drop(n);
                self.shared.kick();
                return Poll::Ready(r);
            }
            s.register_send_waker(cx.waker());
            Poll::Pending
        })
        .await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        futures::future::poll_fn(|cx| {
            let mut n = self.shared.node.lock().unwrap();
            let s = n.udp(self.h);
            if s.can_recv() {
                return Poll::Ready(match s.recv_slice(buf) {
                    Ok((len, meta)) => match meta.endpoint.addr {
                        IpAddress::Ipv4(a) => Ok((len, SocketAddrV4::new(a, meta.endpoint.port))),
                        #[allow(unreachable_patterns)]
                        _ => Err(io::Error::new(io::ErrorKind::Other, "not ipv4")),
                    },
                    Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
                });
            }
            if !s.is_open() {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, "mesh closed")));
            }
            s.register_recv_waker(cx.waker());
            Poll::Pending
        })
        .await
    }
}

impl Drop for Datagrams {
    fn drop(&mut self) {
        self.shared.node.lock().unwrap().close_udp(self.h);
    }
}
