//! A mesh node without I/O: one WireGuard peer (the leg's server) under a smoltcp IP interface. Datagrams go in with
//! `input`, come out of `take_out`; `poll` runs WireGuard timers and the TCP/UDP stack and says when to call it again.
//! The browser driver, the native driver and the in-process test hub all run this same code.

use boringtun::noise::{errors::WireGuardError, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

/// every mesh node runs MTU 1280 (the root crate's src/lib.rs `MTU`)
pub const MTU: usize = 1280;
/// net.mesh addresses are 10.77.0.0/16
pub const PREFIX: u8 = 16;
const TCP_BUF: usize = 64 * 1024;
const UDP_BUF: usize = 64 * 1024;
const WG_TICK: Duration = Duration::from_millis(250);
const WG_BUF: usize = 65536;

struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

pub struct Rx(Vec<u8>);
pub struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl<'a> smoltcp::phy::TxToken for Tx<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut p = vec![0u8; len];
        let r = f(&mut p);
        self.0.push_back(p);
        r
    }
}

impl Device for Queue {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = MTU;
        c
    }
}

pub struct Node {
    tunn: Tunn,
    iface: Interface,
    dev: Queue,
    sockets: SocketSet<'static>,
    t0: web_time::Instant,
    last_tick: Option<web_time::Instant>,
    out: Vec<Vec<u8>>,
    buf: Vec<u8>,
    closing: Vec<SocketHandle>,
    next_port: u16,
    addr: Ipv4Addr,
    expired: bool,
}

impl Node {
    /// `secret`: this node's WireGuard key; `peer`: the server's. `keepalive` in seconds (25 like wg-quick).
    pub fn new(secret: StaticSecret, peer: PublicKey, addr: Ipv4Addr, keepalive: Option<u16>) -> Node {
        let mut idx = [0u8; 4];
        getrandom::getrandom(&mut idx).expect("getrandom");
        // boringtun keeps the low 8 bits for its session index
        let tunn = Tunn::new(secret, peer, None, keepalive, u32::from_le_bytes(idx) >> 8, None).expect("Tunn::new");
        let mut dev = Queue { rx: VecDeque::new(), tx: VecDeque::new() };
        let t0 = web_time::Instant::now();
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, smoltcp::time::Instant::ZERO);
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(IpAddress::Ipv4(addr), PREFIX)).unwrap();
        });
        let mut p = [0u8; 2];
        getrandom::getrandom(&mut p).expect("getrandom");
        Node {
            tunn, iface, dev, sockets: SocketSet::new(vec![]), t0, last_tick: None, out: Vec::new(), buf: vec![0u8; WG_BUF],
            closing: Vec::new(), next_port: 49152 + (u16::from_le_bytes(p) % 16000), addr, expired: false,
        }
    }

    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    /// a WireGuard session exists (the handshake finished at least once)
    pub fn is_up(&self) -> bool {
        self.tunn.time_since_last_handshake().is_some()
    }

    /// WireGuard gave up (no handshake answer within its reject time)
    pub fn expired(&self) -> bool {
        self.expired
    }

    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(self.t0.elapsed().as_micros() as i64)
    }

    /// start a handshake now instead of on the first packet
    pub fn handshake(&mut self) {
        if let TunnResult::WriteToNetwork(p) = self.tunn.format_handshake_initiation(&mut self.buf, false) {
            self.out.push(p.to_vec());
        }
    }

    /// one WireGuard datagram from the network
    pub fn input(&mut self, datagram: &[u8]) {
        let mut r = self.tunn.decapsulate(None, datagram, &mut self.buf);
        loop {
            match r {
                TunnResult::WriteToNetwork(p) => {
                    self.out.push(p.to_vec());
                    // boringtun may hold queued packets behind a finished handshake; drain them
                    r = self.tunn.decapsulate(None, &[], &mut self.buf);
                    continue;
                }
                TunnResult::WriteToTunnelV4(p, _src) => self.dev.rx.push_back(p.to_vec()),
                TunnResult::WriteToTunnelV6(..) | TunnResult::Done | TunnResult::Err(_) => {}
            }
            break;
        }
    }

    /// run timers and the IP stack; returns how long until the next call is due
    pub fn poll(&mut self) -> Duration {
        let wall = web_time::Instant::now();
        if self.last_tick.map_or(true, |t| wall.duration_since(t) >= WG_TICK) {
            self.last_tick = Some(wall);
            match self.tunn.update_timers(&mut self.buf) {
                TunnResult::WriteToNetwork(p) => self.out.push(p.to_vec()),
                TunnResult::Err(WireGuardError::ConnectionExpired) => self.expired = true,
                _ => {}
            }
        }
        let now = self.now();
        // poll until the stack is quiet: one poll may answer packets that the next poll sends
        for _ in 0..64 {
            let r = self.iface.poll(now, &mut self.dev, &mut self.sockets);
            self.flush_tx();
            if r == smoltcp::iface::PollResult::None && self.dev.rx.is_empty() {
                break;
            }
        }
        self.reap();
        let d = self.iface.poll_delay(now, &self.sockets).map(|d| Duration::from_micros(d.total_micros())).unwrap_or(WG_TICK);
        d.min(WG_TICK)
    }

    fn flush_tx(&mut self) {
        while let Some(ip) = self.dev.tx.pop_front() {
            if let TunnResult::WriteToNetwork(p) = self.tunn.encapsulate(&ip, &mut self.buf) {
                self.out.push(p.to_vec());
            }
        }
    }

    /// datagrams for the network since the last call
    pub fn take_out(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }

    fn port(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = if p >= 65000 { 49152 } else { p + 1 };
        p
    }

    fn tcp_socket() -> tcp::Socket<'static> {
        let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; TCP_BUF]), tcp::SocketBuffer::new(vec![0u8; TCP_BUF]));
        s.set_nagle_enabled(false);
        s
    }

    pub fn tcp_connect(&mut self, dst: SocketAddrV4) -> Result<SocketHandle, String> {
        let mut s = Self::tcp_socket();
        let local = self.port();
        s.connect(self.iface.context(), (IpAddress::Ipv4(*dst.ip()), dst.port()), local).map_err(|e| format!("connect {dst}: {e}"))?;
        Ok(self.sockets.add(s))
    }

    pub fn tcp_listen(&mut self, port: u16) -> Result<SocketHandle, String> {
        let mut s = Self::tcp_socket();
        s.listen(port).map_err(|e| format!("listen {port}: {e}"))?;
        Ok(self.sockets.add(s))
    }

    pub fn udp_bind(&mut self, port: u16) -> Result<SocketHandle, String> {
        let mut s = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; UDP_BUF]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; UDP_BUF]),
        );
        let port = if port == 0 { self.port() } else { port };
        s.bind(port).map_err(|e| format!("bind {port}: {e}"))?;
        Ok(self.sockets.add(s))
    }

    pub fn tcp(&mut self, h: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(h)
    }

    pub fn udp(&mut self, h: SocketHandle) -> &mut udp::Socket<'static> {
        self.sockets.get_mut::<udp::Socket>(h)
    }

    /// close a TCP socket gracefully; the node frees it once the close finishes
    pub fn close_tcp(&mut self, h: SocketHandle) {
        self.tcp(h).close();
        self.closing.push(h);
    }

    pub fn close_udp(&mut self, h: SocketHandle) {
        self.udp(h).close();
        self.sockets.remove(h);
    }

    /// abort every TCP socket and close every UDP socket (the leg is gone); wakes every waiting task
    pub fn abort_all(&mut self) {
        for (_, s) in self.sockets.iter_mut() {
            match s {
                smoltcp::socket::Socket::Tcp(s) => s.abort(),
                smoltcp::socket::Socket::Udp(s) => s.close(),
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }

    fn reap(&mut self) {
        let mut keep = Vec::new();
        for h in std::mem::take(&mut self.closing) {
            match self.sockets.get::<tcp::Socket>(h).state() {
                tcp::State::Closed | tcp::State::TimeWait => {
                    self.sockets.remove(h);
                }
                _ => keep.push(h),
            }
        }
        self.closing = keep;
    }
}

/// two nodes wired back to back, for tests: a's datagrams go to b and back until both are quiet
pub fn pump(a: &mut Node, b: &mut Node) {
    for _ in 0..256 {
        a.poll();
        b.poll();
        let (x, y) = (a.take_out(), b.take_out());
        if x.is_empty() && y.is_empty() {
            return;
        }
        x.iter().for_each(|p| b.input(p));
        y.iter().for_each(|p| a.input(p));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::ephemeral_key;

    #[test]
    fn tcp_echo_through_wireguard_in_memory() {
        let (sa, sb) = (ephemeral_key(), ephemeral_key());
        let (pa, pb) = (PublicKey::from(&sa), PublicKey::from(&sb));
        let mut a = Node::new(sa, pb, Ipv4Addr::new(10, 77, 255, 7), None);
        let mut b = Node::new(sb, pa, Ipv4Addr::new(10, 77, 0, 5), None);
        let l = b.tcp_listen(7900).unwrap();
        let c = a.tcp_connect("10.77.0.5:7900".parse().unwrap()).unwrap();
        pump(&mut a, &mut b);
        assert!(a.is_up() && b.is_up());
        assert_eq!(a.tcp(c).state(), tcp::State::Established);
        a.tcp(c).send_slice(b"hello cell").unwrap();
        pump(&mut a, &mut b);
        let mut buf = [0u8; 64];
        let n = b.tcp(l).recv_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello cell");
        b.tcp(l).send_slice(&buf[..n]).unwrap();
        pump(&mut a, &mut b);
        let n = a.tcp(c).recv_slice(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello cell");
    }
}
