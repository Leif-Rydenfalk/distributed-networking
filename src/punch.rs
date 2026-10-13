//! net.mesh NAT traversal: open the server's UDP door without touching the router by hand, then punch through to a
//! client.
//!
//! The typical case: the server sits behind two NATs, a home router and the ISP's carrier-grade
//! NAT (router WAN in 100.64.0.0/10, public e.g. 203.0.113.7). A plain port forward on the home router can never be
//! reached from the internet. What works (measured on a long-haul path: p50 261 ms, min 247 ms, equal to Tailscale's
//! direct path):
//!
//! 1. A leased NAT-PMP mapping (RFC 6886) on the home router for the door port, short lifetime, renewed, removed on
//!    stop. The router then forwards whatever the CGNAT lets in.
//! 2. STUN (RFC 5389 binding) from the door socket itself: the CGNAT's public address and port for it. That is the
//!    address announced to clients. The CGNAT maps endpoint-independently, so one STUN answer holds for every peer.
//! 3. The CGNAT filters by address: a client's packets come in only after the server has sent something to that
//!    client's IP. So the server sends a few small punch packets to the client's public IP as soon as its leg connects.
//!
//! Only parsing and packet building live here (pure, tested in tests/punch.rs); the socket work is in leg.rs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

pub const STUN_COOKIE: u32 = 0x2112_A442;
/// NAT-PMP lease lifetime: short, so a crashed server's door closes by itself within two minutes
pub const LEASE_S: u32 = 120;
/// renew well before the lease ends; STUN rides the same tick and keeps the CGNAT mapping warm
pub const RENEW_EVERY: Duration = Duration::from_secs(40);
/// the punch packet: 8 bytes, never a valid beacon or WireGuard message, so a client that receives it ignores it
pub const PUNCH: &[u8; 8] = b"NMPUNCH1";

/// a STUN binding request with this transaction id
pub fn stun_request(tid: &[u8; 12]) -> Vec<u8> {
    let mut b = Vec::with_capacity(20);
    b.extend_from_slice(&1u16.to_be_bytes()); // binding request
    b.extend_from_slice(&0u16.to_be_bytes()); // no attributes
    b.extend_from_slice(&STUN_COOKIE.to_be_bytes());
    b.extend_from_slice(tid);
    b
}

/// true for anything shaped like a STUN message (cookie at 4..8, top two bits zero). Cheap first test in serve_udp.
pub fn is_stun(p: &[u8]) -> bool {
    p.len() >= 20 && p[0] & 0xC0 == 0 && p[4..8] == STUN_COOKIE.to_be_bytes()
}

/// the mapped address in a binding success response to `tid`; None for anything else (another tid, an error
/// response, a truncated or malformed packet). XOR-MAPPED-ADDRESS wins over MAPPED-ADDRESS. IPv4 only.
pub fn stun_parse(p: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    if !is_stun(p) || p[0..2] != 0x0101u16.to_be_bytes() || &p[8..20] != tid {
        return None;
    }
    let len = u16::from_be_bytes([p[2], p[3]]) as usize;
    let end = 20usize.checked_add(len)?;
    if end > p.len() {
        return None;
    }
    let (mut i, mut plain) = (20usize, None);
    while i + 4 <= end {
        let t = u16::from_be_bytes([p[i], p[i + 1]]);
        let n = u16::from_be_bytes([p[i + 2], p[i + 3]]) as usize;
        let v = p.get(i + 4..i + 4 + n)?;
        if (t == 0x0020 || t == 0x0001) && n >= 8 && v[1] == 0x01 {
            let mut port = u16::from_be_bytes([v[2], v[3]]);
            let mut ip = [v[4], v[5], v[6], v[7]];
            if t == 0x0020 {
                port ^= (STUN_COOKIE >> 16) as u16;
                for (b, k) in ip.iter_mut().zip(STUN_COOKIE.to_be_bytes()) { *b ^= k; }
                return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
            }
            plain = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
        }
        i += 4 + n + (n.wrapping_neg() % 4);
    }
    plain
}

/// NAT-PMP: map UDP `internal` to `external` (0 = router picks) for `life` seconds; life 0 removes the mapping
pub fn natpmp_request(internal: u16, external: u16, life: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[1] = 1; // opcode 1 = UDP
    b[4..6].copy_from_slice(&internal.to_be_bytes());
    b[6..8].copy_from_slice(&external.to_be_bytes());
    b[8..12].copy_from_slice(&life.to_be_bytes());
    b
}

/// a NAT-PMP UDP mapping answer: Ok((internal, external, lifetime)) or Err(result code). None if not one.
pub fn natpmp_parse(p: &[u8]) -> Option<Result<(u16, u16, u32), u16>> {
    if p.len() < 16 || p[0] != 0 || p[1] != 129 {
        return None;
    }
    let rc = u16::from_be_bytes([p[2], p[3]]);
    if rc != 0 {
        return Some(Err(rc));
    }
    let int = u16::from_be_bytes([p[8], p[9]]);
    let ext = u16::from_be_bytes([p[10], p[11]]);
    let life = u32::from_be_bytes([p[12], p[13], p[14], p[15]]);
    Some(Ok((int, ext, life)))
}

/// ask the router at `gw` (port 5351) for a lease from `bind_ip`. Two tries, 1 s each.
pub async fn natpmp_lease(gw: Ipv4Addr, bind_ip: IpAddr, port: u16, life: u32) -> Result<(u16, u32), String> {
    let s = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await.map_err(|e| e.to_string())?;
    let to = SocketAddr::new(IpAddr::V4(gw), 5351);
    let req = natpmp_request(port, if life == 0 { 0 } else { port }, life);
    let mut buf = [0u8; 64];
    for _ in 0..2 {
        s.send_to(&req, to).await.map_err(|e| e.to_string())?;
        if let Ok(Ok((n, src))) = tokio::time::timeout(Duration::from_secs(1), s.recv_from(&mut buf)).await {
            if src != to { continue; }
            match natpmp_parse(&buf[..n]) {
                Some(Ok((int, ext, got))) if int == port => return Ok((ext, got)),
                Some(Err(rc)) => return Err(format!("nat-pmp result {rc}")),
                _ => {}
            }
        }
    }
    Err(format!("no nat-pmp answer from {to}"))
}

/// first IPv4 address for a STUN host name
pub async fn resolve4(host: &str) -> Option<SocketAddr> {
    tokio::net::lookup_host(host).await.ok()?.find(|a| a.is_ipv4())
}

/// a fresh random transaction id
pub fn tid() -> [u8; 12] {
    let mut t = [0u8; 12];
    getrandom::getrandom(&mut t).expect("getrandom");
    t
}

/// the client's public IP from a `Cf-Connecting-Ip` header value; only a plain IPv4 is accepted (an IPv6 address
/// cannot be punched from an IPv4-only door)
pub fn client_ip(header: &str) -> Option<IpAddr> {
    match header.trim().parse::<IpAddr>().ok()? {
        IpAddr::V4(v) if !v.is_private() && !v.is_loopback() && !v.is_unspecified() => Some(IpAddr::V4(v)),
        _ => None,
    }
}

/// the door address announced in `udp2 <tid> <key> door=<ip:port>`; None when the token is missing or not public
pub fn announced_door(udp2_line: &str) -> Option<SocketAddr> {
    let a: SocketAddr = udp2_line.split_whitespace().find_map(|t| t.strip_prefix("door="))?.parse().ok()?;
    match a.ip() {
        IpAddr::V4(v) if !v.is_private() && !v.is_loopback() && !v.is_unspecified() && a.port() != 0 => Some(a),
        _ => None,
    }
}
