//! WireGuard: boringtun::noise (Noise_IKpsk2 + transport + timers), the same code the native nodes run.

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// a fresh x25519 key from the OS (crypto.getRandomValues in a browser); never stored
pub fn ephemeral_key() -> StaticSecret {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("getrandom");
    StaticSecret::from(b)
}

/// a minimal IPv4 packet (UDP, no checksum) from `src` to `dst`, so decapsulate hands it to the tunnel side
pub fn ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 17, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

/// Two in-memory peers: handshake, then one IPv4 packet from a to b. Proves the noise layer links and runs on
/// this target (ring's ChaCha20-Poly1305, x25519, blake2, the patched clock).
pub fn selftest() -> Result<(), String> {
    let (sa, sb) = (ephemeral_key(), ephemeral_key());
    let (pa, pb) = (PublicKey::from(&sa), PublicKey::from(&sb));
    let mut a = Tunn::new(sa, pb, None, None, 1, None).map_err(String::from)?;
    let mut b = Tunn::new(sb, pa, None, None, 2, None).map_err(String::from)?;
    let (mut x, mut y) = (vec![0u8; 2048], vec![0u8; 2048]);

    let init = match a.format_handshake_initiation(&mut x, false) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        _ => return Err("no handshake initiation".into()),
    };
    let resp = match b.decapsulate(None, &init, &mut y) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        _ => return Err("no handshake response".into()),
    };
    if let TunnResult::WriteToNetwork(k) = a.decapsulate(None, &resp, &mut x) {
        let k = k.to_vec();
        let _ = b.decapsulate(None, &k, &mut y); // keepalive confirms the session at b
    }
    let ip = ipv4_packet([10, 77, 0, 1], [10, 77, 0, 2], b"net.mesh wasm");
    let data = match a.encapsulate(&ip, &mut x) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        _ => return Err("encapsulate gave no datagram".into()),
    };
    match b.decapsulate(None, &data, &mut y) {
        TunnResult::WriteToTunnelV4(p, src) if p == &ip[..] && src.octets() == [10, 77, 0, 1] => Ok(()),
        TunnResult::Err(e) => Err(format!("decapsulate: {e:?}")),
        _ => Err("decapsulate gave the wrong packet".into()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn handshake_and_packet_native() {
        super::selftest().unwrap();
    }
}
