//! The tab hello on the leg door. Both ends live here so the leg server checks exactly
//! the bytes the client signs.
//!
//!   server -> tab   text  `net.mesh/leg/v1 <nonce hex>`                       (the leg's node challenge)
//!   tab -> server   text  JSON TabHello {proto, node, wg, cell, cap, ts, sig}
//!   server -> tab   text  `ok <tab addr> <server wg pub b64> <cell addr:port>`  or `refused: <why>`
//!
//! `node` is the tab's ephemeral ed25519 key (hex, the same form as `node_id`), `wg` its ephemeral x25519 key (base64
//! like `wg pubkey`). `sig` is ed25519 over `signed_bytes`, which binds the server's nonce, so a hello copied off
//! the wire is useless on another connection. `cap` is the capability the embedding app's backend minted for `node`,
//! scoped to `net.mesh:cell:<cell>`; the server verifies it through its IAM verifier.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddrV4};

pub const LEG_PROTO: &str = "net.mesh/leg/v1";
pub const TAB_PROTO: &str = "net.mesh/leg/tab/v1";
pub const MAX_SKEW_S: u64 = 60;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub fn unb64_32(s: &str) -> Option<[u8; 32]> {
    base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()?.try_into().ok()
}

pub fn unix_now() -> u64 {
    web_time::SystemTime::now().duration_since(web_time::SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A tab's two keys, made in memory and never stored. Natively a node may load its long-lived
/// keys with `from_secrets`.
pub struct Identity {
    pub(crate) sign: SigningKey,
    pub(crate) wg: boringtun::x25519::StaticSecret,
}

impl Identity {
    pub fn ephemeral() -> Identity {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        getrandom::getrandom(&mut a).expect("getrandom");
        getrandom::getrandom(&mut b).expect("getrandom");
        Identity::from_secrets(a, b)
    }

    pub fn from_secrets(ed25519_seed: [u8; 32], wg_secret: [u8; 32]) -> Identity {
        Identity { sign: SigningKey::from_bytes(&ed25519_seed), wg: boringtun::x25519::StaticSecret::from(wg_secret) }
    }

    /// what the backend mints the cap for (the grant's audience)
    pub fn node_id(&self) -> String {
        hex(self.sign.verifying_key().as_bytes())
    }

    pub fn wg_public(&self) -> String {
        b64(boringtun::x25519::PublicKey::from(&self.wg).as_bytes())
    }
}

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

impl TabHello {
    pub fn signed_bytes(&self, nonce: &str) -> Vec<u8> {
        // cap goes last: it is the only field that may hold any character
        format!("{}\n{nonce}\n{}\n{}\n{}\n{}\n{}", self.proto, self.node, self.wg, self.cell, self.ts, self.cap).into_bytes()
    }

    pub fn signed(id: &Identity, nonce: &str, cell: &str, cap: &str, ts: u64) -> TabHello {
        let mut h = TabHello { proto: TAB_PROTO.into(), node: id.node_id(), wg: id.wg_public(), cell: cell.into(), cap: cap.into(), ts, sig: String::new() };
        h.sig = hex(&id.sign.sign(&h.signed_bytes(nonce)).to_bytes());
        h
    }

    /// proto, field shapes, timestamp window and signature. Replay across connections is stopped by the nonce;
    /// the cap is the server's to check.
    pub fn check(&self, nonce: &str, now: u64) -> Result<(), &'static str> {
        if self.proto != TAB_PROTO {
            return Err("bad proto");
        }
        if self.ts + MAX_SKEW_S < now || self.ts > now + MAX_SKEW_S {
            return Err("timestamp outside window");
        }
        if self.cell.is_empty() || self.cell.len() > 128 || !self.cell.bytes().all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c)) {
            return Err("bad cell name");
        }
        if self.cap.is_empty() {
            return Err("no cap");
        }
        unb64_32(&self.wg).ok_or("bad wg key")?;
        let pk: [u8; 32] = unhex(&self.node).and_then(|v| v.try_into().ok()).ok_or("bad node id")?;
        let sig: [u8; 64] = unhex(&self.sig).and_then(|v| v.try_into().ok()).ok_or("bad signature encoding")?;
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad node id")?;
        vk.verify(&self.signed_bytes(nonce), &Signature::from_bytes(&sig)).map_err(|_| "bad signature")
    }
}

/// what the server handed the tab
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Admitted {
    pub addr: Ipv4Addr,
    pub server_wg: [u8; 32],
    pub cell: SocketAddrV4,
}

impl Admitted {
    pub fn ok_line(&self) -> String {
        format!("ok {} {} {}", self.addr, b64(&self.server_wg), self.cell)
    }

    pub fn parse(line: &str) -> Result<Admitted, String> {
        let mut it = line.split_whitespace();
        if it.next() != Some("ok") {
            return Err(line.to_string());
        }
        let bad = || format!("bad ok line: {line:?}");
        let addr = it.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
        let server_wg = it.next().and_then(unb64_32).ok_or_else(bad)?;
        let cell = it.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
        Ok(Admitted { addr, server_wg, cell })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_hello_checks_and_tampering_fails() {
        let id = Identity::ephemeral();
        let now = unix_now();
        let h = TabHello::signed(&id, "n1", "demo.echo", "cap-token", now);
        assert_eq!(h.check("n1", now), Ok(()));
        assert_eq!(h.check("n2", now), Err("bad signature")); // another connection's nonce
        assert_eq!(h.check("n1", now + 61), Err("timestamp outside window"));
        let mut t = h.clone();
        t.cell = "other.cell".into();
        assert_eq!(t.check("n1", now), Err("bad signature"));
        let mut t = h.clone();
        t.cap = String::new();
        assert_eq!(t.check("n1", now), Err("no cap"));
        let j: TabHello = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(j, h);
    }

    #[test]
    fn ok_line_round_trips() {
        let a = Admitted { addr: "10.77.255.7".parse().unwrap(), server_wg: [7; 32], cell: "10.77.0.5:7900".parse().unwrap() };
        assert_eq!(Admitted::parse(&a.ok_line()), Ok(a));
        assert_eq!(Admitted::parse("refused: expired cap"), Err("refused: expired cap".into()));
    }
}
