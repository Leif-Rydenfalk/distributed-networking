//! ring 0.16 has no ChaCha20/Poly1305 on wasm32-unknown-unknown without C (GFp_ChaCha20_ctr32 and GFp_poly1305_*
//! are undefined at link time). boringtun's Cargo.toml maps `ring` to this crate on wasm32 only, so the noise code
//! is unchanged and native builds keep the real ring. Same signatures as the ring calls boringtun makes.

pub mod error {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Unspecified;
    impl core::fmt::Display for Unspecified {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result { f.write_str("ring::error::Unspecified") }
    }
    impl std::error::Error for Unspecified {}
}

pub mod constant_time {
    use subtle::ConstantTimeEq;
    pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), super::error::Unspecified> {
        if a.len() == b.len() && bool::from(a.ct_eq(b)) { Ok(()) } else { Err(super::error::Unspecified) }
    }
}

pub mod aead {
    use super::error::Unspecified;
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;

    pub const TAG_LEN: usize = 16;

    pub struct Algorithm(());
    pub static CHACHA20_POLY1305: Algorithm = Algorithm(());

    pub struct Nonce([u8; 12]);
    impl Nonce {
        pub fn assume_unique_for_key(n: [u8; 12]) -> Self { Nonce(n) }
    }

    pub struct Aad<A>(A);
    impl<A: AsRef<[u8]>> Aad<A> {
        pub fn from(a: A) -> Self { Aad(a) }
    }

    pub struct Tag([u8; TAG_LEN]);
    impl AsRef<[u8]> for Tag {
        fn as_ref(&self) -> &[u8] { &self.0 }
    }

    pub struct UnboundKey(ChaCha20Poly1305);
    impl UnboundKey {
        pub fn new(_alg: &'static Algorithm, key: &[u8]) -> Result<Self, Unspecified> {
            ChaCha20Poly1305::new_from_slice(key).map(UnboundKey).map_err(|_| Unspecified)
        }
    }

    pub struct LessSafeKey(ChaCha20Poly1305);
    impl LessSafeKey {
        pub fn new(k: UnboundKey) -> Self { LessSafeKey(k.0) }

        pub fn seal_in_place_separate_tag<A: AsRef<[u8]>>(&self, nonce: Nonce, aad: Aad<A>, in_out: &mut [u8]) -> Result<Tag, Unspecified> {
            let t = self.0.encrypt_in_place_detached(&nonce.0.into(), aad.0.as_ref(), in_out).map_err(|_| Unspecified)?;
            Ok(Tag(t.into()))
        }

        /// in_out is ciphertext || tag; returns the plaintext prefix
        pub fn open_in_place<'a, A: AsRef<[u8]>>(&self, nonce: Nonce, aad: Aad<A>, in_out: &'a mut [u8]) -> Result<&'a mut [u8], Unspecified> {
            let n = in_out.len().checked_sub(TAG_LEN).ok_or(Unspecified)?;
            let (ct, tag) = in_out.split_at_mut(n);
            let tag: [u8; TAG_LEN] = (&*tag).try_into().map_err(|_| Unspecified)?;
            self.0.decrypt_in_place_detached(&nonce.0.into(), aad.0.as_ref(), ct, &tag.into()).map_err(|_| Unspecified)?;
            Ok(&mut in_out[..n])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::aead::*;

    // RFC 8439 2.8.2 AEAD test vector
    #[test]
    fn rfc8439_vector_and_tamper() {
        let key: Vec<u8> = (0x80u8..0xa0).collect();
        let nonce = [0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
        let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let k = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap());
        let mut buf = pt.to_vec();
        let tag = k.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut buf).unwrap();
        assert_eq!(tag.as_ref(), [0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91]);
        assert_eq!(&buf[..4], [0xd3, 0x1a, 0x8d, 0x34]);
        buf.extend_from_slice(tag.as_ref());
        let mut bad = buf.clone();
        bad[0] ^= 1;
        assert!(k.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut bad).is_err());
        let p = k.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut buf).unwrap();
        assert_eq!(p, &pt[..]);
    }
}
