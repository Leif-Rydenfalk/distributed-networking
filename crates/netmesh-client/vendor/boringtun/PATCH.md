# boringtun 0.6.0, patched for wasm32-unknown-unknown

Upstream: crates.io boringtun 0.6.0 (BSD-3-Clause, Cloudflare), copied unchanged except for these patches.
Every patch is `cfg(target_arch = "wasm32")`, so native builds compile the upstream code byte for byte.

Why, measured with rustc for wasm32-unknown-unknown:
1. `src/sleepyinstant/mod.rs` has only unix and windows clock backends: `cannot find module or crate inner` (E0433).
   Patch: `use web_time as inner;` on wasm32 (web-time reads performance.now()).
2. `src/noise/handshake.rs` TimeStamper calls `std::time::SystemTime::now()`, which panics on wasm32-unknown-unknown.
   Patch: `web_time::SystemTime` on wasm32 (Date.now()).
3. ring 0.16 has no ChaCha20/Poly1305 on wasm32 without C: link fails with undefined `GFp_ChaCha20_ctr32`,
   `GFp_poly1305_init/update/finish`, `GFp_memcmp`. Patch: `Cargo.toml` takes ring only off wasm32 and
   `../ring-shim` (netmesh-ring-shim, pure Rust chacha20poly1305 + subtle, the exact ring calls boringtun makes) on wasm32;
   `src/lib.rs` adds `extern crate netmesh_ring_shim as ring;` on wasm32 so the noise code is unchanged.
   The shim passes the RFC 8439 2.8.2 AEAD vector.

Proof: `netmesh_client::wg::selftest` (two peers, handshake, one IPv4 packet) passes natively and under
wasm-bindgen-test-runner 0.2.129 on node 24 (node 18 crashes inside the runner, so use node >= 20).

4. `Cargo.toml` x25519-dalek `=2.0.0-rc.3` -> `2.0.1`: rc.3 pins curve25519-dalek `=4.0.0-rc.3`, which cannot sit
   beside ed25519-dalek 2.2 (the tab's identity key). Same API; upstream boringtun master made the same move.
   This one applies natively too.
