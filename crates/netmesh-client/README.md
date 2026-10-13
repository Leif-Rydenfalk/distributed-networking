# netmesh-client

A full mesh node that runs in a browser tab (`wasm32-unknown-unknown`) and natively: WireGuard
(`boringtun::noise`) under a smoltcp TCP/UDP stack, carried over the relay leg WebSocket. The page gets a mesh
address, completes a WireGuard handshake with the relay's server, and opens TCP streams and UDP sockets to services
on the mesh. No browser extension or native helper is needed.

## API

```rust
use netmesh_client::{Identity, Mesh};

let id = Identity::ephemeral();                      // ed25519 + x25519, in memory, never stored
// the app's logged-in backend mints a capability for id.node_id(), action net.mesh:cell:<service>, <= 10 min
let mesh = Mesh::connect("wss://relay.example.com/v1/leg", &id, "demo.echo", &cap).await?;
let mut s = mesh.dial_cell("demo.echo").await?;      // Stream: duplex bytes
s.write_all(b"...").await?;
let n = s.read(&mut buf).await?;
```

- `Mesh::connect(leg_url, &Identity, cell, cap) -> Result<Mesh, Error>`: passes the relay's door and finishes the
  WireGuard handshake; returns when the tunnel carries packets. The relay answers with the tab's `10.77.255.x`
  address and the service's `addr:port`, so the page never hardcodes a mesh address.
- `mesh.addr() -> Ipv4Addr`, `mesh.resolve(name)`, `mesh.closed() -> Option<String>`, `mesh.close()`
- `mesh.dial_cell(name) -> Stream`: the service named at connect, or any name from `with_cells(impl CellDirectory)`
- `mesh.dial_tcp(SocketAddrV4) -> Stream`, `mesh.udp(port) -> Datagrams` (`send_to`, `recv_from`)
- `Stream`: `futures::io::{AsyncRead, AsyncWrite}` on every target, `tokio::io::{AsyncRead, AsyncWrite}` natively,
  plus inherent `read`, `write_all`, `flush`, `close`. Split for full duplex with
  `futures::io::AsyncReadExt::split`.
- Natively `connect` needs a tokio runtime; on wasm32 it runs on the page's event loop (`spawn_local`,
  `setTimeout`).

The door's wire format is in `src/hello.rs`; the relay server in the root crate (`src/leg.rs`) checks exactly the
bytes this crate signs.

## Layers

| Module | Role |
|---|---|
| `wg` | WireGuard from vendored boringtun 0.6.0 (`noise` only) |
| `node` | one WireGuard peer under a smoltcp IP interface, no I/O; MTU 1280, `10.77.0.0/16` |
| `leg` | the leg WebSocket as frame channels (web-sys in a browser, tokio-tungstenite natively), datagram batching |
| `hello` | the tab hello on the leg door, both ends |
| `mesh` | `Mesh::connect`, `dial_cell`, `dial_tcp`, `udp`, `Stream` |

## Build and test

```sh
cargo test                                             # unit tests + native end to end (tests/leg_echo.rs)
cargo build --target wasm32-unknown-unknown            # no C compiler needed (pure-Rust ring shim on wasm32)

# wasm end to end: a loopback test leg, then the wasm tests against it (node >= 22 for a global WebSocket)
cargo run --example test_leg -- 127.0.0.1:7745 &
NETMESH_TEST_LEG=ws://127.0.0.1:7745/v1/leg CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --target wasm32-unknown-unknown
```

The test leg in `examples/test_leg.rs` uses fixed test credentials and binds loopback only; never deploy it.

Measured: a native 200 KB echo through the leg completes in about 38 ms on loopback; the wasm build passes a 50 KB
echo under node 24.

## Vendored code

- `vendor/boringtun`: boringtun 0.6.0 (BSD-3-Clause, Cloudflare; see `vendor/boringtun/LICENSE.md`) with three
  `cfg(target_arch = "wasm32")`-only patches and one dependency bump, documented in `vendor/boringtun/PATCH.md`.
  Native builds compile the upstream noise code unchanged.
- `vendor/ring-shim`: the slice of ring 0.16's API that boringtun's noise code uses (ChaCha20-Poly1305 AEAD,
  constant-time compare), in pure Rust for wasm32. Native builds keep the real ring.

## License

Apache-2.0 (see the repository root), except `vendor/boringtun`, which keeps its BSD-3-Clause license.
