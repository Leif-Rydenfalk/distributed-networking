//! net.mesh client: a full mesh node that runs in a browser tab (wasm32) and natively, over the relay leg WebSocket.
//! Layers, bottom up:
//! - `wg`: WireGuard, boringtun::noise (vendored 0.6.0 with cfg(wasm32)-only patches, vendor/boringtun/PATCH.md)
//! - `node`: one WireGuard peer under a smoltcp IP interface, no I/O (MTU 1280, 10.77.0.0/16)
//! - `leg`: the leg WebSocket as frame channels (web-sys / tokio-tungstenite), datagram batching
//! - `hello`: the tab hello on the leg door, both ends
//! - `mesh`: `Mesh::connect`, `dial_cell`, `dial_tcp`, `udp`; `Stream` is a duplex byte stream for any protocol

pub mod hello;
pub mod leg;
pub mod mesh;
pub mod node;
mod rt;
pub mod wg;

pub use hello::Identity;
pub use mesh::{CellDirectory, Datagrams, Error, Mesh, Stream};
