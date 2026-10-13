//! The test leg (tab door + hub with an echo cell) as a process, for the wasm test:
//!   cargo run --example test_leg -- 127.0.0.1:7745
//!   NETMESH_TEST_LEG=ws://127.0.0.1:7745/v1/leg cargo test --target wasm32-unknown-unknown
//! Binds loopback only. Test credentials (cap "test-cap"); never deploy it.
#[path = "../tests/common/mod.rs"]
mod common;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:7745".into());
    let a: std::net::SocketAddr = addr.parse().expect("addr");
    assert!(a.ip().is_loopback(), "test leg binds loopback only");
    let l = tokio::net::TcpListener::bind(a).await.expect("bind");
    eprintln!("test leg on ws://{a}/v1/leg (cell {} cap {})", common::CELL, common::CAP);
    common::serve(l).await;
}
