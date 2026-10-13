//! wasm-bindgen-test-runner (node >= 22 for a global WebSocket, or --headless --chrome)
#![cfg(target_arch = "wasm32")]
use netmesh_client::{Identity, Mesh};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn handshake_and_packet_wasm() {
    netmesh_client::wg::selftest().unwrap();
}

/// against examples/test_leg.rs; NETMESH_TEST_LEG is read at build time
#[wasm_bindgen_test]
async fn connect_dial_cell_echo_wasm() {
    let Some(url) = option_env!("NETMESH_TEST_LEG") else { return };
    let id = Identity::ephemeral();
    let mesh = Mesh::connect(url, &id, "test.echo", "test-cap").await.unwrap();
    assert_eq!(mesh.addr().to_string(), "10.77.255.7");
    let mut s = mesh.dial_cell("test.echo").await.unwrap();
    let msg: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    s.write_all(&msg).await.unwrap();
    let mut back = Vec::new();
    let mut buf = [0u8; 4096];
    while back.len() < msg.len() {
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0, "eof after {} bytes", back.len());
        back.extend_from_slice(&buf[..n]);
    }
    assert_eq!(back, msg);
    let e = Mesh::connect(url, &Identity::ephemeral(), "test.echo", "stolen").await.err().unwrap();
    assert!(e.0.contains("refused"), "{e}");
}
