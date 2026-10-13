//! Native end to end: Mesh::connect through a test leg (tab door + hub WireGuard), dial_cell, bytes round-trip.
#![cfg(not(target_arch = "wasm32"))]
mod common;

use netmesh_client::{Identity, Mesh};
use std::time::Duration;

async fn leg() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/leg", l.local_addr().unwrap());
    tokio::spawn(common::serve(l));
    url
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_dial_cell_echo() {
    let url = leg().await;
    let id = Identity::ephemeral();
    let mesh = tokio::time::timeout(Duration::from_secs(15), Mesh::connect(&url, &id, common::CELL, common::CAP)).await.unwrap().unwrap();
    assert_eq!(mesh.addr(), common::TAB_ADDR);
    let s = mesh.dial_cell(common::CELL).await.unwrap();
    // 200 KB: three times the 64 KB windows and ~160 MTUs, so flow control and batching both run
    let msg: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut back = vec![0u8; msg.len()];
    let (mut r, mut w) = futures::io::AsyncReadExt::split(s);
    let t = std::time::Instant::now();
    let (wr, rd) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(futures::io::AsyncWriteExt::write_all(&mut w, &msg), futures::io::AsyncReadExt::read_exact(&mut r, &mut back))
    }).await.unwrap();
    wr.unwrap();
    rd.unwrap();
    assert_eq!(back, msg);
    eprintln!("200 KB echo in {:?}", t.elapsed());

    // a second stream on the same mesh
    let mut s2 = mesh.dial_cell(common::CELL).await.unwrap();
    s2.write_all(b"second").await.unwrap();
    let mut b = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(10), s2.read(&mut b)).await.unwrap().unwrap();
    assert_eq!(&b, b"second");
    assert!(mesh.dial_cell("not.a.cell").await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_cap_and_wrong_cell_are_refused() {
    let url = leg().await;
    let id = Identity::ephemeral();
    let e = Mesh::connect(&url, &id, common::CELL, "stolen").await.err().unwrap();
    assert!(e.0.contains("refused: cap refused"), "{e}");
    let e = Mesh::connect(&url, &id, "other.cell", common::CAP).await.err().unwrap();
    assert!(e.0.contains("refused"), "{e}");
}
