//! A test leg: the tab door from `hello` plus an in-process hub node (the "server WireGuard") that runs an echo cell.
//! Used by tests/leg_echo.rs natively and by examples/test_leg.rs, which the wasm test dials.

use futures::{SinkExt, StreamExt};
use netmesh_client::hello::{unix_now, Admitted, TabHello, LEG_PROTO, hex};
use netmesh_client::leg;
use netmesh_client::node::Node;
use netmesh_client::wg::ephemeral_key;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

pub const CELL: &str = "test.echo";
pub const CAP: &str = "test-cap";
pub const CELL_ADDR: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 5);
pub const CELL_PORT: u16 = 7900;
pub const TAB_ADDR: Ipv4Addr = Ipv4Addr::new(10, 77, 255, 7);

pub async fn serve(l: TcpListener) {
    loop {
        let Ok((tcp, _)) = l.accept().await else { continue };
        tokio::spawn(async move {
            if let Err(e) = conn(tcp).await {
                eprintln!("test leg: {e}");
            }
        });
    }
}

fn echo(hub: &mut Node, ls: &mut Vec<SocketHandle>) {
    let mut buf = [0u8; 4096];
    for h in ls.clone() {
        let s = hub.tcp(h);
        while s.can_recv() && s.can_send() {
            let room = (s.send_capacity() - s.send_queue()).min(buf.len());
            let n = s.recv_slice(&mut buf[..room]).unwrap_or(0);
            if n == 0 { break; }
            s.send_slice(&buf[..n]).unwrap();
        }
        if s.state() == tcp::State::CloseWait {
            s.close();
        }
    }
    let listening = ls.iter().filter(|h| hub.tcp(**h).state() == tcp::State::Listen).count();
    if listening == 0 {
        ls.push(hub.tcp_listen(CELL_PORT).unwrap());
    }
}

async fn conn(tcp: tokio::net::TcpStream) -> Result<(), String> {
    let mut ws = tokio_tungstenite::accept_async(tcp).await.map_err(|e| e.to_string())?;
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).unwrap();
    let nonce = hex(&n);
    ws.send(Message::Text(format!("{LEG_PROTO} {nonce}"))).await.map_err(|e| e.to_string())?;
    let hello = match ws.next().await {
        Some(Ok(Message::Text(t))) => serde_json::from_str::<TabHello>(&t).map_err(|_| "bad hello".to_string())?,
        _ => return Err("no hello".into()),
    };
    let refuse = match hello.check(&nonce, unix_now()) {
        Err(e) => Some(e.to_string()),
        Ok(()) if hello.cell != CELL => Some("cap not for this cell".into()),
        Ok(()) if hello.cap != CAP => Some("cap refused".into()),
        Ok(()) => None,
    };
    if let Some(e) = refuse {
        let _ = ws.send(Message::Text(format!("refused: {e}"))).await;
        return Err(format!("refused: {e}"));
    }
    let key = ephemeral_key();
    let server_wg = *boringtun::x25519::PublicKey::from(&key).as_bytes();
    let peer = boringtun::x25519::PublicKey::from(netmesh_client::hello::unb64_32(&hello.wg).unwrap());
    let mut hub = Node::new(key, peer, CELL_ADDR, None);
    let mut ls = vec![hub.tcp_listen(CELL_PORT).unwrap()];
    let ok = Admitted { addr: TAB_ADDR, server_wg, cell: SocketAddrV4::new(CELL_ADDR, CELL_PORT) };
    ws.send(Message::Text(ok.ok_line())).await.map_err(|e| e.to_string())?;
    loop {
        let d = hub.poll();
        echo(&mut hub, &mut ls);
        hub.poll();
        for b in leg::batches(hub.take_out()) {
            ws.send(Message::Binary(b)).await.map_err(|e| e.to_string())?;
        }
        tokio::select! {
            m = ws.next() => match m {
                Some(Ok(Message::Binary(b))) => leg::unpack(&b).into_iter().for_each(|p| hub.input(p)),
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return Ok(()),
                _ => {}
            },
            _ = tokio::time::sleep(d) => {}
        }
    }
}
