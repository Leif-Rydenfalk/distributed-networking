//! The relay leg as a message pipe: one WebSocket (web-sys in a browser, tokio-tungstenite natively) turned into two
//! channels of `Frame`s, so everything above it is the same code on both. Binary frames carry WireGuard datagrams
//! as `u16 BE length || datagram`, batched (the root crate's src/leg.rs `pack`/`unpack`).

use futures::channel::mpsc;

pub const BATCH_MAX: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Text(String),
    Binary(Vec<u8>),
    /// the socket is gone (sent up by the transport), or close it (sent down by the client)
    Closed(String),
}

pub struct Leg {
    pub tx: mpsc::UnboundedSender<Frame>,
    pub rx: mpsc::UnboundedReceiver<Frame>,
}

pub fn pack(out: &mut Vec<u8>, pkt: &[u8]) {
    out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    out.extend_from_slice(pkt);
}

/// split a batch back into datagrams; a truncated tail is dropped (never panics on hostile input)
pub fn unpack(mut b: &[u8]) -> Vec<&[u8]> {
    let mut v = Vec::new();
    while b.len() >= 2 {
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        if b.len() < 2 + n {
            break;
        }
        v.push(&b[2..2 + n]);
        b = &b[2 + n..];
    }
    v
}

/// datagrams into as few binary frames as fit under BATCH_MAX
pub fn batches(pkts: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    let mut cur = Vec::new();
    for p in pkts {
        if !cur.is_empty() && cur.len() + 2 + p.len() > BATCH_MAX {
            v.push(std::mem::take(&mut cur));
        }
        pack(&mut cur, &p);
    }
    if !cur.is_empty() {
        v.push(cur);
    }
    v
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn open(url: &str) -> Result<Leg, String> {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    // disable_nagle: Nagle + delayed ACKs held small WireGuard packets up to ~200 ms (see the root crate's leg.rs)
    let (ws, _) = tokio_tungstenite::connect_async_with_config(url, None, true).await.map_err(|e| format!("connect {url}: {e}"))?;
    let (mut sink, mut stream) = ws.split();
    let (up_tx, up_rx) = mpsc::unbounded();
    let (down_tx, mut down_rx) = mpsc::unbounded::<Frame>();
    tokio::spawn(async move {
        let why = loop {
            match stream.next().await {
                Some(Ok(Message::Binary(b))) => { let _ = up_tx.unbounded_send(Frame::Binary(b)); }
                Some(Ok(Message::Text(t))) => { let _ = up_tx.unbounded_send(Frame::Text(t)); }
                Some(Ok(Message::Close(f))) => break format!("closed {f:?}"),
                Some(Ok(_)) => {}
                Some(Err(e)) => break format!("ws: {e}"),
                None => break "eof".to_string(),
            }
        };
        let _ = up_tx.unbounded_send(Frame::Closed(why));
    });
    tokio::spawn(async move {
        while let Some(f) = down_rx.next().await {
            let m = match f {
                Frame::Binary(b) => Message::Binary(b),
                Frame::Text(t) => Message::Text(t),
                Frame::Closed(_) => break,
            };
            if sink.send(m).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
    Ok(Leg { tx: down_tx, rx: up_rx })
}

#[cfg(target_arch = "wasm32")]
pub async fn open(url: &str) -> Result<Leg, String> {
    use futures::StreamExt;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;
    use web_sys::{BinaryType, CloseEvent, Event, MessageEvent, WebSocket};

    let ws = WebSocket::new(url).map_err(|e| format!("WebSocket {url}: {e:?}"))?;
    ws.set_binary_type(BinaryType::Arraybuffer);
    let (up_tx, up_rx) = mpsc::unbounded();
    let (open_tx, mut open_rx) = mpsc::unbounded::<Result<(), String>>();

    let t = up_tx.clone();
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
        let d = e.data();
        if let Ok(ab) = d.clone().dyn_into::<js_sys::ArrayBuffer>() {
            let _ = t.unbounded_send(Frame::Binary(js_sys::Uint8Array::new(&ab).to_vec()));
        } else if let Some(s) = d.as_string() {
            let _ = t.unbounded_send(Frame::Text(s));
        }
    });
    let (t, o) = (up_tx.clone(), open_tx.clone());
    let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |e: CloseEvent| {
        let why = format!("closed {} {}", e.code(), e.reason());
        let _ = o.unbounded_send(Err(why.clone()));
        let _ = t.unbounded_send(Frame::Closed(why));
    });
    let o = open_tx.clone();
    let on_open = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
        let _ = o.unbounded_send(Ok(()));
    });
    let on_error = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
        let _ = open_tx.unbounded_send(Err("websocket error".into()));
    });
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    match open_rx.next().await {
        Some(Ok(())) => {}
        Some(Err(e)) => return Err(format!("{url}: {e}")),
        None => return Err(format!("{url}: no open")),
    }
    let (down_tx, mut down_rx) = mpsc::unbounded::<Frame>();
    wasm_bindgen_futures::spawn_local(async move {
        // the closures live as long as this task: the socket is closed and they are dropped together
        let _keep = (on_message, on_close, on_open, on_error);
        while let Some(f) = down_rx.next().await {
            let r = match f {
                Frame::Binary(b) => ws.send_with_u8_array(&b),
                Frame::Text(t) => ws.send_with_str(&t),
                Frame::Closed(_) => break,
            };
            if r.is_err() {
                break;
            }
        }
        ws.set_onmessage(None);
        ws.set_onclose(None);
        ws.set_onopen(None);
        ws.set_onerror(None);
        let _ = ws.close();
        let _ = up_tx.unbounded_send(Frame::Closed("closed by client".into()));
    });
    Ok(Leg { tx: down_tx, rx: up_rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_split_under_max_and_unpack() {
        let pkts: Vec<Vec<u8>> = (0..40).map(|i| vec![i as u8; 1300]).collect();
        let b = batches(pkts.clone());
        assert!(b.len() > 1 && b.iter().all(|f| f.len() <= BATCH_MAX));
        let back: Vec<Vec<u8>> = b.iter().flat_map(|f| unpack(f).into_iter().map(|p| p.to_vec())).collect();
        assert_eq!(back, pkts);
        assert!(unpack(&[0, 9, 1, 2]).is_empty());
    }
}
