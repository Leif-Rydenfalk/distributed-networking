//! The two runtimes: tokio natively, the browser's event loop on wasm32.

use std::future::Future;
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn<F: Future<Output = ()> + Send + 'static>(f: F) {
    tokio::spawn(f);
}

#[cfg(target_arch = "wasm32")]
pub fn spawn<F: Future<Output = ()> + 'static>(f: F) {
    wasm_bindgen_futures::spawn_local(f);
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(d: Duration) {
    tokio::time::sleep(d).await
}

#[cfg(target_arch = "wasm32")]
mod js {
    use wasm_bindgen::prelude::*;
    #[wasm_bindgen]
    extern "C" {
        // the global setTimeout: windows, workers and node all have it
        #[wasm_bindgen(js_name = setTimeout)]
        pub fn set_timeout(f: &js_sys::Function, ms: i32) -> JsValue;
    }
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(d: Duration) {
    let ms = d.as_millis().min(i32::MAX as u128) as i32;
    let p = js_sys::Promise::new(&mut |resolve, _| {
        js::set_timeout(&resolve, ms);
    });
    let _ = wasm_bindgen_futures::JsFuture::from(p).await;
}
