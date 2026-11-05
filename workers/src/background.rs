use std::future::Future;
use std::panic::AssertUnwindSafe;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen(raw_module = "cloudflare:workers")]
extern "C" {
    #[wasm_bindgen(js_name = waitUntil)]
    fn wait_until_js(promise: &js_sys::Promise);
}

/// Schedule a fire-and-forget background task via `waitUntil`.
///
/// The response is sent to the client immediately; the Worker keeps running
/// until the future settles (up to the 30-second `waitUntil` budget).
pub fn spawn_background<F>(future: F)
where
    F: Future<Output = ()> + 'static,
{
    let promise = future_to_promise(AssertUnwindSafe(async {
        future.await;
        Ok(JsValue::UNDEFINED)
    }));
    wait_until_js(&promise);
}
