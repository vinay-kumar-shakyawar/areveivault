//! WASM boundary: one JSON dispatcher over a single engine instance per Worker.
//! Returns `{"ok": ...}` or `{"error": "..."}` as a JSON string.

use std::cell::RefCell;

use wasm_bindgen::prelude::*;

use crate::engine::Engine;

thread_local! {
    static ENGINE: RefCell<Engine> = RefCell::new(Engine::new());
}

#[wasm_bindgen]
pub fn call(method: &str, args: &str) -> String {
    let parsed = match serde_json::from_str(if args.is_empty() { "{}" } else { args }) {
        Ok(v) => v,
        Err(e) => return serde_json::json!({ "error": format!("invalid arguments: {e}") }).to_string(),
    };
    let result = ENGINE.with(|e| e.borrow_mut().call(method, parsed));
    match result {
        Ok(v) => serde_json::json!({ "ok": v }).to_string(),
        Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
    }
}
