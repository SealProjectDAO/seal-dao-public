//! HTTP transport abstraction for chain observers.
//!
//! All outbound network I/O for bridge observers goes through the
//! [`HttpTransport`] trait. This lets tests inject canned responses
//! without a live network. The real implementation is a thin wrapper
//! around `reqwest::blocking`.

use std::time::Duration;

use serde_json::Value;

use crate::error::BridgeError;

/// An HTTP call performed by an observer.
///
/// Abstracted so unit tests can substitute a `MockTransport` that
/// returns pre-recorded response bodies for the exact (method, url,
/// body) they care about.
pub trait HttpTransport: Send + Sync {
    /// POST a JSON body and return the parsed JSON response.
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, BridgeError>;

    /// GET a URL and return the parsed JSON response.
    fn get_json(&self, url: &str) -> Result<Value, BridgeError>;
}

/// Real implementation backed by `reqwest::blocking`.
///
/// Used in production. For tests, prefer `MockTransport` so we don't
/// depend on a reachable network / running testnet.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client builder");
        Self { client }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpTransport for ReqwestTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, BridgeError> {
        let resp = self
            .client
            .post(url)
            .json(body)
            .send()
            .map_err(|e| BridgeError::RpcError(format!("POST {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(BridgeError::RpcError(format!(
                "POST {url}: HTTP {}",
                resp.status()
            )));
        }
        resp.json()
            .map_err(|e| BridgeError::RpcError(format!("POST {url}: json decode: {e}")))
    }

    fn get_json(&self, url: &str) -> Result<Value, BridgeError> {
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| BridgeError::RpcError(format!("GET {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(BridgeError::RpcError(format!(
                "GET {url}: HTTP {}",
                resp.status()
            )));
        }
        resp.json()
            .map_err(|e| BridgeError::RpcError(format!("GET {url}: json decode: {e}")))
    }
}

// ── Test helper ─────────────────────────────────────────────

/// In-memory transport that replays canned responses. Useful for unit
/// tests that need to exercise the full observer parse path without
/// hitting a real chain.
#[cfg(any(test, feature = "mock-transport"))]
pub struct MockTransport {
    /// Keyed by (method, url). Returns the next response in the vec on
    /// each call. Panics in tests if exhausted (fail loud, not silent).
    responses: std::sync::Mutex<std::collections::HashMap<(String, String), Vec<Value>>>,
}

#[cfg(any(test, feature = "mock-transport"))]
impl MockTransport {
    pub fn new() -> Self {
        Self {
            responses: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Enqueue a canned response for the next matching request.
    pub fn enqueue(&self, method: &str, url: &str, response: Value) {
        let key = (method.to_string(), url.to_string());
        let mut map = self.responses.lock().unwrap();
        map.entry(key).or_default().push(response);
    }

    fn pop(&self, method: &str, url: &str) -> Result<Value, BridgeError> {
        let key = (method.to_string(), url.to_string());
        let mut map = self.responses.lock().unwrap();
        let queue = map.get_mut(&key).ok_or_else(|| {
            BridgeError::RpcError(format!(
                "MockTransport: no enqueued response for {method} {url}"
            ))
        })?;
        if queue.is_empty() {
            return Err(BridgeError::RpcError(format!(
                "MockTransport: queue for {method} {url} is empty"
            )));
        }
        Ok(queue.remove(0))
    }
}

#[cfg(any(test, feature = "mock-transport"))]
impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "mock-transport"))]
impl HttpTransport for MockTransport {
    fn post_json(&self, url: &str, _body: &Value) -> Result<Value, BridgeError> {
        self.pop("POST", url)
    }
    fn get_json(&self, url: &str) -> Result<Value, BridgeError> {
        self.pop("GET", url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mock_transport_returns_enqueued_response() {
        let t = MockTransport::new();
        t.enqueue("POST", "http://x/y", json!({"result": 42}));
        let got = t.post_json("http://x/y", &json!({})).unwrap();
        assert_eq!(got["result"], 42);
    }

    #[test]
    fn mock_transport_empty_queue_errors() {
        let t = MockTransport::new();
        let err = t.get_json("http://missing").unwrap_err();
        assert!(format!("{err}").contains("no enqueued response"));
    }

    #[test]
    fn mock_transport_fifo_order() {
        let t = MockTransport::new();
        t.enqueue("GET", "http://x", json!(1));
        t.enqueue("GET", "http://x", json!(2));
        assert_eq!(t.get_json("http://x").unwrap(), json!(1));
        assert_eq!(t.get_json("http://x").unwrap(), json!(2));
    }
}
