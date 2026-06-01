//! Thin RPC helpers for the relayer. Mirrors seal-faucet's hand-
//! rolled tokio TcpStream approach so we don't drag reqwest +
//! hyper-rustls into the relayer binary — the surface here is
//! 4 calls (load_keyfile + 3 RPC verbs) and adding a heavy HTTP
//! client crate for that is not worth the build-time cost.

use crate::WithdrawalRecord;
use seal_crypto::{hash::sha3_256, signature::SigningKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn load_keyfile(path: &str) -> Result<(SigningKey, String, String), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("parse: {e}"))?;
    let sk_hex = v
        .get("signing_key")
        .and_then(|x| x.as_str())
        .ok_or("missing 'signing_key'")?;
    let vk_hex = v
        .get("verifying_key")
        .and_then(|x| x.as_str())
        .ok_or("missing 'verifying_key'")?;
    let address = v
        .get("address")
        .and_then(|x| x.as_str())
        .ok_or("missing 'address'")?;
    let sk_bytes = hex::decode(sk_hex).map_err(|e| format!("signing_key hex: {e}"))?;
    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| format!("signing key: {e}"))?;
    Ok((sk, vk_hex.to_string(), address.to_string()))
}

async fn rpc_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let host = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let host = host.trim_end_matches('/');
    let mut stream = tokio::net::TcpStream::connect(host)
        .await
        .map_err(|e| format!("connect {host}: {e}"))?;
    let body_str = body.to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("send: {e}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("read: {e}"))?;
    let response_str = String::from_utf8_lossy(&response);
    let json_start = response_str
        .find("\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| "bad HTTP response".to_string())?;
    serde_json::from_str(&response_str[json_start..]).map_err(|e| format!("parse: {e}"))
}

fn sign_request(
    sk: &SigningKey,
    vk_hex: &str,
    method: &str,
    params: &serde_json::Value,
) -> Result<(String, String), String> {
    let params_json = serde_json::to_string(params).map_err(|e| e.to_string())?;
    let message = format!("{method}{params_json}");
    let hash = sha3_256(message.as_bytes());
    let sig = sk.sign(hash.as_ref()).map_err(|e| e.to_string())?;
    Ok((hex::encode(sig.to_bytes()), vk_hex.to_string()))
}

pub async fn list_bridge_withdrawals(url: &str) -> Result<Vec<WithdrawalRecord>, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "seal_listBridgeWithdrawals",
        "params": {},
        "id": 1,
    });
    let resp = rpc_post(url, &body).await?;
    if let Some(err) = resp.get("error") {
        return Err(format!("seal_listBridgeWithdrawals: {err}"));
    }
    let list = resp
        .get("result")
        .and_then(|r| r.get("withdrawals"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing result.withdrawals".to_string())?
        .clone();
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        match serde_json::from_value::<WithdrawalRecord>(entry.clone()) {
            Ok(rec) => out.push(rec),
            Err(e) => tracing::warn!(error = %e, raw = %entry, "skip malformed withdrawal"),
        }
    }
    Ok(out)
}

pub async fn get_bridge_withdrawal(
    url: &str,
    withdrawal_id: &str,
) -> Result<Option<WithdrawalRecord>, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "seal_getBridgeWithdrawal",
        "params": {"withdrawal_id": withdrawal_id},
        "id": 1,
    });
    let resp = rpc_post(url, &body).await?;
    if let Some(err) = resp.get("error") {
        return Err(format!("seal_getBridgeWithdrawal: {err}"));
    }
    let withdrawal = resp
        .get("result")
        .and_then(|r| r.get("withdrawal"))
        .cloned();
    match withdrawal {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => serde_json::from_value::<WithdrawalRecord>(v)
            .map(Some)
            .map_err(|e| format!("parse withdrawal: {e}")),
    }
}

/// Returns the `was_already_executed` flag from the response, so the
/// caller can log race-loser vs first-write paths.
///
/// `vk_hex` is the hex-encoded verifying key from the relayer's
/// keyfile — passed in rather than re-derived from `sk` because the
/// SigningKey type doesn't expose a verifying-key getter.
pub async fn bridge_mark_executed(
    url: &str,
    sk: &SigningKey,
    vk_hex: &str,
    withdrawal_id: &str,
    dest_chain_tx_hash: Option<&str>,
) -> Result<bool, String> {
    let mut params = serde_json::json!({ "withdrawal_id": withdrawal_id });
    if let Some(h) = dest_chain_tx_hash {
        params["dest_chain_tx_hash"] = serde_json::Value::String(h.to_string());
    }
    let (sig, sender) = sign_request(sk, vk_hex, "seal_bridgeMarkExecuted", &params)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "seal_bridgeMarkExecuted",
        "params": params,
        "id": 1,
        "signature": sig,
        "sender": sender,
    });
    let resp = rpc_post(url, &body).await?;
    if let Some(err) = resp.get("error") {
        return Err(format!("seal_bridgeMarkExecuted: {err}"));
    }
    let was_already = resp
        .get("result")
        .and_then(|r| r.get("was_already_executed"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(was_already)
}
