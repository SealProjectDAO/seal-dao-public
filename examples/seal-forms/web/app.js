// forms.seal — minimal browser frontend.
//
// Talks to a Seal node over JSON-RPC and uses the workspace WASM SDK
// for ML-KEM encapsulation + SHA3 trace hashing. The SDK is
// optionally loaded; if missing, the page falls back to read-only
// inspection.

import init, * as sdk from "../../../sdks/wasm/pkg/seal_dao_wasm.js";

const $ = (id) => document.getElementById(id);

let state = {
  rpcUrl: null,
  formId: null,
  formMeta: null,
  encrypted: null, // { kem_ct_hex, answer_ct_hex, trace_hash_hex }
  prevTraceHex: null,
};

let sdkReady = false;
init()
  .then(() => { sdkReady = true; })
  .catch((e) => {
    console.warn("SDK not available:", e);
    note("encrypted",
      "(SDK module not built — encrypt button disabled. " +
      "Run `cd sdks/wasm && ./build.sh`.)");
  });

// ---------- RPC helpers ----------

async function rpcCall(method, params) {
  const body = {
    jsonrpc: "2.0",
    id: Date.now(),
    method,
    params: params ?? [],
  };
  const r = await fetch(state.rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`RPC ${method} -> HTTP ${r.status}`);
  const j = await r.json();
  if (j.error) throw new Error(`RPC ${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}

function note(targetId, text) {
  $(targetId).textContent = text;
}

// ---------- 1. Connect ----------

$("rpc-test").addEventListener("click", async () => {
  state.rpcUrl = $("rpc-url").value.trim();
  try {
    const r = await rpcCall("seal_status", []);
    note("rpc-status", JSON.stringify(r, null, 2));
  } catch (e) {
    note("rpc-status", `failed: ${e.message}`);
  }
});

// ---------- 2. Load form ----------

$("form-load").addEventListener("click", async () => {
  if (!state.rpcUrl) {
    note("form-meta", "connect to a Seal node first");
    return;
  }
  state.formId = parseInt($("form-id").value, 10);
  try {
    // The schema chosen by `forms.seal` is documented in
    // examples/seal-forms/src/lib.rs::SCHEMA_DDL.
    const sql = `SELECT id, owner, schema_json, mlkem_pk_hex, ` +
                `genesis_trace_hex FROM forms WHERE id = ${state.formId}`;
    const result = await rpcCall("seal_querySql", [sql]);
    if (!result.rows || result.rows.length === 0) {
      throw new Error("form not found");
    }
    const r = result.rows[0];
    state.formMeta = {
      id: r[0], owner: r[1], schema_json: r[2],
      mlkem_pk_hex: r[3], genesis_trace_hex: r[4],
    };
    state.prevTraceHex = state.formMeta.genesis_trace_hex;
    note("form-meta",
      `id=${state.formMeta.id}\nowner=${state.formMeta.owner}\n` +
      `schema=${state.formMeta.schema_json}\n` +
      `pk=${state.formMeta.mlkem_pk_hex.slice(0, 32)}...`);
    $("answer-prompt").textContent =
      `Form #${state.formMeta.id}: ${state.formMeta.schema_json}`;
    $("encrypt-btn").disabled = false;
  } catch (e) {
    note("form-meta", `failed: ${e.message}`);
  }
});

// ---------- 3. Answer ----------

$("encrypt-btn").addEventListener("click", () => {
  if (!sdkReady) {
    note("encrypted", "SDK not loaded yet — try again in a moment");
    return;
  }
  const plaintext = $("answer-text").value;
  if (!plaintext) {
    note("encrypted", "type an answer first");
    return;
  }
  try {
    const out = sdk.encrypt_form_answer(
      state.formMeta.mlkem_pk_hex,
      state.prevTraceHex,
      plaintext,
    );
    state.encrypted = JSON.parse(out);
    note("encrypted", JSON.stringify(state.encrypted, null, 2));
    $("submit-btn").disabled = false;
  } catch (e) {
    note("encrypted", `encrypt failed: ${e.message}`);
  }
});

$("submit-btn").addEventListener("click", async () => {
  if (!state.encrypted) return;
  try {
    // INSERT into the responses table over the chain. Production
    // would route through a wallet that signs the tx; this demo
    // assumes the RPC node accepts unsigned writes from localhost.
    const sql = `INSERT INTO responses ` +
      `(form_id, respondent_addr, kem_ct_hex, answer_ct_hex, ` +
      ` trace_hash_hex, prev_trace_hash_hex, sig_hex, block_height) ` +
      `VALUES (${state.formMeta.id}, 'browser-demo', ` +
      `'${state.encrypted.kem_ct_hex}', ` +
      `'${state.encrypted.answer_ct_hex}', ` +
      `'${state.encrypted.trace_hash_hex}', ` +
      `'${state.prevTraceHex}', '00', 0)`;
    const r = await rpcCall("seal_submitSql", [sql]);
    note("encrypted", `submitted: ${JSON.stringify(r)}`);
    state.prevTraceHex = state.encrypted.trace_hash_hex;
  } catch (e) {
    note("encrypted", `submit failed: ${e.message}`);
  }
});

// ---------- 4. Audit ----------

$("audit-btn").addEventListener("click", async () => {
  if (!state.formMeta) {
    note("audit-status", "load a form first");
    return;
  }
  try {
    const sql =
      `SELECT prev_trace_hash_hex, answer_ct_hex, trace_hash_hex ` +
      `FROM responses WHERE form_id = ${state.formMeta.id} ` +
      `ORDER BY block_height ASC`;
    const result = await rpcCall("seal_querySql", [sql]);
    let walk = state.formMeta.genesis_trace_hex;
    let ok = true;
    for (const row of result.rows ?? []) {
      const [prev, ct, claimed] = row;
      if (prev !== walk) { ok = false; break; }
      const recomputed = sdk.next_trace(walk, ct);
      if (recomputed !== claimed) { ok = false; break; }
      walk = claimed;
    }
    note("audit-status",
      ok ? `chain OK (${result.rows?.length ?? 0} responses)` :
           "chain BROKEN — stop trusting this form");
  } catch (e) {
    note("audit-status", `audit failed: ${e.message}`);
  }
});
