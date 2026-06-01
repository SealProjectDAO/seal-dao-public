//! `seal-forms` demo binary.
//!
//! Walks through the canonical forms.seal flow:
//!   1. Owner creates a form (publishes ML-KEM pubkey + schema)
//!   2. Three respondents submit encrypted answers, each linked into
//!      the trace chain
//!   3. Auditor verifies the trace chain end-to-end without decrypting
//!   4. Owner decrypts to read the answers
//!
//! Output is plaintext; nothing is sent over a network. Pair with
//! `cargo run -p seal-node` if you want to see the rows actually land
//! on chain — the schema lives in `SCHEMA_DDL` and is the same one
//! the appstore would deploy.

use seal_crypto::kem::KemKeypair;
use seal_forms::{
    decrypt_answer, encrypt_answer, genesis_trace, schema_hash, verify_trace, AnswerContext,
    FormRecord, ResponseRecord, SCHEMA_DDL,
};
use seal_wallet::Wallet;

fn main() {
    println!("=== forms.seal — encrypted survey demo ===\n");

    println!("DDL the appstore deploys:\n{}\n", SCHEMA_DDL.trim());

    // ── Owner setup ────────────────────────────────────────────────
    let owner_wallet = Wallet::generate(true);
    let owner_addr = owner_wallet.address().to_string();
    let form_kp = KemKeypair::generate();
    let form_id: u64 = 1;
    let schema_json =
        r#"{"questions":[{"id":"q1","prompt":"Are PQC signatures fast enough?","type":"text"}]}"#;
    let schema_h = schema_hash(schema_json);
    let genesis = genesis_trace(form_id, &owner_addr, schema_json);

    let form = FormRecord {
        id: form_id,
        owner: owner_addr,
        schema_json: schema_json.into(),
        mlkem_pk_hex: hex::encode(form_kp.public.to_bytes()),
        genesis_trace_hex: hex::encode(genesis),
        created_at_height: 0,
    };
    println!("Form created:");
    println!("  id              = {}", form.id);
    println!("  owner           = {}", form.owner);
    println!("  ml-kem pk       = {}…", &form.mlkem_pk_hex[..32]);
    println!("  genesis trace   = {}\n", form.genesis_trace_hex);

    // ── Respondents ────────────────────────────────────────────────
    let respondents = ["respondent-alice", "respondent-bob", "respondent-eve"];
    let answers = ["yes, easily", "depends on the curve", "no comment"];
    let mut prev_trace = genesis;
    let mut responses: Vec<ResponseRecord> = Vec::new();

    for (i, (addr, ans)) in respondents.iter().zip(answers.iter()).enumerate() {
        let ctx = AnswerContext {
            form_id,
            schema_hash: schema_h,
            respondent_addr: addr,
            idx: i as u64,
        };
        let enc = encrypt_answer(&form_kp.public, &prev_trace, &ctx, ans.as_bytes());
        let response = ResponseRecord {
            form_id,
            respondent_addr: (*addr).to_string(),
            kem_ct_hex: hex::encode(enc.kem_ct.to_bytes()),
            answer_ct_hex: hex::encode(&enc.answer_ct),
            trace_hash_hex: hex::encode(enc.trace_hash),
            prev_trace_hash_hex: hex::encode(prev_trace),
            // Real flow signs `(form_id || trace_hash)` with the
            // respondent's ML-DSA key. Demo elides this for brevity.
            sig_hex: "demo:unsigned".into(),
            block_height: (i as u64) + 1,
        };
        println!("Response {}", i + 1);
        println!("  by              {}", response.respondent_addr);
        println!("  prev trace      {}", response.prev_trace_hash_hex);
        println!("  trace_hash      {}", response.trace_hash_hex);
        prev_trace = enc.trace_hash;
        responses.push(response);
    }

    // ── Auditor ────────────────────────────────────────────────────
    println!("\nAuditor walk: re-derive each trace from genesis without decrypting.");
    let mut walk = genesis;
    for (i, r) in responses.iter().enumerate() {
        let answer_ct = hex::decode(&r.answer_ct_hex).expect("hex");
        let expected: [u8; 32] = hex::decode(&r.trace_hash_hex)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let ok = verify_trace(&walk, &answer_ct, &expected);
        println!("  response {}  trace verifies: {}", i + 1, ok);
        assert!(ok, "trace chain broken at response {}", i + 1);
        walk = expected;
    }

    // ── Owner decrypts ────────────────────────────────────────────
    println!("\nOwner decrypts each response with the form's ML-KEM secret key:");
    for (i, r) in responses.iter().enumerate() {
        let kem_ct_bytes = hex::decode(&r.kem_ct_hex).expect("hex");
        let kem_ct = seal_crypto::kem::KemCiphertext::from_bytes(kem_ct_bytes);
        let answer_ct = hex::decode(&r.answer_ct_hex).expect("hex");
        let ctx = AnswerContext {
            form_id,
            schema_hash: schema_h,
            respondent_addr: &r.respondent_addr,
            idx: i as u64,
        };
        let plaintext =
            decrypt_answer(&form_kp.secret, &kem_ct, &ctx, &answer_ct).expect("AES-GCM decrypt");
        let s = String::from_utf8_lossy(&plaintext);
        println!("  response {}  → \"{}\"", i + 1, s);
    }

    println!("\nDone. The trace chain is the structure that future ZK statistics commit to.");
}
