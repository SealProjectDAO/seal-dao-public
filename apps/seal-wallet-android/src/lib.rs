//! Seal Wallet FFI — C-ABI bridge for Android (JNI) and iOS.
//!
//! All cryptographic operations happen in Rust. The mobile UI
//! calls these functions via JNI (Android) or Swift bridging (iOS).
//!
//! # Safety
//!
//! All exported functions use C-compatible types:
//! - Strings passed as `*const c_char` (null-terminated UTF-8)
//! - Strings returned as `*mut c_char` (caller must free with `seal_free_string`)
//! - Booleans as `i32` (0 = false, 1 = true)
//!
//! # Android (JNI) Usage
//!
//! ```kotlin
//! // Load native library
//! System.loadLibrary("seal_wallet_ffi")
//!
//! // Declare native methods
//! external fun sealCreateWallet(testnet: Boolean): String
//! external fun sealImportWallet(mnemonicHex: String, testnet: Boolean): String
//! external fun sealGetAddress(): String
//! external fun sealSignMessage(message: String): String
//! external fun sealVerifySignature(message: String, signatureHex: String): Boolean
//! external fun sealExportMnemonic(): String
//! external fun sealExportMnemonicBip39(): String
//! ```
//!
//! # Build
//!
//! ```bash
//! # For Android (aarch64)
//! cargo build --target aarch64-linux-android --release
//!
//! # For Android (x86_64 emulator)
//! cargo build --target x86_64-linux-android --release
//!
//! # Output: target/<target>/release/libseal_wallet_ffi.so
//! # Copy to: app/src/main/jniLibs/arm64-v8a/libseal_wallet_ffi.so
//! ```

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

use seal_wallet::keystore::Wallet;
use seal_wallet::mnemonic::Seed;

/// Global wallet state (protected by mutex for thread safety).
static WALLET: Mutex<Option<WalletState>> = Mutex::new(None);

struct WalletState {
    wallet: Wallet,
    seed_bytes: [u8; 32],
}

// --- Helpers ---

/// Convert a C string to a Rust &str. Returns empty string on null/invalid.
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    CStr::from_ptr(ptr).to_str().unwrap_or("")
}

/// Convert a Rust string to a C string. Caller must free with `seal_free_string`.
fn str_to_cstr(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

/// Free a string returned by any seal_* function.
///
/// # Safety
/// `ptr` must be a pointer returned by a `seal_*` function, or null.
#[no_mangle]
pub unsafe extern "C" fn seal_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// --- Wallet lifecycle ---

/// Create a new random wallet. Returns WalletInfo as JSON string.
///
/// # Safety
/// Returned string must be freed with `seal_free_string`.
#[no_mangle]
pub extern "C" fn seal_create_wallet(testnet: i32) -> *mut c_char {
    let testnet = testnet != 0;
    let seed = Seed::generate();
    let seed_hex = seed.to_hex();
    let seed_bytes_vec = hex::decode(&seed_hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed_bytes_vec);

    let wallet = Wallet::from_seed(seed, testnet);
    let json = serde_json::to_string(&wallet.info()).unwrap_or_default();

    *WALLET.lock().unwrap() = Some(WalletState {
        wallet,
        seed_bytes: arr,
    });

    str_to_cstr(&json)
}

/// Import a wallet from a hex mnemonic. Returns WalletInfo as JSON string.
///
/// # Safety
/// `mnemonic_hex` must be a valid null-terminated UTF-8 string.
/// Returned string must be freed with `seal_free_string`.
#[no_mangle]
pub unsafe extern "C" fn seal_import_wallet(
    mnemonic_hex: *const c_char,
    testnet: i32,
) -> *mut c_char {
    let hex_str = cstr_to_str(mnemonic_hex);
    let testnet = testnet != 0;

    let seed = match Seed::from_hex(hex_str) {
        Ok(s) => s,
        Err(e) => return str_to_cstr(&format!("{{\"error\":\"{}\"}}", e)),
    };

    let seed_hex = seed.to_hex();
    let seed_bytes_vec = hex::decode(&seed_hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed_bytes_vec);

    let wallet = Wallet::from_seed(seed, testnet);
    let json = serde_json::to_string(&wallet.info()).unwrap_or_default();

    *WALLET.lock().unwrap() = Some(WalletState {
        wallet,
        seed_bytes: arr,
    });

    str_to_cstr(&json)
}

/// Import a wallet from BIP-39 24-word mnemonic. Returns WalletInfo as JSON.
///
/// # Safety
/// `words` must be a valid null-terminated UTF-8 string (space-separated).
/// Returned string must be freed with `seal_free_string`.
#[no_mangle]
pub unsafe extern "C" fn seal_import_wallet_bip39(
    words: *const c_char,
    testnet: i32,
) -> *mut c_char {
    let words_str = cstr_to_str(words);
    let testnet = testnet != 0;

    let word_list: Vec<String> = words_str.split_whitespace().map(String::from).collect();
    let entropy = match seal_wallet::bip39::mnemonic_to_entropy(&word_list) {
        Ok(e) => e,
        Err(e) => return str_to_cstr(&format!("{{\"error\":\"{}\"}}", e)),
    };

    let seed = Seed::from_bytes(entropy);
    let seed_hex = seed.to_hex();
    let seed_bytes_vec = hex::decode(&seed_hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed_bytes_vec);

    let wallet = Wallet::from_seed(seed, testnet);
    let json = serde_json::to_string(&wallet.info()).unwrap_or_default();

    *WALLET.lock().unwrap() = Some(WalletState {
        wallet,
        seed_bytes: arr,
    });

    str_to_cstr(&json)
}

// --- Wallet info ---

/// Get the wallet's Seal address (bech32m). Returns empty string if no wallet.
///
/// # Safety
/// Returned string must be freed with `seal_free_string`.
#[no_mangle]
pub extern "C" fn seal_get_address() -> *mut c_char {
    let guard = WALLET.lock().unwrap();
    match guard.as_ref() {
        Some(state) => str_to_cstr(&state.wallet.info().seal_address),
        None => str_to_cstr(""),
    }
}

/// Get wallet info as JSON.
///
/// # Safety
/// Returned string must be freed with `seal_free_string`.
#[no_mangle]
pub extern "C" fn seal_get_wallet_info() -> *mut c_char {
    let guard = WALLET.lock().unwrap();
    match guard.as_ref() {
        Some(state) => {
            let json = serde_json::to_string(&state.wallet.info()).unwrap_or_default();
            str_to_cstr(&json)
        }
        None => str_to_cstr("{}"),
    }
}

// --- Mnemonic export ---

/// Export hex mnemonic (64 chars).
///
/// # Safety
/// Returned string must be freed with `seal_free_string`.
#[no_mangle]
pub extern "C" fn seal_export_mnemonic() -> *mut c_char {
    let guard = WALLET.lock().unwrap();
    match guard.as_ref() {
        Some(state) => str_to_cstr(&hex::encode(state.seed_bytes)),
        None => str_to_cstr(""),
    }
}

/// Export BIP-39 24-word mnemonic.
///
/// # Safety
/// Returned string must be freed with `seal_free_string`.
#[no_mangle]
pub extern "C" fn seal_export_mnemonic_bip39() -> *mut c_char {
    let guard = WALLET.lock().unwrap();
    match guard.as_ref() {
        Some(state) => {
            let words = seal_wallet::bip39::entropy_to_mnemonic(&state.seed_bytes);
            str_to_cstr(&words.join(" "))
        }
        None => str_to_cstr(""),
    }
}

// --- Crypto operations ---

/// Sign a message with ML-DSA-65. Returns signature as hex string.
///
/// # Safety
/// `message` must be valid null-terminated UTF-8.
/// Returned string must be freed with `seal_free_string`.
#[no_mangle]
pub unsafe extern "C" fn seal_sign_message(message: *const c_char) -> *mut c_char {
    let msg = cstr_to_str(message);
    let guard = WALLET.lock().unwrap();
    match guard.as_ref() {
        Some(state) => {
            match state.wallet.sign(msg.as_bytes()) {
                Ok(sig) => str_to_cstr(&hex::encode(sig.to_bytes())),
                Err(_) => str_to_cstr(""),
            }
        }
        None => str_to_cstr(""),
    }
}

/// Verify a signature. Returns 1 if valid, 0 if invalid.
///
/// # Safety
/// Both `message` and `signature_hex` must be valid null-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn seal_verify_signature(
    message: *const c_char,
    signature_hex: *const c_char,
) -> i32 {
    let msg = cstr_to_str(message);
    let sig_hex = cstr_to_str(signature_hex);

    let guard = WALLET.lock().unwrap();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => return 0,
    };

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    let sig = seal_crypto::signature::Signature::from_bytes(sig_bytes);
    let vk_bytes = match hex::decode(&state.wallet.info().seal_pubkey_hex) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    let vk = match seal_crypto::signature::VerifyingKey::from_bytes(&vk_bytes) {
        Ok(k) => k,
        Err(_) => return 0,
    };

    if vk.verify(msg.as_bytes(), &sig).is_ok() {
        1
    } else {
        0
    }
}

/// Check if a wallet is loaded.
#[no_mangle]
pub extern "C" fn seal_has_wallet() -> i32 {
    if WALLET.lock().unwrap().is_some() {
        1
    } else {
        0
    }
}

/// Lock (unload) the current wallet.
#[no_mangle]
pub extern "C" fn seal_lock_wallet() {
    *WALLET.lock().unwrap() = None;
}

// ─── RPC Functions ─────────────────────────────────────

/// Query a node's chain height. Returns JSON string.
#[no_mangle]
pub unsafe extern "C" fn seal_rpc_get_height(node_url: *const c_char) -> *mut c_char {
    let url = cstr_to_str(node_url);
    match rpc_call(&url, "seal_getHeight", "{}") {
        Ok(resp) => str_to_cstr(&resp),
        Err(e) => str_to_cstr(&format!("{{\"error\":\"{}\"}}", e)),
    }
}

/// Query SQL on a node. Returns JSON string.
#[no_mangle]
pub unsafe extern "C" fn seal_rpc_query(node_url: *const c_char, sql: *const c_char) -> *mut c_char {
    let url = cstr_to_str(node_url);
    let sql = cstr_to_str(sql);
    let params = format!("{{\"sql\":\"{}\"}}", sql.replace('"', "\\\""));
    match rpc_call(&url, "seal_querySql", &params) {
        Ok(resp) => str_to_cstr(&resp),
        Err(e) => str_to_cstr(&format!("{{\"error\":\"{}\"}}", e)),
    }
}

/// Send a signed SQL transaction. Returns JSON string.
#[no_mangle]
pub unsafe extern "C" fn seal_rpc_send(node_url: *const c_char, sql: *const c_char) -> *mut c_char {
    let url = cstr_to_str(node_url);
    let sql_str = cstr_to_str(sql);

    let guard = WALLET.lock().unwrap();
    let state = match guard.as_ref() {
        Some(s) => s,
        None => return str_to_cstr("{\"error\":\"no wallet loaded\"}"),
    };

    let params_json = format!("{{\"sql\":\"{}\"}}", sql_str.replace('"', "\\\""));
    let message = format!("seal_submitSql{}", params_json);
    let message_hash = seal_crypto::hash::sha3_256(message.as_bytes());

    let sig = match state.wallet.sign(message_hash.as_ref()) {
        Ok(s) => s,
        Err(e) => return str_to_cstr(&format!("{{\"error\":\"signing: {}\"}}", e)),
    };

    let vk = state.wallet.verifying_key();
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"seal_submitSql\",\"params\":{},\"signature\":\"{}\",\"sender\":\"{}\",\"id\":1}}",
        params_json,
        hex::encode(sig.to_bytes()),
        hex::encode(vk.to_bytes())
    );

    match rpc_post(&url, &body) {
        Ok(resp) => str_to_cstr(&resp),
        Err(e) => str_to_cstr(&format!("{{\"error\":\"{}\"}}", e)),
    }
}

fn rpc_call(url: &str, method: &str, params: &str) -> Result<String, String> {
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"{}\",\"params\":{},\"id\":1}}",
        method, params
    );
    rpc_post(url, &body)
}

fn rpc_post(url: &str, body: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    let addr = url.trim_start_matches("http://");
    let mut stream = std::net::TcpStream::connect(addr)
        .map_err(|e| format!("connect: {}", e))?;
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    stream.write_all(req.as_bytes()).map_err(|e| format!("send: {}", e))?;
    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|e| format!("read: {}", e))?;
    let json_start = response.find("\r\n\r\n").map(|p| p + 4).ok_or("bad response")?;
    Ok(response[json_start..].to_string())
}

/// MPC aggregate query. Returns JSON string.
#[no_mangle]
pub unsafe extern "C" fn seal_rpc_mpc(node_url: *const c_char, function: *const c_char, table: *const c_char, column: *const c_char) -> *mut c_char {
    let url = cstr_to_str(node_url);
    let func = cstr_to_str(function);
    let tbl = cstr_to_str(table);
    let col = cstr_to_str(column);
    let params = format!("{{\"function\":\"{}\",\"table\":\"{}\",\"column\":\"{}\"}}", func, tbl, col);
    match rpc_call(&url, "seal_mpcAggregate", &params) {
        Ok(resp) => str_to_cstr(&resp),
        Err(e) => str_to_cstr(&format!("{{\"error\":\"{}\"}}", e)),
    }
}

/// ZK prove query. Returns JSON string.
#[no_mangle]
pub unsafe extern "C" fn seal_rpc_zk_prove(node_url: *const c_char, table: *const c_char, statement: *const c_char) -> *mut c_char {
    let url = cstr_to_str(node_url);
    let tbl = cstr_to_str(table);
    let stmt = cstr_to_str(statement);
    let params = format!("{{\"table\":\"{}\",\"statement\":\"{}\"}}", tbl, stmt.replace('"', "\\\""));
    match rpc_call(&url, "seal_zkProve", &params) {
        Ok(resp) => str_to_cstr(&resp),
        Err(e) => str_to_cstr(&format!("{{\"error\":\"{}\"}}", e)),
    }
}

// ─── JNI Bridge ─────────────────────────────────────────
// Uses JNI_OnLoad to register natives dynamically.
// They wrap the C-ABI functions above.

#[cfg(target_os = "android")]
mod jni_bridge {
    use super::*;
    use jni::JNIEnv;
    use jni::JavaVM;
    use jni::objects::{JClass, JString};
    use jni::sys::{jint, jstring, JNI_VERSION_1_6, JNINativeMethod};

    fn c_ptr_to_jstring(env: &mut JNIEnv, ptr: *mut c_char) -> jstring {
        if ptr.is_null() {
            return std::ptr::null_mut();
        }
        let s = unsafe { CStr::from_ptr(ptr).to_str().unwrap_or("") };
        let result = match env.new_string(s) {
            Ok(js) => js.into_raw(),
            Err(_) => std::ptr::null_mut(),
        };
        unsafe { seal_free_string(ptr) };
        result
    }

    unsafe extern "system" fn native_create_wallet(
        mut env: JNIEnv, _class: JClass, testnet: jint,
    ) -> jstring {
        let ptr = seal_create_wallet(testnet);
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_import_wallet(
        mut env: JNIEnv, _class: JClass, mnemonic_hex: JString, testnet: jint,
    ) -> jstring {
        let hex: String = env.get_string(&mnemonic_hex).unwrap().into();
        let c_hex = CString::new(hex).unwrap();
        let ptr = seal_import_wallet(c_hex.as_ptr(), testnet);
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_import_wallet_bip39(
        mut env: JNIEnv, _class: JClass, words: JString, testnet: jint,
    ) -> jstring {
        let w: String = env.get_string(&words).unwrap().into();
        let c_w = CString::new(w).unwrap();
        let ptr = seal_import_wallet_bip39(c_w.as_ptr(), testnet);
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_get_address(
        mut env: JNIEnv, _class: JClass,
    ) -> jstring {
        let ptr = seal_get_address();
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_get_wallet_info(
        mut env: JNIEnv, _class: JClass,
    ) -> jstring {
        let ptr = seal_get_wallet_info();
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_export_mnemonic(
        mut env: JNIEnv, _class: JClass,
    ) -> jstring {
        let ptr = seal_export_mnemonic();
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_export_mnemonic_bip39(
        mut env: JNIEnv, _class: JClass,
    ) -> jstring {
        let ptr = seal_export_mnemonic_bip39();
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_sign_message(
        mut env: JNIEnv, _class: JClass, message: JString,
    ) -> jstring {
        let msg: String = env.get_string(&message).unwrap().into();
        let c_msg = CString::new(msg).unwrap();
        let ptr = seal_sign_message(c_msg.as_ptr());
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_verify_signature(
        mut env: JNIEnv, _class: JClass, message: JString, sig_hex: JString,
    ) -> jint {
        let msg: String = env.get_string(&message).unwrap().into();
        let sig: String = env.get_string(&sig_hex).unwrap().into();
        let c_msg = CString::new(msg).unwrap();
        let c_sig = CString::new(sig).unwrap();
        seal_verify_signature(c_msg.as_ptr(), c_sig.as_ptr())
    }

    unsafe extern "system" fn native_rpc_get_height(
        mut env: JNIEnv, _class: JClass, url: JString,
    ) -> jstring {
        let u: String = env.get_string(&url).unwrap().into();
        let c_u = CString::new(u).unwrap();
        let ptr = seal_rpc_get_height(c_u.as_ptr());
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_rpc_query(
        mut env: JNIEnv, _class: JClass, url: JString, sql: JString,
    ) -> jstring {
        let u: String = env.get_string(&url).unwrap().into();
        let s: String = env.get_string(&sql).unwrap().into();
        let c_u = CString::new(u).unwrap();
        let c_s = CString::new(s).unwrap();
        let ptr = seal_rpc_query(c_u.as_ptr(), c_s.as_ptr());
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_rpc_mpc(
        mut env: JNIEnv, _class: JClass, url: JString, function: JString, table: JString, column: JString,
    ) -> jstring {
        let u: String = env.get_string(&url).unwrap().into();
        let f: String = env.get_string(&function).unwrap().into();
        let t: String = env.get_string(&table).unwrap().into();
        let c: String = env.get_string(&column).unwrap().into();
        let c_u = CString::new(u).unwrap();
        let c_f = CString::new(f).unwrap();
        let c_t = CString::new(t).unwrap();
        let c_c = CString::new(c).unwrap();
        let ptr = seal_rpc_mpc(c_u.as_ptr(), c_f.as_ptr(), c_t.as_ptr(), c_c.as_ptr());
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_rpc_zk_prove(
        mut env: JNIEnv, _class: JClass, url: JString, table: JString, statement: JString,
    ) -> jstring {
        let u: String = env.get_string(&url).unwrap().into();
        let t: String = env.get_string(&table).unwrap().into();
        let s: String = env.get_string(&statement).unwrap().into();
        let c_u = CString::new(u).unwrap();
        let c_t = CString::new(t).unwrap();
        let c_s = CString::new(s).unwrap();
        let ptr = seal_rpc_zk_prove(c_u.as_ptr(), c_t.as_ptr(), c_s.as_ptr());
        c_ptr_to_jstring(&mut env, ptr)
    }

    unsafe extern "system" fn native_rpc_send(
        mut env: JNIEnv, _class: JClass, url: JString, sql: JString,
    ) -> jstring {
        let u: String = env.get_string(&url).unwrap().into();
        let s: String = env.get_string(&sql).unwrap().into();
        let c_u = CString::new(u).unwrap();
        let c_s = CString::new(s).unwrap();
        let ptr = seal_rpc_send(c_u.as_ptr(), c_s.as_ptr());
        c_ptr_to_jstring(&mut env, ptr)
    }

    /// Called by the JVM when the library is loaded via System.loadLibrary.
    /// Registers all native methods dynamically — no name mangling needed.
    #[no_mangle]
    pub unsafe extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
        let mut env = match vm.get_env() {
            Ok(env) => env,
            Err(_) => return -1,
        };

        let class = match env.find_class("org/sealdao/wallet/SealNative") {
            Ok(c) => c,
            Err(_) => return -1,
        };

        let methods: &[jni::NativeMethod] = &[
            jni::NativeMethod {
                name: "nativeCreateWallet".into(),
                sig: "(I)Ljava/lang/String;".into(),
                fn_ptr: native_create_wallet as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeImportWallet".into(),
                sig: "(Ljava/lang/String;I)Ljava/lang/String;".into(),
                fn_ptr: native_import_wallet as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeImportWalletBip39".into(),
                sig: "(Ljava/lang/String;I)Ljava/lang/String;".into(),
                fn_ptr: native_import_wallet_bip39 as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeGetAddress".into(),
                sig: "()Ljava/lang/String;".into(),
                fn_ptr: native_get_address as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeGetWalletInfo".into(),
                sig: "()Ljava/lang/String;".into(),
                fn_ptr: native_get_wallet_info as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeExportMnemonic".into(),
                sig: "()Ljava/lang/String;".into(),
                fn_ptr: native_export_mnemonic as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeExportMnemonicBip39".into(),
                sig: "()Ljava/lang/String;".into(),
                fn_ptr: native_export_mnemonic_bip39 as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeSignMessage".into(),
                sig: "(Ljava/lang/String;)Ljava/lang/String;".into(),
                fn_ptr: native_sign_message as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeVerifySignature".into(),
                sig: "(Ljava/lang/String;Ljava/lang/String;)I".into(),
                fn_ptr: native_verify_signature as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeRpcGetHeight".into(),
                sig: "(Ljava/lang/String;)Ljava/lang/String;".into(),
                fn_ptr: native_rpc_get_height as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeRpcQuery".into(),
                sig: "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;".into(),
                fn_ptr: native_rpc_query as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeRpcSend".into(),
                sig: "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;".into(),
                fn_ptr: native_rpc_send as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeRpcMpc".into(),
                sig: "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;".into(),
                fn_ptr: native_rpc_mpc as *mut std::ffi::c_void,
            },
            jni::NativeMethod {
                name: "nativeRpcZkProve".into(),
                sig: "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;".into(),
                fn_ptr: native_rpc_zk_prove as *mut std::ffi::c_void,
            },
        ];

        if env.register_native_methods(&class, methods).is_err() {
            return -1;
        }

        JNI_VERSION_1_6
    }
}

/// Tests share global WALLET state — run single-threaded:
///   cargo test --manifest-path apps/seal-wallet-android/Cargo.toml -- --test-threads=1
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get_address() {

        let json_ptr = seal_create_wallet(1); // testnet
        let json = unsafe { CStr::from_ptr(json_ptr).to_str().unwrap().to_string() };
        unsafe { seal_free_string(json_ptr) };

        assert!(json.contains("sealt1"));

        let addr_ptr = seal_get_address();
        let addr = unsafe { CStr::from_ptr(addr_ptr).to_str().unwrap().to_string() };
        unsafe { seal_free_string(addr_ptr) };

        assert!(addr.starts_with("sealt1"));
    }

    #[test]
    fn test_sign_and_verify() {

        let json_ptr = seal_create_wallet(1);
        unsafe { seal_free_string(json_ptr) };

        let msg = CString::new("hello seal ffi").unwrap();
        let sig_ptr = unsafe { seal_sign_message(msg.as_ptr()) };
        let sig_hex = unsafe { CStr::from_ptr(sig_ptr).to_str().unwrap().to_string() };
        unsafe { seal_free_string(sig_ptr) };

        assert!(!sig_hex.is_empty(), "signature should not be empty");

        let sig_cstr = CString::new(sig_hex).unwrap();
        let valid = unsafe { seal_verify_signature(msg.as_ptr(), sig_cstr.as_ptr()) };
        assert_eq!(valid, 1, "valid signature should verify");

        let wrong_msg = CString::new("wrong message").unwrap();
        let invalid = unsafe { seal_verify_signature(wrong_msg.as_ptr(), sig_cstr.as_ptr()) };
        assert_eq!(invalid, 0, "wrong message should not verify");
    }

    #[test]
    fn test_export_mnemonic() {

        seal_create_wallet(1);

        let hex_ptr = seal_export_mnemonic();
        let hex_str = unsafe { CStr::from_ptr(hex_ptr).to_str().unwrap().to_string() };
        unsafe { seal_free_string(hex_ptr) };

        assert_eq!(hex_str.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_bip39_mnemonic() {

        seal_create_wallet(1);

        let words_ptr = seal_export_mnemonic_bip39();
        let words = unsafe { CStr::from_ptr(words_ptr).to_str().unwrap().to_string() };
        unsafe { seal_free_string(words_ptr) };

        let count = words.split_whitespace().count();
        assert_eq!(count, 24);
    }

    #[test]
    fn test_import_roundtrip() {

        seal_create_wallet(1);

        let addr_ptr = seal_get_address();
        let addr1 = unsafe { CStr::from_ptr(addr_ptr).to_str().unwrap().to_string() };
        unsafe { seal_free_string(addr_ptr) };

        let hex_ptr = seal_export_mnemonic();
        let mnemonic = unsafe { CStr::from_ptr(hex_ptr).to_str().unwrap().to_string() };
        unsafe { seal_free_string(hex_ptr) };

        // Import same mnemonic
        let mnemonic_cstr = CString::new(mnemonic).unwrap();
        let json_ptr = unsafe { seal_import_wallet(mnemonic_cstr.as_ptr(), 1) };
        unsafe { seal_free_string(json_ptr) };

        let addr_ptr = seal_get_address();
        let addr2 = unsafe { CStr::from_ptr(addr_ptr).to_str().unwrap().to_string() };
        unsafe { seal_free_string(addr_ptr) };

        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_has_wallet_and_lock() {
        // Lock any existing wallet first
        seal_lock_wallet();
        assert_eq!(seal_has_wallet(), 0, "should be empty after lock");

        seal_create_wallet(1);
        assert_eq!(seal_has_wallet(), 1, "should have wallet after create");

        seal_lock_wallet();
        assert_eq!(seal_has_wallet(), 0, "should be empty after second lock");
    }
}
