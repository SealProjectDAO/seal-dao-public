//! Generate a Ringtail singleton keypair for the bridge committee path.
//!
//! Operator workflow (ADR-002): create the keypair file before
//! starting `seal-node` with `--bridge-ringtail-keypair-file <path>`.
//!
//! ```
//! cargo run --example bridge-ringtail-keygen --features ringtail-singleton \
//!     -p seal-bridge -- --output /var/lib/seal/keys/bridge-ringtail.json
//! chmod 600 /var/lib/seal/keys/bridge-ringtail.json
//! ```
//!
//! Without the `ringtail-singleton` feature this example refuses to
//! compile — the underlying RingtailKeypair type is feature-gated.

#[cfg(feature = "ringtail-singleton")]
fn main() {
    use seal_bridge::ringtail::RingtailKeypair;
    use std::path::PathBuf;

    let args: Vec<String> = std::env::args().collect();
    let output = match parse_arg(&args, "--output") {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: bridge-ringtail-keygen --output <path>\n\
                 \n\
                 Writes a fresh (PublicParams, sk_collapsed_bytes) JSON\n\
                 keypair file. Mode it 0600 after writing — the file\n\
                 contains the validator's secret share."
            );
            std::process::exit(2);
        }
    };
    if output.exists() {
        eprintln!(
            "refusing to overwrite existing {}: move it aside first",
            output.display()
        );
        std::process::exit(2);
    }
    let kp = RingtailKeypair::generate();
    if let Err(e) = kp.save_to_file(&output) {
        eprintln!("save failed: {e}");
        std::process::exit(2);
    }
    println!("wrote keypair to {}", output.display());
    println!(
        "REMINDER: chmod 600 {} (file holds the validator secret share)",
        output.display()
    );
}

#[cfg(not(feature = "ringtail-singleton"))]
fn main() {
    eprintln!(
        "this example requires --features ringtail-singleton; \n\
         re-run with: cargo run --example bridge-ringtail-keygen \\\n\
                       --features ringtail-singleton -p seal-bridge -- --output <path>"
    );
    std::process::exit(2);
}

#[cfg(feature = "ringtail-singleton")]
fn parse_arg<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).map(|s| s.as_str()))
}
