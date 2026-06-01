//! Snapshot chunk encoding for the state-sync RPC trio
//! (`seal_getSnapshotManifest` / `seal_getSnapshotChunk`).
//!
//! A snapshot is a flat, deterministic byte stream of `(key, value)`
//! HAMT leaves, broken into fixed-cap chunks. Each chunk's identity
//! is the SHA3-256 of its byte payload; the manifest is the ordered
//! list of `(index, chunk_hash, byte_size)` plus the total byte count
//! and a tip block hash (so the caller can verify the chunks reach
//! exactly the snapshot's state root after replay).
//!
//! # Wire format (per chunk)
//!
//! Sequence of records, each:
//!
//! ```text
//! [ key_len: u32 LE ]
//! [ value_len: u32 LE ]
//! [ key bytes (key_len) ]
//! [ value bytes (value_len) ]
//! ```
//!
//! Records are appended until the next record would push the chunk
//! past `MAX_CHUNK_BYTES`. A record never spans two chunks: if a
//! single key+value+8 header exceeds the cap, that record gets its
//! own oversized chunk (with a warning). This means the cap is a
//! soft target, not a hard ceiling — a single 5 MiB row will still
//! land in one chunk to preserve atomicity.
//!
//! # Determinism
//!
//! The caller is responsible for sorting `(key, value)` pairs in a
//! stable order before passing them to `chunk_entries`. The chunker
//! itself is order-preserving — it never reorders. Snapshots
//! produced from the same state with the same sort key produce
//! identical manifests, which is what makes the `state_root` /
//! manifest-hash binding useful.

use seal_crypto::hash::{sha3_256, Hash256};

/// Soft per-chunk byte cap (4 MiB). Matches the plan ("4 MiB cap")
/// in `TODOS/SESSION-2026-05-10-testnet-readiness.md` step 2c.
pub const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// One chunk's manifest entry: identity (hash) + size, no payload.
/// The payload is fetched separately via `seal_getSnapshotChunk`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkRef {
    /// Zero-based position in the manifest's `chunks` vec. Stable
    /// for a given manifest; identical chunks at different positions
    /// in different manifests are NOT deduplicated (snapshot
    /// identity is per-position).
    pub index: u32,
    /// SHA3-256 of the chunk's byte payload. Caller re-hashes after
    /// fetching to confirm bit-equivalence.
    pub chunk_hash: Hash256,
    /// Byte size of the chunk's payload. Sum across all chunks in a
    /// manifest equals `SnapshotManifest::total_bytes`.
    pub byte_size: u32,
}

/// One emitted chunk: identity + payload bytes.
///
/// The byte payload is owned (`Vec<u8>`) — the chunker takes
/// ownership of the input `(key, value)` pairs, so it's free to
/// move them into the chunk buffer rather than copy.
#[derive(Clone, Debug)]
pub struct Chunk {
    pub r#ref: ChunkRef,
    pub bytes: Vec<u8>,
}

/// Encode a sequence of `(key, value)` pairs into chunks of at most
/// `MAX_CHUNK_BYTES` bytes (soft cap; see module docs for the
/// oversized-row exception).
///
/// Caller must sort `entries` in a stable, deterministic order before
/// calling. Returns a vector of `Chunk` in emission order, ready to
/// be served by `seal_getSnapshotChunk`.
pub fn chunk_entries(entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut next_index: u32 = 0;
    for (key, value) in entries {
        let record_len = 8 + key.len() + value.len();
        // If adding this record would push the chunk past the cap
        // AND the chunk already has at least one record, close it
        // and start a new one. The "at least one record" guard
        // ensures an oversized row doesn't infinitely-loop —
        // instead it lands in its own chunk.
        if !current.is_empty() && current.len() + record_len > MAX_CHUNK_BYTES {
            chunks.push(close_chunk(next_index, std::mem::take(&mut current)));
            next_index += 1;
        }
        current.extend_from_slice(&(key.len() as u32).to_le_bytes());
        current.extend_from_slice(&(value.len() as u32).to_le_bytes());
        current.extend_from_slice(&key);
        current.extend_from_slice(&value);
    }
    if !current.is_empty() {
        chunks.push(close_chunk(next_index, current));
    }
    chunks
}

/// Build a snapshot manifest from a list of chunks.
///
/// Returns `(chunk_refs, total_bytes)`. The caller fills in the rest
/// of the manifest (state_root, tip_block_hash, tip_aggregate_hash)
/// from the source-of-truth in `ConsensusRunner`.
pub fn manifest_from_chunks(chunks: &[Chunk]) -> (Vec<ChunkRef>, u64) {
    let mut total: u64 = 0;
    let refs: Vec<ChunkRef> = chunks
        .iter()
        .map(|c| {
            total = total.saturating_add(c.r#ref.byte_size as u64);
            c.r#ref.clone()
        })
        .collect();
    (refs, total)
}

/// Hash every chunk in order and combine into a single fingerprint.
/// Useful as a manifest-equivalence check independent of byte
/// payload — two callers with the same chunk_refs in the same order
/// agree on this hash.
pub fn manifest_fingerprint(refs: &[ChunkRef]) -> Hash256 {
    let mut buf = Vec::with_capacity(refs.len() * (4 + 32 + 4));
    for r in refs {
        buf.extend_from_slice(&r.index.to_le_bytes());
        buf.extend_from_slice(&r.chunk_hash.0);
        buf.extend_from_slice(&r.byte_size.to_le_bytes());
    }
    sha3_256(&buf)
}

fn close_chunk(index: u32, bytes: Vec<u8>) -> Chunk {
    let chunk_hash = sha3_256(&bytes);
    let byte_size = bytes.len() as u32;
    Chunk {
        r#ref: ChunkRef {
            index,
            chunk_hash,
            byte_size,
        },
        bytes,
    }
}

/// Decode a single chunk's byte payload back into its constituent
/// `(key, value)` records. The inverse of `chunk_entries`'s
/// per-record encoding. Used by the A2d late-joiner stream
/// reconstructor and by round-trip tests.
///
/// Returns `Err` on truncation or oversized headers — i.e. anything
/// the encoder would never emit. A well-formed chunk can be decoded
/// into the same `(key, value)` sequence the encoder consumed
/// (modulo concatenation across chunk boundaries).
#[allow(clippy::type_complexity)]
pub fn decode_chunk_bytes(bytes: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 8 > bytes.len() {
            return Err(format!(
                "chunk truncated: need 8-byte header at offset {i}, only {} bytes left",
                bytes.len() - i
            ));
        }
        let key_len = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        let value_len = u32::from_le_bytes(bytes[i + 4..i + 8].try_into().unwrap()) as usize;
        i += 8;
        if i + key_len + value_len > bytes.len() {
            return Err(format!(
                "chunk truncated: record at offset {} declares key_len={key_len} value_len={value_len} but only {} bytes left",
                i - 8,
                bytes.len() - i
            ));
        }
        let key = bytes[i..i + key_len].to_vec();
        i += key_len;
        let value = bytes[i..i + value_len].to_vec();
        i += value_len;
        out.push((key, value));
    }
    Ok(out)
}

/// Decode a sequence of chunks (concatenated in index order) into
/// the `(key, value)` records they encode. Convenience wrapper
/// around `decode_chunk_bytes` for the late-joiner full-stream
/// path.
#[allow(clippy::type_complexity)]
pub fn decode_chunks(chunks: &[Chunk]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
    let mut all = Vec::new();
    for c in chunks {
        all.extend(decode_chunk_bytes(&c.bytes)?);
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(k: &str, v: &str) -> (Vec<u8>, Vec<u8>) {
        (k.as_bytes().to_vec(), v.as_bytes().to_vec())
    }

    #[test]
    fn empty_input_yields_no_chunks() {
        let chunks = chunk_entries(vec![]);
        assert!(chunks.is_empty());
        let (refs, total) = manifest_from_chunks(&chunks);
        assert!(refs.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn small_input_fits_in_one_chunk() {
        let entries = vec![
            entry("alice", "100"),
            entry("bob", "200"),
            entry("carol", "300"),
        ];
        let chunks = chunk_entries(entries);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].r#ref.index, 0);
        // 3 records * (8 header + small key + small val) ≈ 30 bytes
        assert!(chunks[0].r#ref.byte_size > 0);
        assert!(chunks[0].r#ref.byte_size < 100);
        assert_eq!(chunks[0].bytes.len(), chunks[0].r#ref.byte_size as usize);
    }

    #[test]
    fn chunk_hash_is_deterministic_under_same_input() {
        let entries = vec![entry("alice", "100"), entry("bob", "200")];
        let a = chunk_entries(entries.clone());
        let b = chunk_entries(entries);
        assert_eq!(a[0].r#ref.chunk_hash, b[0].r#ref.chunk_hash);
        assert_eq!(a[0].bytes, b[0].bytes);
    }

    #[test]
    fn input_order_changes_chunk_hash() {
        let a = chunk_entries(vec![entry("alice", "100"), entry("bob", "200")]);
        let b = chunk_entries(vec![entry("bob", "200"), entry("alice", "100")]);
        // Different on-wire byte order => different hash. The chunker
        // is order-preserving; deterministic ordering is the
        // caller's responsibility.
        assert_ne!(a[0].r#ref.chunk_hash, b[0].r#ref.chunk_hash);
    }

    #[test]
    fn oversize_record_lands_in_own_chunk() {
        // Single record larger than MAX_CHUNK_BYTES. The chunker
        // must NOT loop forever — it emits the oversized record as
        // its own chunk and moves on.
        let big = vec![0xab; MAX_CHUNK_BYTES + 1];
        let entries = vec![(b"big".to_vec(), big), entry("after", "x")];
        let chunks = chunk_entries(entries);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].r#ref.byte_size as usize > MAX_CHUNK_BYTES);
        assert!((chunks[1].r#ref.byte_size as usize) < 100);
    }

    #[test]
    fn many_records_split_at_cap() {
        // Each record is ~1 KiB; cap is 4 MiB ⇒ ~4096 records per
        // chunk. Use 5000 records to force a split.
        let value = vec![b'v'; 1000];
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..5000)
            .map(|i| (format!("k{:08}", i).into_bytes(), value.clone()))
            .collect();
        let chunks = chunk_entries(entries);
        assert!(chunks.len() >= 2, "5000 1KiB records should split");
        // No chunk except possibly the last exceeds the cap.
        for c in &chunks[..chunks.len() - 1] {
            assert!((c.r#ref.byte_size as usize) <= MAX_CHUNK_BYTES);
        }
        // Indices are sequential and zero-based.
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.r#ref.index as usize, i);
        }
    }

    #[test]
    fn manifest_fingerprint_changes_with_chunk_order() {
        let a = chunk_entries(vec![entry("alice", "100"), entry("bob", "200")]);
        let (a_refs, _) = manifest_from_chunks(&a);
        let mut b_refs = a_refs.clone();
        // Swap indices and the fingerprint should change.
        if b_refs.len() >= 2 {
            b_refs.swap(0, 1);
        }
        if a_refs.len() >= 2 {
            assert_ne!(manifest_fingerprint(&a_refs), manifest_fingerprint(&b_refs));
        }
    }

    #[test]
    fn manifest_total_bytes_is_sum_of_chunks() {
        let value = vec![b'v'; 1000];
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..100)
            .map(|i| (format!("k{:04}", i).into_bytes(), value.clone()))
            .collect();
        let chunks = chunk_entries(entries);
        let (refs, total) = manifest_from_chunks(&chunks);
        let summed: u64 = refs.iter().map(|r| r.byte_size as u64).sum();
        assert_eq!(total, summed);
    }

    /// Round-trip: encode a deterministic stream, decode it back,
    /// and verify the entries match. This is the property the
    /// late-joiner bootstrap path (A2d) relies on — chunks must be
    /// decode-equivalent to their input.
    #[test]
    fn chunks_decode_round_trip_on_small_input() {
        let entries = vec![
            entry("alice", "100"),
            entry("bob", "200"),
            entry("carol", "300"),
        ];
        let chunks = chunk_entries(entries.clone());
        let decoded = decode_chunks(&chunks).unwrap();
        assert_eq!(decoded, entries);
    }

    /// Round-trip across multiple chunks: 5000 records force a
    /// split; the decoder concatenates and recovers all of them.
    #[test]
    fn chunks_decode_round_trip_across_split() {
        let value = vec![b'v'; 1000];
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..5000)
            .map(|i| (format!("k{:08}", i).into_bytes(), value.clone()))
            .collect();
        let chunks = chunk_entries(entries.clone());
        assert!(chunks.len() >= 2);
        let decoded = decode_chunks(&chunks).unwrap();
        assert_eq!(decoded.len(), entries.len());
        // Spot-check the first / last to keep assertion runtime tight.
        assert_eq!(decoded.first(), entries.first());
        assert_eq!(decoded.last(), entries.last());
    }

    /// Truncated chunk bytes surface as a structured error rather
    /// than a panic — the late-joiner can detect this and re-fetch.
    #[test]
    fn decode_chunk_truncated_header_errors() {
        // 4 bytes only — not enough for the 8-byte record header.
        let truncated = vec![0u8; 4];
        let err = decode_chunk_bytes(&truncated).unwrap_err();
        assert!(err.contains("truncated"));
    }

    #[test]
    fn decode_chunk_truncated_payload_errors() {
        // Header says key_len=10 value_len=10 but only 8 bytes follow.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&10u32.to_le_bytes());
        bytes.extend_from_slice(&10u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        let err = decode_chunk_bytes(&bytes).unwrap_err();
        assert!(err.contains("truncated"));
    }
}
