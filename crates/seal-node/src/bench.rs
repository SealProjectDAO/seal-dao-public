//! Simple benchmarks for critical path operations.
//!
//! Not using criterion (to avoid the dependency). Just measures wall time.
//! Run: cargo test -p seal-node --lib -- bench --nocapture

#[cfg(test)]
mod tests {
    use crate::consensus_runner::ConsensusRunner;
    use seal_consensus::config::ConsensusConfig;
    use seal_crypto::hash::sha3_256;
    use seal_crypto::signature::SigningKey;
    use seal_threshold::ntt::HandRolledOps;
    use seal_threshold::ringtail::RingOps;
    use seal_threshold::traits::ThresholdScheme;
    use seal_threshold::RingtailThreshold;
    use seal_vrf::pq_vrf::PqVrf;
    use seal_vrf::traits::Vrf;
    use std::time::Instant;

    #[test]
    fn bench_ml_dsa_keygen() {
        let start = Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let _ = SigningKey::generate();
        }
        let elapsed = start.elapsed();
        println!(
            "ML-DSA-65 keygen: {:.2} ms/op ({} ops in {:.1}s)",
            elapsed.as_millis() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn bench_ml_dsa_sign() {
        let (sk, _vk) = SigningKey::generate();
        let message = vec![0u8; 256]; // 256-byte message
        let start = Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let _ = sk.sign(&message).unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "ML-DSA-65 sign (256B msg): {:.2} ms/op ({} ops in {:.1}s)",
            elapsed.as_millis() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn bench_ml_dsa_verify() {
        let (sk, vk) = SigningKey::generate();
        let message = vec![0u8; 256];
        let sig = sk.sign(&message).unwrap();
        let start = Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            vk.verify(&message, &sig).unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "ML-DSA-65 verify (256B msg): {:.2} ms/op ({} ops in {:.1}s)",
            elapsed.as_millis() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn bench_sha3_256() {
        let data = vec![0u8; 1024]; // 1KB
        let start = Instant::now();
        let iterations = 10000;
        for _ in 0..iterations {
            let _ = sha3_256(&data);
        }
        let elapsed = start.elapsed();
        println!(
            "SHA3-256 (1KB): {:.3} us/op ({} ops in {:.1}s)",
            elapsed.as_micros() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn bench_block_production() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        runner
            .submit_sql("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();
        for i in 0..10 {
            runner
                .submit_sql(&format!("INSERT INTO t (id, val) VALUES ({}, 'v{}')", i, i))
                .unwrap();
        }

        let start = Instant::now();
        let mut produced = 0;
        for _ in 0..100 {
            if runner.advance_slot().is_some() {
                produced += 1;
                if produced >= 10 {
                    break;
                }
            }
            // Re-add transactions for next block
            runner
                .submit_sql(&format!(
                    "INSERT INTO t (id, val) VALUES ({}, 'x')",
                    100 + produced
                ))
                .unwrap();
        }
        let elapsed = start.elapsed();
        if produced > 0 {
            println!(
                "Block production: {:.2} ms/block ({} blocks in {:.1}s)",
                elapsed.as_millis() as f64 / produced as f64,
                produced,
                elapsed.as_secs_f64()
            );
        }
    }

    #[test]
    fn bench_sql_insert_query() {
        let mut runner = ConsensusRunner::new(ConsensusConfig::default());
        runner
            .submit_sql("CREATE TABLE bench (id BIGINT PRIMARY KEY, data TEXT)")
            .unwrap();

        // Insert benchmark
        let start = Instant::now();
        let inserts = 1000;
        for i in 0..inserts {
            runner
                .submit_sql(&format!(
                    "INSERT INTO bench (id, data) VALUES ({}, 'row_{}')",
                    i, i
                ))
                .unwrap();
        }
        let insert_elapsed = start.elapsed();

        // Query benchmark
        let start = Instant::now();
        let queries = 100;
        for _ in 0..queries {
            let _ = runner.query_sql("SELECT * FROM bench").unwrap();
        }
        let query_elapsed = start.elapsed();

        println!(
            "SQL INSERT: {:.3} us/op ({} ops in {:.1}s)",
            insert_elapsed.as_micros() as f64 / inserts as f64,
            inserts,
            insert_elapsed.as_secs_f64()
        );
        println!(
            "SQL SELECT * (1000 rows): {:.2} ms/op ({} ops in {:.1}s)",
            query_elapsed.as_millis() as f64 / queries as f64,
            queries,
            query_elapsed.as_secs_f64()
        );
    }

    // ========================================================================
    // PqVrf benchmarks
    // ========================================================================

    #[test]
    fn bench_pqvrf_keygen() {
        let start = Instant::now();
        let iterations = 10;
        for _ in 0..iterations {
            let _ = PqVrf::keygen();
        }
        let elapsed = start.elapsed();
        println!(
            "PqVrf keygen (ML-DSA): {:.2} ms/op ({} ops in {:.1}s)",
            elapsed.as_millis() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn bench_pqvrf_eval() {
        let kp = PqVrf::keygen();
        let input = sha3_256(b"slot_42_epoch_seed").0.to_vec();
        let start = Instant::now();
        let iterations = 50;
        for _ in 0..iterations {
            let _ = PqVrf::eval(&kp.secret_key, &input).unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "PqVrf eval: {:.2} ms/op ({} ops in {:.1}s)",
            elapsed.as_millis() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn bench_pqvrf_verify() {
        let kp = PqVrf::keygen();
        let input = sha3_256(b"slot_42_epoch_seed").0.to_vec();
        let (output, proof) = PqVrf::eval(&kp.secret_key, &input).unwrap();
        let start = Instant::now();
        let iterations = 50;
        for _ in 0..iterations {
            PqVrf::verify(&kp.public_key, &input, &output, &proof).unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "PqVrf verify: {:.2} ms/op ({} ops in {:.1}s)",
            elapsed.as_millis() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    // ========================================================================
    // Ringtail threshold signature benchmarks
    // ========================================================================

    #[test]
    fn bench_ringtail_partial_sign() {
        let ring = HandRolledOps::new();
        let sk = ring.sample_gaussian(6.108);
        let sk_bytes = ring.to_bytes(&sk);
        let message = sha3_256(b"block_hash").0;

        let start = Instant::now();
        let iterations = 20;
        for i in 0..iterations {
            let _ = RingtailThreshold::partial_sign(i % 100, &sk_bytes, &message).unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "Ringtail partial_sign: {:.2} ms/op ({} ops in {:.1}s)",
            elapsed.as_millis() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn bench_ringtail_3_of_5() {
        let ring = HandRolledOps::new();
        let message = sha3_256(b"bench_block").0;

        // Generate 5 key shares
        let keys: Vec<Vec<u8>> = (0..5)
            .map(|_| {
                let sk = ring.sample_gaussian(6.108);
                ring.to_bytes(&sk)
            })
            .collect();

        let start = Instant::now();
        let iterations = 5;
        for _ in 0..iterations {
            // 3 partial signatures
            let partials: Vec<_> = (0..3)
                .map(|i| RingtailThreshold::partial_sign(i, &keys[i], &message).unwrap())
                .collect();

            // Aggregate
            let _sig = RingtailThreshold::aggregate(&partials, &keys, &message, 3, 5).unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "Ringtail 3-of-5 (sign+aggregate): {:.2} ms/op ({} ops in {:.1}s)",
            elapsed.as_millis() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn bench_ringtail_67_of_100() {
        let ring = HandRolledOps::new();
        let message = sha3_256(b"bench_100_party_block").0;

        // Generate 100 key shares
        let keys: Vec<Vec<u8>> = (0..100)
            .map(|_| {
                let sk = ring.sample_gaussian(6.108);
                ring.to_bytes(&sk)
            })
            .collect();

        let start = Instant::now();
        let iterations = 2;
        for _ in 0..iterations {
            // 67 partial signatures (>2/3 threshold)
            let partials: Vec<_> = (0..67)
                .map(|i| RingtailThreshold::partial_sign(i, &keys[i], &message).unwrap())
                .collect();

            // Aggregate
            let sig = RingtailThreshold::aggregate(&partials, &keys, &message, 67, 100).unwrap();

            // Verify
            RingtailThreshold::verify(&sig, &keys, &message, 67).unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "Ringtail 67-of-100 (sign+aggregate+verify): {:.0} ms/op ({} ops in {:.1}s)",
            elapsed.as_millis() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
        let ms_per_op = elapsed.as_millis() as f64 / iterations as f64;
        let status = if ms_per_op < 2000.0 {
            "PASS"
        } else {
            "NEEDS OPTIMIZATION"
        };
        println!(
            "  → Target: <2000ms WAN. Result: {:.0}ms ({})",
            ms_per_op, status
        );
    }

    // ========================================================================
    // NTT benchmarks
    // ========================================================================

    #[test]
    fn bench_ntt_polynomial_mul() {
        let ring = HandRolledOps::new();
        let a = ring.sample_uniform();
        let b = ring.sample_uniform();

        let start = Instant::now();
        let iterations = 1000;
        for _ in 0..iterations {
            let _ = ring.mul(&a, &b);
        }
        let elapsed = start.elapsed();
        println!(
            "NTT poly mul (N=256): {:.3} us/op ({} ops in {:.1}s)",
            elapsed.as_micros() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn bench_discrete_gaussian_sampling() {
        let ring = HandRolledOps::new();

        let start = Instant::now();
        let iterations = 1000;
        for _ in 0..iterations {
            let _ = ring.sample_gaussian(6.108);
        }
        let elapsed = start.elapsed();
        println!(
            "Discrete Gaussian sample (N=256, sigma=6.1): {:.3} us/op ({} ops in {:.1}s)",
            elapsed.as_micros() as f64 / iterations as f64,
            iterations,
            elapsed.as_secs_f64()
        );
    }
}
