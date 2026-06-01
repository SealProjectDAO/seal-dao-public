//! Process-lifetime metrics for seal-relayer.
//!
//! Exposes a Prometheus-format `/metrics` endpoint on the configured
//! port. Hand-rolled tokio TcpListener (mirrors `apps/seal-faucet`'s
//! pattern) so the relayer doesn't drag axum + tower into its dep
//! graph just for one read endpoint.
//!
//! All counters are `AtomicU64` — increments under the polling loop's
//! single task, never need consistent multi-counter reads.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub struct Metrics {
    /// Total polling passes (whether they did work or not).
    pub passes_total: AtomicU64,
    /// Withdrawals seen with `committee_signature_hex` set + `executed=false`.
    pub withdrawals_seen: AtomicU64,
    /// Successful destination-chain submissions (CLI exit 0).
    pub submissions_total: AtomicU64,
    /// Failed destination-chain submissions (CLI non-zero exit).
    pub submission_failures: AtomicU64,
    /// Withdrawals skipped because chain wasn't configured on this
    /// relayer instance (Solana-only or Stellar-only operator
    /// deployment).
    pub skipped_not_configured: AtomicU64,
    /// `seal_bridgeMarkExecuted` calls that succeeded (first writer).
    pub mark_executed_total: AtomicU64,
    /// `seal_bridgeMarkExecuted` calls that landed after another
    /// relayer already executed (race no-op).
    pub mark_executed_already: AtomicU64,
    /// Mark-executed RPC failures (claim landed on-chain but Seal
    /// state wasn't updated; relayer retries on next pass).
    pub mark_executed_failures: AtomicU64,
    /// Dry-run-mode logged-but-not-submitted entries.
    pub dry_run_skipped: AtomicU64,
    /// Process start time for the uptime gauge.
    pub start_time: Instant,
    /// `--dry-run` flag captured at launch (0/1 gauge).
    pub dry_run_mode: bool,
}

impl Metrics {
    pub fn new(dry_run_mode: bool) -> Self {
        Metrics {
            passes_total: AtomicU64::new(0),
            withdrawals_seen: AtomicU64::new(0),
            submissions_total: AtomicU64::new(0),
            submission_failures: AtomicU64::new(0),
            skipped_not_configured: AtomicU64::new(0),
            mark_executed_total: AtomicU64::new(0),
            mark_executed_already: AtomicU64::new(0),
            mark_executed_failures: AtomicU64::new(0),
            dry_run_skipped: AtomicU64::new(0),
            start_time: Instant::now(),
            dry_run_mode,
        }
    }

    pub fn render_prometheus(&self) -> String {
        let uptime = self.start_time.elapsed().as_secs();
        let dry_run = if self.dry_run_mode { 1 } else { 0 };
        format!(
            "# HELP seal_relayer_passes_total Total polling passes\n\
             # TYPE seal_relayer_passes_total counter\n\
             seal_relayer_passes_total {passes}\n\
             # HELP seal_relayer_withdrawals_seen Withdrawals seen with committee_signature set and executed=false\n\
             # TYPE seal_relayer_withdrawals_seen counter\n\
             seal_relayer_withdrawals_seen {seen}\n\
             # HELP seal_relayer_submissions_total Successful destination-chain unlock submissions\n\
             # TYPE seal_relayer_submissions_total counter\n\
             seal_relayer_submissions_total {subs}\n\
             # HELP seal_relayer_submission_failures Failed destination-chain submissions (CLI non-zero exit)\n\
             # TYPE seal_relayer_submission_failures counter\n\
             seal_relayer_submission_failures {sub_fails}\n\
             # HELP seal_relayer_skipped_not_configured Withdrawals skipped because chain isn't configured on this relayer\n\
             # TYPE seal_relayer_skipped_not_configured counter\n\
             seal_relayer_skipped_not_configured {skip_nc}\n\
             # HELP seal_relayer_mark_executed_total Successful seal_bridgeMarkExecuted calls (first writer)\n\
             # TYPE seal_relayer_mark_executed_total counter\n\
             seal_relayer_mark_executed_total {mark}\n\
             # HELP seal_relayer_mark_executed_already Mark-executed calls where another relayer raced first\n\
             # TYPE seal_relayer_mark_executed_already counter\n\
             seal_relayer_mark_executed_already {mark_race}\n\
             # HELP seal_relayer_mark_executed_failures Mark-executed RPC failures (claim landed on-chain, Seal state not updated)\n\
             # TYPE seal_relayer_mark_executed_failures counter\n\
             seal_relayer_mark_executed_failures {mark_fails}\n\
             # HELP seal_relayer_dry_run_skipped Withdrawals logged-but-not-submitted under --dry-run\n\
             # TYPE seal_relayer_dry_run_skipped counter\n\
             seal_relayer_dry_run_skipped {dryrun_count}\n\
             # HELP seal_relayer_uptime_secs Seconds since the relayer process started\n\
             # TYPE seal_relayer_uptime_secs gauge\n\
             seal_relayer_uptime_secs {uptime}\n\
             # HELP seal_relayer_dry_run 1 when started with --dry-run, else 0\n\
             # TYPE seal_relayer_dry_run gauge\n\
             seal_relayer_dry_run {dry_run}\n",
            passes = self.passes_total.load(Ordering::Relaxed),
            seen = self.withdrawals_seen.load(Ordering::Relaxed),
            subs = self.submissions_total.load(Ordering::Relaxed),
            sub_fails = self.submission_failures.load(Ordering::Relaxed),
            skip_nc = self.skipped_not_configured.load(Ordering::Relaxed),
            mark = self.mark_executed_total.load(Ordering::Relaxed),
            mark_race = self.mark_executed_already.load(Ordering::Relaxed),
            mark_fails = self.mark_executed_failures.load(Ordering::Relaxed),
            dryrun_count = self.dry_run_skipped.load(Ordering::Relaxed),
            uptime = uptime,
            dry_run = dry_run,
        )
    }
}

/// Spawn the metrics HTTP server. Returns immediately; the server
/// runs in a tokio task until process exit.
///
/// Bind failures are logged but not fatal — the relayer's main job is
/// the polling loop, and metrics are best-effort. Operators see the
/// startup error and either fix the port conflict or accept the loss.
pub fn spawn(metrics: Arc<Metrics>, bind: std::net::SocketAddr) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => {
                tracing::info!(bind = %bind, "metrics endpoint listening");
                l
            }
            Err(e) => {
                tracing::warn!(error = %e, bind = %bind, "metrics endpoint bind failed — continuing without /metrics");
                return;
            }
        };
        loop {
            let (mut stream, _addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "metrics accept failed");
                    continue;
                }
            };
            let m = metrics.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_one(&mut stream, &m).await {
                    tracing::debug!(error = %e, "metrics request handling failed");
                }
            });
        }
    });
}

/// Serve a single HTTP/1.1 request. Recognizes GET /metrics; everything
/// else is 404. No keep-alive (Connection: close) so the request loop
/// stays trivial.
async fn serve_one(stream: &mut tokio::net::TcpStream, metrics: &Metrics) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or("");
    let response = if first_line.starts_with("GET /metrics") {
        let body = metrics.render_prometheus();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    } else if first_line.starts_with("GET /health") {
        let body = "ok\n";
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    } else {
        let body = "not found\n";
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_all_counters() {
        let m = Metrics::new(true);
        m.passes_total.store(7, Ordering::Relaxed);
        m.withdrawals_seen.store(3, Ordering::Relaxed);
        m.submissions_total.store(2, Ordering::Relaxed);
        m.dry_run_skipped.store(1, Ordering::Relaxed);
        let rendered = m.render_prometheus();

        for needle in [
            "seal_relayer_passes_total 7",
            "seal_relayer_withdrawals_seen 3",
            "seal_relayer_submissions_total 2",
            "seal_relayer_dry_run_skipped 1",
            "seal_relayer_dry_run 1",
            "seal_relayer_uptime_secs",
        ] {
            assert!(
                rendered.contains(needle),
                "missing `{}` in metrics output:\n{}",
                needle,
                rendered
            );
        }
    }

    #[test]
    fn dry_run_gauge_reflects_flag() {
        let m_on = Metrics::new(true);
        assert!(m_on.render_prometheus().contains("seal_relayer_dry_run 1"));
        let m_off = Metrics::new(false);
        assert!(m_off.render_prometheus().contains("seal_relayer_dry_run 0"));
    }
}
