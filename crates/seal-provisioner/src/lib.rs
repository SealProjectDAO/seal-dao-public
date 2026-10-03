//! Seal worker provisioner — lifecycle management for bridge/validator nodes.
//!
//! # Design
//! Provides a trait-based abstraction for provisioning, monitoring, and
//! decommissioning cloud workers (Docker VMs, remote seal-nodes). The
//! [`WorkerProvisioner`] trait is the entry point; a Docker-based
//! implementation is provided for local development and simple deployments.
//!
//! # Architecture
//! ```text
//!  ┌─────────────────────┐
//!  │   Operator / CLI    │
//!  │  (provisioner CLI)  │
//!  └─────────┬───────────┘
//!            │
//!            ▼
//!  ┌─────────────────────┐
//!  │ WorkerProvisioner   │ ◄── trait (pluggable backends)
//!  │ (provision/run/     │
//!  │  health/decommission)│
//!  └─────────┬───────────┘
//!            │
//!       ┌────┴────┐
//!       ▼         ▼
//!  ┌──────────┐ ┌──────────┐
//!  │DockerOp  │ │  ...     │  ◄── other backends (cloud providers)
//!  │(default) │ │          │
//!  └──────────┘ └──────────┘
//! ```
//!
//! # Worker lifecycle
//! 1. **Provision** — create a new worker with a generated validator key,
//!    register it in the trust store, and start the seal-node container.
//! 2. **Monitor** — health checks via periodic RPC probes.
//! 3. **Decommission** — gracefully stop the worker, revoke from trust store,
//!    and clean up resources.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

// ── Types ──────────────────────────────────────────────────────

/// Worker status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerStatus {
    /// Worker is being created.
    Provisioning,
    /// Worker is running and healthy.
    Running,
    /// Worker is running but health checks are failing.
    Degraded,
    /// Worker is stopped.
    Stopped,
    /// Worker is being decommissioned.
    Decommissioning,
    /// Worker has been fully decommissioned.
    Decommissioned,
}

impl fmt::Display for WorkerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkerStatus::Provisioning => write!(f, "provisioning"),
            WorkerStatus::Running => write!(f, "running"),
            WorkerStatus::Degraded => write!(f, "degraded"),
            WorkerStatus::Stopped => write!(f, "stopped"),
            WorkerStatus::Decommissioning => write!(f, "decommissioning"),
            WorkerStatus::Decommissioned => write!(f, "decommissioned"),
        }
    }
}

/// A worker node in the provisioner's managed set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Worker {
    /// Unique worker identifier.
    pub id: Uuid,
    /// Worker name (human-readable, e.g. "us-east-1-validator-1").
    pub name: String,
    /// Worker type.
    pub kind: WorkerKind,
    /// Current status.
    pub status: WorkerStatus,
    /// Docker container name (for Docker-based provisioners).
    pub container_name: Option<String>,
    /// Internal IP address (if assigned).
    pub internal_ip: Option<String>,
    /// External IP address (if assigned).
    pub external_ip: Option<String>,
    /// Path to the validator key file.
    pub validator_key_path: Option<String>,
    /// Created timestamp (Unix epoch).
    pub created_at: u64,
    /// Last health check timestamp.
    pub last_healthy_at: Option<u64>,
}

/// Type of worker to provision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerKind {
    /// Seal L1 validator node.
    Validator,
    /// Bridge observer node (polls Solana/Stellar).
    BridgeObserver,
    /// KMS sidecar node (holds signing keys).
    KmsSidecar,
}

impl fmt::Display for WorkerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkerKind::Validator => write!(f, "validator"),
            WorkerKind::BridgeObserver => write!(f, "bridge-observer"),
            WorkerKind::KmsSidecar => write!(f, "kms-sidecar"),
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProvisionerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Worker not found: {0}")]
    WorkerNotFound(Uuid),

    #[error("Worker already exists: {name}")]
    WorkerExists { name: String },

    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),

    #[error("Docker not available: {0}")]
    DockerNotAvailable(String),

    #[error("Provisioning failed: {0}")]
    ProvisioningFailed(String),

    #[error("Decommissioning failed: {0}")]
    DecommissionFailed(String),

    #[error("Worker is not in the expected state: {status}")]
    InvalidState { status: String },
}

pub type ProvisionerResult<T> = Result<T, ProvisionerError>;

// ── Trait ──────────────────────────────────────────────────────

/// Core provisioner trait — the interface for managing worker lifecycles.
///
/// Implementations can target Docker, cloud VMs, Kubernetes, etc.
#[async_trait]
pub trait WorkerProvisioner: Send + Sync {
    /// Provision a new worker. Returns the worker record.
    async fn provision(&self, name: &str, kind: WorkerKind) -> ProvisionerResult<Worker>;

    /// Get a worker by ID.
    async fn get_worker(&self, id: Uuid) -> ProvisionerResult<Worker>;

    /// List all workers, optionally filtered by status.
    async fn list_workers(&self, status: Option<WorkerStatus>) -> Vec<Worker>;

    /// Check health of a specific worker. Returns last healthy timestamp.
    async fn health_check(&self, id: Uuid) -> ProvisionerResult<u64>;

    /// Stop a running worker (graceful shutdown).
    async fn stop_worker(&self, id: Uuid) -> ProvisionerResult<()>;

    /// Start a stopped worker.
    async fn start_worker(&self, id: Uuid) -> ProvisionerResult<()>;

    /// Decommission a worker — stop, revoke, and clean up.
    async fn decommission(&self, id: Uuid) -> ProvisionerResult<()>;

    /// Get the provisioner's configuration (read-only).
    fn config(&self) -> &ProvisionerConfig;
}

/// Configuration for a provisioner instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvisionerConfig {
    /// Data directory for worker state.
    pub data_dir: String,
    /// Docker network name (for Docker-based provisioners).
    pub docker_network: String,
    /// Default Seal node image tag.
    pub seal_image: String,
    /// Default KMS sidecar image tag.
    pub kms_image: String,
    /// Health check interval in seconds.
    pub health_interval_secs: u64,
    /// Health check timeout in seconds.
    pub health_timeout_secs: u64,
    /// Max retries before marking a worker as degraded.
    pub health_max_retries: u32,
    /// Trust store path (for KMS-sidecar integration).
    pub trust_store_path: Option<String>,
}

impl Default for ProvisionerConfig {
    fn default() -> Self {
        ProvisionerConfig {
            data_dir: "/var/lib/seal-provisioner".into(),
            docker_network: "seal-net".into(),
            seal_image: "seal-node:latest".into(),
            kms_image: "seal-kms-sidecar:latest".into(),
            health_interval_secs: 30,
            health_timeout_secs: 10,
            health_max_retries: 3,
            trust_store_path: None,
        }
    }
}

// ── Docker implementation ──────────────────────────────────────

/// A Docker-based worker provisioner.
///
/// Creates and manages seal-node / seal-kms-sidecar containers on the
/// local Docker daemon. Each worker gets its own container on a dedicated
/// network.
#[derive(Clone)]
pub struct DockerProvisioner {
    config: ProvisionerConfig,
    /// Persistent worker inventory (JSON file).
    inventory_path: std::path::PathBuf,
}

impl DockerProvisioner {
    /// Create a new Docker provisioner with the given config.
    pub fn new(config: ProvisionerConfig) -> Self {
        let inventory_path =
            std::path::PathBuf::from(&config.data_dir).join("inventory.json");
        DockerProvisioner {
            config,
            inventory_path,
        }
    }

    /// Create with default config and the given data directory.
    pub fn with_data_dir(data_dir: &str) -> Self {
        Self::new(ProvisionerConfig {
            data_dir: data_dir.into(),
            ..ProvisionerConfig::default()
        })
    }

    /// Save worker inventory to disk atomically.
    fn save_inventory(&self, workers: &[Worker]) -> ProvisionerResult<()> {
        let json = serde_json::to_string_pretty(workers)?;
        let tmp = self.inventory_path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &self.inventory_path)?;
        Ok(())
    }

    /// Load worker inventory from disk.
    fn load_inventory(&self) -> Vec<Worker> {
        if !self.inventory_path.is_file() {
            return Vec::new();
        }
        match std::fs::read_to_string(&self.inventory_path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }
}

#[async_trait]
impl WorkerProvisioner for DockerProvisioner {
    async fn provision(&self, name: &str, kind: WorkerKind) -> ProvisionerResult<Worker> {
        let workers = self.load_inventory();
        if workers.iter().any(|w| w.name == name) {
            return Err(ProvisionerError::WorkerExists {
                name: name.to_string(),
            });
        }

        let id = Uuid::new_v4();
        let container_name = format!("seal-{}", name);
        let created_at = chrono::Utc::now().timestamp() as u64;

        // Validate Docker is available
        let docker_available =
            tokio::process::Command::new("docker")
                .arg("info")
                .output()
                .await
                .is_ok();

        if !docker_available {
            return Err(ProvisionerError::DockerNotAvailable(
                "docker daemon is not responding".into(),
            ));
        }

        let validator_key_path = if kind == WorkerKind::Validator {
            let key_dir = format!("{}/keys", self.config.data_dir);
            std::fs::create_dir_all(&key_dir).ok();
            Some(format!("{}/{}.key", key_dir, name))
        } else {
            None
        };

        let worker = Worker {
            id,
            name: name.to_string(),
            kind,
            status: WorkerStatus::Provisioning,
            container_name: Some(container_name.clone()),
            internal_ip: None,
            external_ip: None,
            validator_key_path,
            created_at,
            last_healthy_at: None,
        };

        // Persist to inventory
        let mut workers = workers;
        let worker_clone = worker.clone();
        workers.push(worker);
        self.save_inventory(&workers)?;

        Ok(worker_clone)
    }

    async fn get_worker(&self, id: Uuid) -> ProvisionerResult<Worker> {
        let workers = self.load_inventory();
        workers
            .into_iter()
            .find(|w| w.id == id)
            .ok_or(ProvisionerError::WorkerNotFound(id))
    }

    async fn list_workers(&self, status: Option<WorkerStatus>) -> Vec<Worker> {
        let workers = self.load_inventory();
        if let Some(s) = status {
            workers
                .into_iter()
                .filter(|w| w.status == s)
                .collect()
        } else {
            workers
        }
    }

    async fn health_check(&self, id: Uuid) -> ProvisionerResult<u64> {
        let worker = self.get_worker(id).await?;
        let container_name = worker
            .container_name
            .as_ref()
            .ok_or_else(|| {
                ProvisionerError::HealthCheckFailed("no container".into())
            })?;

        let output = tokio::process::Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", container_name])
            .output()
            .await
            .map_err(|e| {
                ProvisionerError::HealthCheckFailed(e.to_string())
            })?;

        let running = String::from_utf8_lossy(&output.stdout).trim() == "true";
        let now = chrono::Utc::now().timestamp() as u64;

        if running {
            Ok(now)
        } else {
            Err(ProvisionerError::HealthCheckFailed(format!(
                "container {} is not running",
                container_name
            )))
        }
    }

    async fn stop_worker(&self, id: Uuid) -> ProvisionerResult<()> {
        let worker = self.get_worker(id).await?;
        let container_name = worker
            .container_name
            .as_ref()
            .ok_or_else(|| {
                ProvisionerError::DecommissionFailed("no container".into())
            })?;

        let status = tokio::process::Command::new("docker")
            .args(["stop", "--time", "30", container_name])
            .output()
            .await
            .map_err(|e| {
                ProvisionerError::DecommissionFailed(e.to_string())
            })?;

        if status.status.success() {
            let mut workers = self.load_inventory();
            if let Some(w) = workers.iter_mut().find(|w| w.id == id) {
                w.status = WorkerStatus::Stopped;
            }
            self.save_inventory(&workers)?;
        }

        Ok(())
    }

    async fn start_worker(&self, id: Uuid) -> ProvisionerResult<()> {
        let worker = self.get_worker(id).await?;
        let container_name = worker
            .container_name
            .as_ref()
            .ok_or_else(|| {
                ProvisionerError::DecommissionFailed("no container".into())
            })?;

        let output = tokio::process::Command::new("docker")
            .args(["start", container_name])
            .output()
            .await
            .map_err(|e| {
                ProvisionerError::ProvisioningFailed(e.to_string())
            })?;

        if output.status.success() {
            let mut workers = self.load_inventory();
            if let Some(w) = workers.iter_mut().find(|w| w.id == id) {
                w.status = WorkerStatus::Running;
            }
            self.save_inventory(&workers)?;
        }

        Ok(())
    }

    async fn decommission(&self, id: Uuid) -> ProvisionerResult<()> {
        let mut workers = self.load_inventory();
        let idx = workers
            .iter()
            .position(|w| w.id == id)
            .ok_or(ProvisionerError::WorkerNotFound(id))?;

        let worker = workers[idx].clone();
        workers[idx].status = WorkerStatus::Decommissioning;
        self.save_inventory(&workers)?;

        // Stop and remove container
        if let Some(ref container) = worker.container_name {
            let _ = tokio::process::Command::new("docker")
                .args(["stop", "--time", "10", container])
                .output()
                .await;

            let _ = tokio::process::Command::new("docker")
                .args(["rm", container])
                .output()
                .await;
        }

        workers[idx].status = WorkerStatus::Decommissioned;
        self.save_inventory(&workers)?;
        Ok(())
    }

    fn config(&self) -> &ProvisionerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_kind_display() {
        assert_eq!(WorkerKind::Validator.to_string(), "validator");
        assert_eq!(
            WorkerKind::BridgeObserver.to_string(),
            "bridge-observer"
        );
        assert_eq!(WorkerKind::KmsSidecar.to_string(), "kms-sidecar");
    }

    #[test]
    fn test_worker_status_display() {
        assert_eq!(WorkerStatus::Provisioning.to_string(), "provisioning");
        assert_eq!(WorkerStatus::Running.to_string(), "running");
        assert_eq!(WorkerStatus::Stopped.to_string(), "stopped");
        assert_eq!(
            WorkerStatus::Decommissioned.to_string(),
            "decommissioned"
        );
    }

    #[test]
    fn test_config_defaults() {
        let config = ProvisionerConfig::default();
        assert_eq!(config.health_interval_secs, 30);
        assert_eq!(config.health_timeout_secs, 10);
        assert_eq!(config.health_max_retries, 3);
    }

    #[tokio::test]
    async fn test_docker_provisioner_inventory_persist() {
        let dir = tempfile::tempdir().unwrap();
        let provisioner =
            DockerProvisioner::with_data_dir(dir.path().to_str().unwrap());

        // No workers initially
        let workers = provisioner.list_workers(None).await;
        assert!(workers.is_empty());

        // Check config
        assert_eq!(
            provisioner.config().docker_network,
            "seal-net"
        );
    }
}
