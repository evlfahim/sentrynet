//! SentryNet REST API layer.
//!
//! Provides Tauri commands that act as REST-like endpoints for the web dashboard
//! and desktop app. All endpoints operate on a single SQLite database file.
//!
//! **IMPORTANT:** Commands in this module must be re-exported in `lib.rs` so that
//! the `#[tauri::command]` macro can generate its internal helpers at the crate root.

use crate::database::Database;
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────
// Configuration types
// ──────────────────────────────────────────────

/// Application configuration persisted in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Default CIDR for ARP scans.
    pub default_cidr: Option<String>,
    /// ARP settle time in milliseconds.
    pub arp_settle_ms: u64,
    /// TCP scan timeout per port in milliseconds.
    pub port_scan_timeout_ms: u64,
    /// TCP scan concurrency.
    pub port_scan_concurrency: usize,
    /// Whether to enable service detection.
    pub port_service_detection: bool,
    /// Number of ICMP ping probes.
    pub ping_count: u32,
    /// ICMP ping timeout in milliseconds.
    pub ping_timeout_ms: u64,
    /// HTTP HEAD port.
    pub http_port: u16,
    /// HTTP HEAD path.
    pub http_path: String,
    /// HTTP HEAD timeout in milliseconds.
    pub http_timeout_ms: u64,
    /// Whether to check latency by default.
    pub check_latency: bool,
    /// History retention period in days (0 = unlimited).
    pub history_retention_days: u64,
    /// Whether to enable desktop notifications.
    pub enable_notifications: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            default_cidr: None,
            arp_settle_ms: 1500,
            port_scan_timeout_ms: crate::port_scan::DEFAULT_SCAN_TIMEOUT_MS,
            port_scan_concurrency: crate::port_scan::DEFAULT_CONCURRENCY,
            port_service_detection: true,
            ping_count: crate::latency::DEFAULT_PING_COUNT,
            ping_timeout_ms: crate::latency::DEFAULT_PING_TIMEOUT_MS,
            http_port: 80,
            http_path: crate::latency::DEFAULT_HTTP_PATH.to_string(),
            http_timeout_ms: crate::latency::DEFAULT_HTTP_TIMEOUT_MS,
            check_latency: true,
            history_retention_days: 90,
            enable_notifications: true,
        }
    }
}

/// Response wrapper for API endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(msg: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg),
        }
    }
}

/// Scan statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub device_count: i64,
    pub port_count: i64,
    pub alert_count: i64,
    pub history_count: i64,
    pub unacknowledged_alerts: i64,
}

/// Cleanup result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupResult {
    pub history_deleted: usize,
    pub alerts_deleted: usize,
}

// ──────────────────────────────────────────────
// Helper: read config from DB as AppConfig
// ──────────────────────────────────────────────

pub fn read_config_from_db(db: &Database) -> AppConfig {
    if let Ok(value) = db.get_config_all() {
        serde_json::from_value(value).unwrap_or_default()
    } else {
        AppConfig::default()
    }
}

pub fn write_config_to_db(db: &Database, config: &AppConfig) -> Result<(), String> {
    let json_str = serde_json::to_string(config).map_err(|e| e.to_string())?;
    db.update_config_json(&json_str).map_err(|e| e.to_string())?;
    Ok(())
}
