//! SentryNet REST API layer.
//!
//! Every endpoint is implemented once as a synchronous `handle_*` function that
//! returns `Result<T, ApiError>`. Two transports sit on top of these handlers:
//!
//! * Tauri commands (`api_*`) used by the desktop window via `invoke`, which
//!   wrap results in an [`ApiResponse`] envelope.
//! * The local HTTP server in [`crate::rest_server`], which maps the same
//!   handlers to `/api/...` routes for the web dashboard.

use crate::alerts;
use crate::arp;
use crate::core;
use crate::database::{self, Database};
use crate::latency;
use crate::port_scan;
use crate::rest_server::RestServer;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::{Mutex, MutexGuard, TryLockError};

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────

/// File name of the SQLite database inside the app data directory.
pub const DEFAULT_DB_FILE: &str = "sentrynet.sqlite";

/// Default number of rows returned by list endpoints.
pub const DEFAULT_LIST_LIMIT: usize = 100;

/// Default number of rows returned by per-device history.
pub const DEFAULT_DEVICE_HISTORY_LIMIT: usize = 50;

/// Default number of history rows included in an export.
pub const DEFAULT_EXPORT_HISTORY_LIMIT: usize = 1000;

/// Upper bound for any `limit` parameter.
pub const MAX_LIST_LIMIT: usize = 10_000;

/// Maximum number of hosts accepted by the ad-hoc port scan endpoint.
pub const MAX_PORT_SCAN_HOSTS: usize = 1024;

/// Maximum number of hosts accepted by the ad-hoc latency endpoint.
pub const MAX_LATENCY_HOSTS: usize = 256;

/// Only one database-writing scan may run at a time.
static SCAN_LOCK: Mutex<()> = Mutex::new(());

// ──────────────────────────────────────────────
// Errors and response envelope
// ──────────────────────────────────────────────

/// An API failure with the HTTP status it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl ApiError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, message)
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.status)
    }
}

impl std::error::Error for ApiError {}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::internal(format!("database error: {e}"))
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

    pub fn from_result(result: Result<T, ApiError>) -> Self {
        match result {
            Ok(data) => Self::ok(data),
            Err(e) => Self::err(e.message),
        }
    }
}

// ──────────────────────────────────────────────
// Payload types
// ──────────────────────────────────────────────

/// Application configuration persisted in the database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// Default CIDR for ARP scans (`None` = auto-detect local /24).
    pub default_cidr: Option<String>,
    /// ARP settle time in milliseconds.
    pub arp_settle_ms: u64,
    /// TCP scan timeout per port in milliseconds.
    pub port_scan_timeout_ms: u64,
    /// TCP scan concurrency.
    pub port_scan_concurrency: usize,
    /// Custom ports to scan (comma-separated or empty for defaults).
    pub port_scan_ports: String,
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
    /// Auto-scan interval in seconds (0 = disabled).
    pub auto_scan_interval_seconds: u64,
    /// Alert rule: fire on new device discovery.
    pub alert_rules_new_device: bool,
    /// Alert rule: fire on new open port.
    pub alert_rules_new_port: bool,
    /// Alert rule: fire when a known device goes offline.
    pub alert_rules_device_offline: bool,
    /// Alert rule: fire when an open port closes.
    pub alert_rules_port_closed: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            default_cidr: None,
            arp_settle_ms: arp::DEFAULT_SETTLE_MS,
            port_scan_timeout_ms: port_scan::DEFAULT_SCAN_TIMEOUT_MS,
            port_scan_concurrency: port_scan::DEFAULT_CONCURRENCY,
            port_scan_ports: String::new(),
            port_service_detection: true,
            ping_count: latency::DEFAULT_PING_COUNT,
            ping_timeout_ms: latency::DEFAULT_PING_TIMEOUT_MS,
            http_port: 80,
            http_path: latency::DEFAULT_HTTP_PATH.to_string(),
            http_timeout_ms: latency::DEFAULT_HTTP_TIMEOUT_MS,
            check_latency: true,
            history_retention_days: 90,
            enable_notifications: true,
            auto_scan_interval_seconds: 0,
            alert_rules_new_device: true,
            alert_rules_new_port: true,
            alert_rules_device_offline: true,
            alert_rules_port_closed: true,
        }
    }
}

/// Optional overrides for a scan. Missing fields fall back to the stored [`AppConfig`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanRequest {
    pub cidr: Option<String>,
    pub arp_settle_ms: Option<u64>,
    pub port_scan_timeout_ms: Option<u64>,
    pub port_scan_concurrency: Option<usize>,
    pub port_scan_ports: Option<String>,
    pub port_service_detection: Option<bool>,
    pub ping_count: Option<u32>,
    pub ping_timeout_ms: Option<u64>,
    pub http_port: Option<u16>,
    pub http_path: Option<String>,
    pub http_timeout_ms: Option<u64>,
    pub check_latency: Option<bool>,
}

impl ScanRequest {
    /// Merge these overrides onto the stored configuration.
    pub fn to_options(&self, config: &AppConfig) -> core::FullScanOptions {
        core::FullScanOptions {
            cidr: self
                .cidr
                .clone()
                .filter(|c| !c.trim().is_empty())
                .or_else(|| config.default_cidr.clone()),
            arp_settle_ms: self.arp_settle_ms.unwrap_or(config.arp_settle_ms),
            port_scan_timeout_ms: self.port_scan_timeout_ms.unwrap_or(config.port_scan_timeout_ms),
            port_scan_concurrency: self.port_scan_concurrency.unwrap_or(config.port_scan_concurrency),
            port_scan_ports: self
                .port_scan_ports
                .clone()
                .filter(|p| !p.trim().is_empty())
                .unwrap_or_else(|| config.port_scan_ports.clone()),
            port_service_detection: self
                .port_service_detection
                .unwrap_or(config.port_service_detection),
            ping_count: self.ping_count.unwrap_or(config.ping_count),
            ping_timeout_ms: self.ping_timeout_ms.unwrap_or(config.ping_timeout_ms),
            http_port: self.http_port.unwrap_or(config.http_port),
            http_path: self.http_path.clone().unwrap_or_else(|| config.http_path.clone()),
            http_timeout_ms: self.http_timeout_ms.unwrap_or(config.http_timeout_ms),
            check_latency: self.check_latency.unwrap_or(config.check_latency),
        }
    }
}

/// Request body for an ad-hoc TCP port scan (no database writes).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortScanRequest {
    pub hosts: Vec<String>,
    /// Ports to scan; empty = default well-known ports.
    pub ports: Option<Vec<u16>>,
    pub timeout_ms: Option<u64>,
    pub concurrency: Option<usize>,
    pub service_detection: Option<bool>,
}

/// Request body for an ad-hoc latency check (no database writes).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LatencyRequest {
    pub hosts: Vec<String>,
    pub ping_count: Option<u32>,
    pub ping_timeout_ms: Option<u64>,
    pub http_port: Option<u16>,
    pub http_path: Option<String>,
    pub http_timeout_ms: Option<u64>,
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

/// Where the frontend can reach the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiServerInfo {
    /// Database file used by the app; pass it as `dbPath` to the `api_*` commands.
    pub db_path: String,
    /// Base URL of the local REST server (e.g. `http://127.0.0.1:7357`), if it started.
    pub rest_url: Option<String>,
    /// Why the REST server did not start, if it failed.
    pub rest_error: Option<String>,
}

/// Tauri-managed state: keeps the REST server alive for the app's lifetime.
pub struct ApiServerState {
    pub info: ApiServerInfo,
    pub server: Option<RestServer>,
}

// ──────────────────────────────────────────────
// Config persistence
// ──────────────────────────────────────────────

pub fn read_config_from_db(db: &Database) -> AppConfig {
    let map = db.read_all_config().unwrap_or_default();
    let d = AppConfig::default();
    fn parsed<T: std::str::FromStr>(
        map: &std::collections::HashMap<String, String>,
        key: &str,
        fallback: T,
    ) -> T {
        map.get(key).and_then(|v| v.parse().ok()).unwrap_or(fallback)
    }
    AppConfig {
        default_cidr: map
            .get("default_cidr")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
        arp_settle_ms: parsed(&map, "arp_settle_ms", d.arp_settle_ms),
        port_scan_timeout_ms: parsed(&map, "port_scan_timeout_ms", d.port_scan_timeout_ms),
        port_scan_concurrency: parsed(&map, "port_scan_concurrency", d.port_scan_concurrency),
        port_scan_ports: map.get("port_scan_ports").cloned().unwrap_or(d.port_scan_ports),
        port_service_detection: parsed(&map, "port_service_detection", d.port_service_detection),
        ping_count: parsed(&map, "ping_count", d.ping_count),
        ping_timeout_ms: parsed(&map, "ping_timeout_ms", d.ping_timeout_ms),
        http_port: parsed(&map, "http_port", d.http_port),
        http_path: map.get("http_path").cloned().unwrap_or(d.http_path),
        http_timeout_ms: parsed(&map, "http_timeout_ms", d.http_timeout_ms),
        check_latency: parsed(&map, "check_latency", d.check_latency),
        history_retention_days: parsed(&map, "history_retention_days", d.history_retention_days),
        enable_notifications: parsed(&map, "enable_notifications", d.enable_notifications),
        auto_scan_interval_seconds: parsed(&map, "auto_scan_interval_seconds", d.auto_scan_interval_seconds),
        alert_rules_new_device: parsed(&map, "alert_rules_new_device", d.alert_rules_new_device),
        alert_rules_new_port: parsed(&map, "alert_rules_new_port", d.alert_rules_new_port),
        alert_rules_device_offline: parsed(&map, "alert_rules_device_offline", d.alert_rules_device_offline),
        alert_rules_port_closed: parsed(&map, "alert_rules_port_closed", d.alert_rules_port_closed),
    }
}

pub fn write_config_to_db(db: &Database, config: &AppConfig) -> Result<(), String> {
    let pairs: [(&str, String); 19] = [
        ("default_cidr", config.default_cidr.clone().unwrap_or_default()),
        ("arp_settle_ms", config.arp_settle_ms.to_string()),
        ("port_scan_timeout_ms", config.port_scan_timeout_ms.to_string()),
        ("port_scan_concurrency", config.port_scan_concurrency.to_string()),
        ("port_scan_ports", config.port_scan_ports.clone()),
        ("port_service_detection", config.port_service_detection.to_string()),
        ("ping_count", config.ping_count.to_string()),
        ("ping_timeout_ms", config.ping_timeout_ms.to_string()),
        ("http_port", config.http_port.to_string()),
        ("http_path", config.http_path.clone()),
        ("http_timeout_ms", config.http_timeout_ms.to_string()),
        ("check_latency", config.check_latency.to_string()),
        ("history_retention_days", config.history_retention_days.to_string()),
        ("enable_notifications", config.enable_notifications.to_string()),
        ("auto_scan_interval_seconds", config.auto_scan_interval_seconds.to_string()),
        ("alert_rules_new_device", config.alert_rules_new_device.to_string()),
        ("alert_rules_new_port", config.alert_rules_new_port.to_string()),
        ("alert_rules_device_offline", config.alert_rules_device_offline.to_string()),
        ("alert_rules_port_closed", config.alert_rules_port_closed.to_string()),
    ];
    let tx = db.conn.unchecked_transaction().map_err(|e| e.to_string())?;
    for (key, value) in pairs.iter() {
        db.set_config_value(key, value).map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}

// ──────────────────────────────────────────────
// Validation
// ──────────────────────────────────────────────

fn check_range(field: &str, value: u64, min: u64, max: u64) -> Result<(), ApiError> {
    if value < min || value > max {
        Err(ApiError::bad_request(format!(
            "{field} must be between {min} and {max} (got {value})"
        )))
    } else {
        Ok(())
    }
}

/// Clamp an optional `limit` parameter to `1..=MAX_LIST_LIMIT`.
pub fn clamp_limit(limit: Option<usize>, default: usize) -> usize {
    limit.unwrap_or(default).clamp(1, MAX_LIST_LIMIT)
}

/// Reject anything that is not a plain hostname / IPv4 / IPv6 literal.
/// Hosts are passed to the system `ping`, so a leading `-` must never get through.
pub fn validate_host(host: &str) -> Result<(), ApiError> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!("invalid host: {host:?}")))
    }
}

fn validate_http_path(path: &str) -> Result<(), ApiError> {
    if !path.starts_with('/') || path.len() > 2048 || path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ApiError::bad_request(format!(
            "http_path must start with '/' and contain no whitespace (got {path:?})"
        )));
    }
    Ok(())
}

fn validate_cidr(cidr: &str) -> Result<(), ApiError> {
    arp::Subnet::parse(cidr)
        .map(|_| ())
        .map_err(|e| ApiError::bad_request(e.to_string()))
}

/// Validate the effective options for a scan.
pub fn validate_scan_options(o: &core::FullScanOptions) -> Result<(), ApiError> {
    if let Some(cidr) = &o.cidr {
        validate_cidr(cidr)?;
    }
    check_range("arp_settle_ms", o.arp_settle_ms, 0, 60_000)?;
    check_range("port_scan_timeout_ms", o.port_scan_timeout_ms, 1, 60_000)?;
    check_range("port_scan_concurrency", o.port_scan_concurrency as u64, 1, 1024)?;
    check_range("ping_count", u64::from(o.ping_count), 1, 20)?;
    check_range("ping_timeout_ms", o.ping_timeout_ms, 1, 60_000)?;
    check_range("http_port", u64::from(o.http_port), 1, 65_535)?;
    validate_http_path(&o.http_path)?;
    check_range("http_timeout_ms", o.http_timeout_ms, 1, 60_000)?;
    Ok(())
}

/// Validate a configuration before storing it.
pub fn validate_config(config: &AppConfig) -> Result<(), ApiError> {
    let as_scan = ScanRequest::default().to_options(config);
    validate_scan_options(&as_scan)?;
    check_range("history_retention_days", config.history_retention_days, 0, 3650)?;
    Ok(())
}

// ──────────────────────────────────────────────
// Handlers (shared by Tauri commands and the HTTP server)
// ──────────────────────────────────────────────

/// Open the database at `db_path`, creating the schema if needed.
pub fn open_db(db_path: &str) -> Result<Database, ApiError> {
    if db_path.trim().is_empty() {
        return Err(ApiError::bad_request("db_path must not be empty"));
    }
    Database::open(db_path)
        .map_err(|e| ApiError::internal(format!("cannot open database {db_path}: {e}")))
}

/// Take the scan lock, or fail with 409 if a scan is already running.
pub fn acquire_scan_lock() -> Result<MutexGuard<'static, ()>, ApiError> {
    match SCAN_LOCK.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => Err(ApiError::conflict("a scan is already running")),
    }
}

/// Full network scan (ARP + ports + latency), persisted to the database.
///
/// Alerts raised by the scan (new devices, new ports) are passed to
/// [`alerts::notify_alerts`], which shows desktop notifications when enabled.
pub fn handle_scan(db: &mut Database, req: &ScanRequest) -> Result<core::FullScanResult, ApiError> {
    let options = req.to_options(&read_config_from_db(db));
    validate_scan_options(&options)?;
    let _guard = acquire_scan_lock()?;
    let result = core::full_scan(db, &options).map_err(|e| ApiError::internal(e.to_string()))?;
    alerts::notify_alerts(db, &result.alerts);
    Ok(result)
}

/// Port scan + latency check of one host, persisted to the database.
pub fn handle_scan_host(
    db: &mut Database,
    host: &str,
    req: &ScanRequest,
) -> Result<core::ScannedDevice, ApiError> {
    let host = host.trim();
    validate_host(host)?;
    let mut options = req.to_options(&read_config_from_db(db));
    options.cidr = None;
    options.arp_settle_ms = 0;
    validate_scan_options(&options)?;
    let _guard = acquire_scan_lock()?;
    core::scan_single_host(db, host, &options).map_err(|e| ApiError::internal(e.to_string()))
}

/// Ad-hoc TCP port scan; results are not stored.
pub fn handle_scan_ports(req: &PortScanRequest) -> Result<Vec<port_scan::HostScanResult>, ApiError> {
    if req.hosts.is_empty() {
        return Err(ApiError::bad_request("hosts must contain at least one host"));
    }
    if req.hosts.len() > MAX_PORT_SCAN_HOSTS {
        return Err(ApiError::bad_request(format!(
            "at most {MAX_PORT_SCAN_HOSTS} hosts can be scanned at once"
        )));
    }
    for host in &req.hosts {
        validate_host(host)?;
    }
    let ports = req.ports.clone().unwrap_or_default();
    if ports.iter().any(|p| *p == 0) {
        return Err(ApiError::bad_request("port 0 is not a valid port"));
    }
    let timeout_ms = req.timeout_ms.unwrap_or(port_scan::DEFAULT_SCAN_TIMEOUT_MS);
    let concurrency = req.concurrency.unwrap_or(port_scan::DEFAULT_CONCURRENCY);
    check_range("timeout_ms", timeout_ms, 1, 60_000)?;
    check_range("concurrency", concurrency as u64, 1, 1024)?;

    let options = port_scan::TcpScanOptions {
        hosts: req.hosts.clone(),
        ports,
        timeout_ms,
        concurrency,
        service_detection: req.service_detection.unwrap_or(true),
    };
    port_scan::tcp_scan(&options).map_err(|e| ApiError::internal(e.to_string()))
}

/// Ad-hoc latency check (ICMP + HTTP HEAD); results are not stored.
pub fn handle_scan_latency(req: &LatencyRequest) -> Result<Vec<latency::HostLatencyResult>, ApiError> {
    if req.hosts.is_empty() {
        return Err(ApiError::bad_request("hosts must contain at least one host"));
    }
    if req.hosts.len() > MAX_LATENCY_HOSTS {
        return Err(ApiError::bad_request(format!(
            "at most {MAX_LATENCY_HOSTS} hosts can be checked at once"
        )));
    }
    for host in &req.hosts {
        validate_host(host)?;
    }
    let count = req.ping_count.unwrap_or(latency::DEFAULT_PING_COUNT);
    let ping_timeout_ms = req.ping_timeout_ms.unwrap_or(latency::DEFAULT_PING_TIMEOUT_MS);
    let http_port = req.http_port.unwrap_or(80);
    let http_path = req
        .http_path
        .clone()
        .unwrap_or_else(|| latency::DEFAULT_HTTP_PATH.to_string());
    let http_timeout_ms = req.http_timeout_ms.unwrap_or(latency::DEFAULT_HTTP_TIMEOUT_MS);
    check_range("ping_count", u64::from(count), 1, 20)?;
    check_range("ping_timeout_ms", ping_timeout_ms, 1, 60_000)?;
    check_range("http_port", u64::from(http_port), 1, 65_535)?;
    validate_http_path(&http_path)?;
    check_range("http_timeout_ms", http_timeout_ms, 1, 60_000)?;

    let options = latency::LatencyCheckOptions {
        hosts: req.hosts.clone(),
        ping: latency::PingOptions {
            host: String::new(),
            count,
            timeout_ms: ping_timeout_ms,
        },
        http: latency::HttpHeadOptions {
            host: String::new(),
            port: http_port,
            use_https: false,
            path: http_path,
            host_header: latency::DEFAULT_HTTP_HOST.to_string(),
            timeout_ms: http_timeout_ms,
        },
    };
    latency::check_latency(&options).map_err(|e| ApiError::internal(e.to_string()))
}

pub fn handle_list_devices(db: &Database) -> Result<Vec<database::Device>, ApiError> {
    Ok(db.list_devices()?)
}

pub fn handle_get_device(db: &Database, ip: &str) -> Result<database::Device, ApiError> {
    db.get_device(ip)?
        .ok_or_else(|| ApiError::not_found(format!("device not found: {ip}")))
}

pub fn handle_get_device_ports(db: &Database, ip: &str) -> Result<Vec<database::Port>, ApiError> {
    Ok(db.get_ports(ip)?)
}

pub fn handle_list_ports(db: &Database) -> Result<Vec<database::Port>, ApiError> {
    Ok(db.list_open_ports()?)
}

pub fn handle_get_device_history(
    db: &Database,
    ip: &str,
    limit: Option<usize>,
) -> Result<Vec<database::HistoryRecord>, ApiError> {
    Ok(db.get_history(ip, clamp_limit(limit, DEFAULT_DEVICE_HISTORY_LIMIT))?)
}

pub fn handle_get_history(
    db: &Database,
    limit: Option<usize>,
    event_type: Option<&str>,
) -> Result<Vec<database::HistoryRecord>, ApiError> {
    let limit = clamp_limit(limit, DEFAULT_LIST_LIMIT);
    match event_type.map(str::trim).filter(|e| !e.is_empty()) {
        Some(event) => Ok(db.get_recent_history_by_type(event, limit)?),
        None => Ok(db.get_recent_history(limit)?),
    }
}

pub fn handle_get_alerts(
    db: &Database,
    acknowledged: Option<bool>,
    limit: Option<usize>,
) -> Result<Vec<database::Alert>, ApiError> {
    Ok(db.list_alerts(acknowledged, clamp_limit(limit, DEFAULT_LIST_LIMIT))?)
}

pub fn handle_get_device_alerts(db: &Database, ip: &str) -> Result<Vec<database::Alert>, ApiError> {
    Ok(db.get_device_alerts(ip)?)
}

pub fn handle_acknowledge_alert(db: &Database, id: i64) -> Result<(), ApiError> {
    match db.acknowledge_alert(id)? {
        0 => Err(ApiError::not_found(format!("alert not found: {id}"))),
        _ => Ok(()),
    }
}

pub fn handle_get_config(db: &Database) -> Result<AppConfig, ApiError> {
    Ok(read_config_from_db(db))
}

/// Replace the whole configuration.
pub fn handle_update_config(db: &Database, mut config: AppConfig) -> Result<AppConfig, ApiError> {
    config.default_cidr = config
        .default_cidr
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty());
    validate_config(&config)?;
    write_config_to_db(db, &config).map_err(ApiError::internal)?;
    Ok(read_config_from_db(db))
}

/// Update only the keys present in `patch` (a JSON object).
pub fn handle_patch_config(db: &Database, patch: &serde_json::Value) -> Result<AppConfig, ApiError> {
    let changes = patch
        .as_object()
        .ok_or_else(|| ApiError::bad_request("config body must be a JSON object"))?;
    let mut merged = serde_json::to_value(read_config_from_db(db))
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if let Some(target) = merged.as_object_mut() {
        for (key, value) in changes {
            if !target.contains_key(key) {
                return Err(ApiError::bad_request(format!("unknown config key: {key}")));
            }
            target.insert(key.clone(), value.clone());
        }
    }
    let config: AppConfig = serde_json::from_value(merged)
        .map_err(|e| ApiError::bad_request(format!("invalid config: {e}")))?;
    handle_update_config(db, config)
}

pub fn handle_get_stats(db: &Database) -> Result<ScanStats, ApiError> {
    Ok(ScanStats {
        device_count: db.device_count()?,
        port_count: db.list_open_ports()?.len() as i64,
        alert_count: db.alert_count()?,
        history_count: db.history_count()?,
        unacknowledged_alerts: db.get_unacknowledged_alerts()?.len() as i64,
    })
}

fn to_pretty_json<T: Serialize>(value: &T) -> Result<String, ApiError> {
    serde_json::to_string_pretty(value).map_err(|e| ApiError::internal(e.to_string()))
}

pub fn handle_export_devices(db: &Database) -> Result<String, ApiError> {
    to_pretty_json(&db.list_devices()?)
}

pub fn handle_export_history(db: &Database, limit: Option<usize>) -> Result<String, ApiError> {
    to_pretty_json(&db.get_recent_history(clamp_limit(limit, DEFAULT_EXPORT_HISTORY_LIMIT))?)
}

pub fn handle_export_ports(db: &Database) -> Result<String, ApiError> {
    to_pretty_json(&db.list_open_ports()?)
}

/// Clean up old history and alerts based on retention policy.
pub fn handle_cleanup(db: &Database) -> Result<CleanupResult, ApiError> {
    let config = read_config_from_db(db);
    if config.history_retention_days == 0 {
        return Ok(CleanupResult {
            history_deleted: 0,
            alerts_deleted: 0,
        });
    }
    let cutoff = Utc::now() - chrono::Duration::days(config.history_retention_days as i64);
    Ok(CleanupResult {
        history_deleted: db.delete_old_history(&cutoff)?,
        alerts_deleted: db.delete_old_alerts(&cutoff)?,
    })
}

/// Get all unacknowledged alerts (for the web dashboard to display via browser notifications).
pub fn handle_get_unacknowledged_alerts(db: &Database) -> Result<Vec<database::Alert>, ApiError> {
    Ok(db.get_unacknowledged_alerts()?)
}

/// Re-send desktop notifications for all unacknowledged alerts.
pub fn handle_notify_pending(db: &Database) -> Result<alerts::NotifyOutcome, ApiError> {
    Ok(alerts::notify_unacknowledged(db)?)
}

/// Show a test desktop notification (honours `enable_notifications`).
pub fn handle_test_notification(db: &Database) -> Result<alerts::NotifyOutcome, ApiError> {
    Ok(alerts::notify_one(
        db,
        &alerts::Notification {
            title: "SentryNet".to_string(),
            body: "Desktop notifications are working.".to_string(),
        },
    ))
}

// ──────────────────────────────────────────────
// Tauri commands
// ──────────────────────────────────────────────

/// Run a blocking handler off the async runtime and wrap it in an [`ApiResponse`].
async fn run_blocking<T, F>(job: F) -> Result<ApiResponse<T>, String>
where
    F: FnOnce() -> Result<T, ApiError> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map(ApiResponse::from_result)
        .map_err(|e| format!("background task failed: {e}"))
}

/// Where the frontend can find the database and the local REST server.
#[tauri::command]
pub fn api_server_info(state: tauri::State<'_, ApiServerState>) -> ApiServerInfo {
    state.info.clone()
}

/// Run a full network scan. Unset options fall back to the stored configuration.
#[tauri::command]
pub async fn api_scan(
    db_path: String,
    cidr: Option<String>,
    arp_settle_ms: Option<u64>,
    port_scan_timeout_ms: Option<u64>,
    port_scan_concurrency: Option<usize>,
    port_scan_ports: Option<String>,
    port_service_detection: Option<bool>,
    ping_count: Option<u32>,
    ping_timeout_ms: Option<u64>,
    http_port: Option<u16>,
    http_path: Option<String>,
    http_timeout_ms: Option<u64>,
    check_latency: Option<bool>,
) -> Result<ApiResponse<core::FullScanResult>, String> {
    let req = ScanRequest {
        cidr,
        arp_settle_ms,
        port_scan_timeout_ms,
        port_scan_concurrency,
        port_scan_ports,
        port_service_detection,
        ping_count,
        ping_timeout_ms,
        http_port,
        http_path,
        http_timeout_ms,
        check_latency,
    };
    run_blocking(move || handle_scan(&mut open_db(&db_path)?, &req)).await
}

/// Scan a single host by IP (ports + latency, no ARP).
#[tauri::command]
pub async fn api_scan_host(
    db_path: String,
    host: String,
    port_scan_timeout_ms: Option<u64>,
    port_scan_concurrency: Option<usize>,
    port_scan_ports: Option<String>,
    port_service_detection: Option<bool>,
    ping_count: Option<u32>,
    ping_timeout_ms: Option<u64>,
    http_port: Option<u16>,
    http_path: Option<String>,
    http_timeout_ms: Option<u64>,
    check_latency: Option<bool>,
) -> Result<ApiResponse<core::ScannedDevice>, String> {
    let req = ScanRequest {
        cidr: None,
        arp_settle_ms: None,
        port_scan_timeout_ms,
        port_scan_concurrency,
        port_scan_ports,
        port_service_detection,
        ping_count,
        ping_timeout_ms,
        http_port,
        http_path,
        http_timeout_ms,
        check_latency,
    };
    run_blocking(move || handle_scan_host(&mut open_db(&db_path)?, &host, &req)).await
}

/// Scan TCP ports on one or more hosts (not stored).
#[tauri::command]
pub async fn api_scan_ports(
    hosts: Vec<String>,
    ports: Option<Vec<u16>>,
    timeout_ms: Option<u64>,
    concurrency: Option<usize>,
    service_detection: Option<bool>,
) -> Result<ApiResponse<Vec<port_scan::HostScanResult>>, String> {
    let req = PortScanRequest {
        hosts,
        ports,
        timeout_ms,
        concurrency,
        service_detection,
    };
    run_blocking(move || handle_scan_ports(&req)).await
}

/// Check latency to one or more hosts (not stored).
#[tauri::command]
pub async fn api_scan_latency(
    hosts: Vec<String>,
    ping_count: Option<u32>,
    ping_timeout_ms: Option<u64>,
    http_port: Option<u16>,
    http_path: Option<String>,
    http_timeout_ms: Option<u64>,
) -> Result<ApiResponse<Vec<latency::HostLatencyResult>>, String> {
    let req = LatencyRequest {
        hosts,
        ping_count,
        ping_timeout_ms,
        http_port,
        http_path,
        http_timeout_ms,
    };
    run_blocking(move || handle_scan_latency(&req)).await
}

/// List all discovered devices.
#[tauri::command]
pub async fn api_get_devices(db_path: String) -> Result<ApiResponse<Vec<database::Device>>, String> {
    run_blocking(move || handle_list_devices(&open_db(&db_path)?)).await
}

/// Get a single device by IP address.
#[tauri::command]
pub async fn api_get_device(db_path: String, ip: String) -> Result<ApiResponse<database::Device>, String> {
    run_blocking(move || handle_get_device(&open_db(&db_path)?, &ip)).await
}

/// Get ports for a specific device.
#[tauri::command]
pub async fn api_get_device_ports(
    db_path: String,
    ip: String,
) -> Result<ApiResponse<Vec<database::Port>>, String> {
    run_blocking(move || handle_get_device_ports(&open_db(&db_path)?, &ip)).await
}

/// Get all open ports across all devices.
#[tauri::command]
pub async fn api_get_ports(db_path: String) -> Result<ApiResponse<Vec<database::Port>>, String> {
    run_blocking(move || handle_list_ports(&open_db(&db_path)?)).await
}

/// Get history records for a device.
#[tauri::command]
pub async fn api_get_device_history(
    db_path: String,
    ip: String,
    limit: Option<usize>,
) -> Result<ApiResponse<Vec<database::HistoryRecord>>, String> {
    run_blocking(move || handle_get_device_history(&open_db(&db_path)?, &ip, limit)).await
}

/// Get recent history across all devices, optionally filtered by event type.
#[tauri::command]
pub async fn api_get_history(
    db_path: String,
    limit: Option<usize>,
    event_type: Option<String>,
) -> Result<ApiResponse<Vec<database::HistoryRecord>>, String> {
    run_blocking(move || handle_get_history(&open_db(&db_path)?, limit, event_type.as_deref())).await
}

/// Get alerts, optionally filtered by acknowledged state.
#[tauri::command]
pub async fn api_get_alerts(
    db_path: String,
    acknowledged: Option<bool>,
    limit: Option<usize>,
) -> Result<ApiResponse<Vec<database::Alert>>, String> {
    run_blocking(move || handle_get_alerts(&open_db(&db_path)?, acknowledged, limit)).await
}

/// Get alerts for a specific device.
#[tauri::command]
pub async fn api_get_device_alerts(
    db_path: String,
    ip: String,
) -> Result<ApiResponse<Vec<database::Alert>>, String> {
    run_blocking(move || handle_get_device_alerts(&open_db(&db_path)?, &ip)).await
}

/// Acknowledge an alert by ID.
#[tauri::command]
pub async fn api_acknowledge_alert(db_path: String, id: i64) -> Result<ApiResponse<()>, String> {
    run_blocking(move || handle_acknowledge_alert(&open_db(&db_path)?, id)).await
}

/// Get application configuration.
#[tauri::command]
pub async fn api_get_config(db_path: String) -> Result<ApiResponse<AppConfig>, String> {
    run_blocking(move || handle_get_config(&open_db(&db_path)?)).await
}

/// Replace application configuration. Missing fields take their default values.
#[tauri::command]
pub async fn api_update_config(
    db_path: String,
    config: AppConfig,
) -> Result<ApiResponse<AppConfig>, String> {
    run_blocking(move || handle_update_config(&open_db(&db_path)?, config)).await
}

/// Get scan statistics.
#[tauri::command]
pub async fn api_get_stats(db_path: String) -> Result<ApiResponse<ScanStats>, String> {
    run_blocking(move || handle_get_stats(&open_db(&db_path)?)).await
}

/// Export device list as JSON.
#[tauri::command]
pub async fn api_export_devices(db_path: String) -> Result<ApiResponse<String>, String> {
    run_blocking(move || handle_export_devices(&open_db(&db_path)?)).await
}

/// Export history as JSON.
#[tauri::command]
pub async fn api_export_history(
    db_path: String,
    limit: Option<usize>,
) -> Result<ApiResponse<String>, String> {
    run_blocking(move || handle_export_history(&open_db(&db_path)?, limit)).await
}

/// Export open ports as JSON.
#[tauri::command]
pub async fn api_export_ports(db_path: String) -> Result<ApiResponse<String>, String> {
    run_blocking(move || handle_export_ports(&open_db(&db_path)?)).await
}

/// Clean up old history and alerts based on retention policy.
#[tauri::command]
pub async fn api_cleanup(db_path: String) -> Result<ApiResponse<CleanupResult>, String> {
    run_blocking(move || handle_cleanup(&open_db(&db_path)?)).await
}

/// Re-send desktop notifications for all unacknowledged alerts.
#[tauri::command]
pub async fn api_notify_pending_alerts(db_path: String) -> Result<ApiResponse<alerts::NotifyOutcome>, String> {
    run_blocking(move || handle_notify_pending(&open_db(&db_path)?)).await
}

/// Show a test desktop notification.
#[tauri::command]
pub async fn api_test_notification(db_path: String) -> Result<ApiResponse<alerts::NotifyOutcome>, String> {
    run_blocking(move || handle_test_notification(&open_db(&db_path)?)).await
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_test_db() -> Database {
        Database::open_memory().unwrap()
    }

    fn make_device(ip: &str, mac: &str) -> database::Device {
        let now = Utc::now();
        database::Device {
            ip: ip.to_string(),
            mac: mac.to_string(),
            name: Some("TestDevice".to_string()),
            vendor: Some("TestVendor".to_string()),
            last_seen: now,
            first_seen: now - Duration::hours(1),
        }
    }

    fn make_port(device_ip: &str, port: u16, service: &str) -> database::Port {
        database::Port {
            device_ip: device_ip.to_string(),
            port,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(service.to_string()),
        }
    }

    fn make_alert(device_ip: &str, alert_type: &str, message: &str) -> database::Alert {
        database::Alert {
            id: None,
            device_ip: device_ip.to_string(),
            alert_type: alert_type.to_string(),
            message: message.to_string(),
            acknowledged: false,
            created_at: Utc::now(),
        }
    }

    fn make_history(device_ip: &str, event_type: &str) -> database::HistoryRecord {
        database::HistoryRecord {
            id: None,
            device_ip: device_ip.to_string(),
            event_type: event_type.to_string(),
            details: None,
            timestamp: Utc::now(),
        }
    }

    // ── ApiResponse / ApiError ─────────────────

    #[test]
    fn test_api_response_ok() {
        let resp = ApiResponse::ok(42);
        assert!(resp.success);
        assert_eq!(resp.data, Some(42));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_api_response_err() {
        let resp: ApiResponse<()> = ApiResponse::err("something went wrong".to_string());
        assert!(!resp.success);
        assert!(resp.data.is_none());
        assert_eq!(resp.error, Some("something went wrong".to_string()));
    }

    #[test]
    fn test_api_response_from_result() {
        let ok: ApiResponse<i32> = ApiResponse::from_result(Ok(7));
        assert!(ok.success);
        assert_eq!(ok.data, Some(7));

        let err: ApiResponse<i32> = ApiResponse::from_result(Err(ApiError::not_found("nope")));
        assert!(!err.success);
        assert_eq!(err.error.as_deref(), Some("nope"));
    }

    #[test]
    fn test_api_response_serialization() {
        let json = serde_json::to_string(&ApiResponse::ok(vec!["a", "b"])).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"data\":[\"a\",\"b\"]"));
        assert!(json.contains("\"error\":null"));

        let json = serde_json::to_string(&ApiResponse::<()>::err("error msg".to_string())).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"data\":null"));
        assert!(json.contains("\"error\":\"error msg\""));
    }

    #[test]
    fn test_api_error_status_codes() {
        assert_eq!(ApiError::bad_request("x").status, 400);
        assert_eq!(ApiError::not_found("x").status, 404);
        assert_eq!(ApiError::conflict("x").status, 409);
        assert_eq!(ApiError::internal("x").status, 500);
    }

    // ── AppConfig ──────────────────────────────

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert_eq!(config.arp_settle_ms, 1500);
        assert_eq!(config.ping_count, 4);
        assert_eq!(config.http_port, 80);
        assert_eq!(config.history_retention_days, 90);
        assert!(config.enable_notifications);
        assert!(config.check_latency);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_app_config_partial_json_uses_defaults() {
        let config: AppConfig = serde_json::from_str(r#"{"ping_count": 2}"#).unwrap();
        assert_eq!(config.ping_count, 2);
        assert_eq!(config.http_port, 80);
        assert_eq!(config.history_retention_days, 90);
    }

    #[test]
    fn test_read_config_empty_db_returns_default() {
        let db = make_test_db();
        assert_eq!(read_config_from_db(&db), AppConfig::default());
    }

    #[test]
    fn test_write_and_read_config() {
        let db = make_test_db();
        let config = AppConfig {
            default_cidr: Some("192.168.1.0/24".to_string()),
            arp_settle_ms: 2000,
            port_scan_timeout_ms: 5000,
            port_scan_concurrency: 50,
            port_scan_ports: "22,80,443".to_string(),
            port_service_detection: false,
            ping_count: 5,
            ping_timeout_ms: 3000,
            http_port: 443,
            http_path: "/health".to_string(),
            http_timeout_ms: 10000,
            check_latency: false,
            history_retention_days: 60,
            enable_notifications: false,
            auto_scan_interval_seconds: 300,
            alert_rules_new_device: true,
            alert_rules_new_port: false,
            alert_rules_device_offline: true,
            alert_rules_port_closed: false,
        };
        write_config_to_db(&db, &config).unwrap();
        assert_eq!(read_config_from_db(&db), config);
    }

    #[test]
    fn test_empty_default_cidr_reads_back_as_none() {
        let db = make_test_db();
        write_config_to_db(&db, &AppConfig::default()).unwrap();
        assert_eq!(read_config_from_db(&db).default_cidr, None);
    }

    #[test]
    fn test_update_config_validates() {
        let db = make_test_db();
        let bad = AppConfig {
            ping_count: 0,
            ..AppConfig::default()
        };
        let err = handle_update_config(&db, bad).unwrap_err();
        assert_eq!(err.status, 400);
        assert!(err.message.contains("ping_count"));

        let bad_cidr = AppConfig {
            default_cidr: Some("10.0.0.0/8".to_string()),
            ..AppConfig::default()
        };
        assert_eq!(handle_update_config(&db, bad_cidr).unwrap_err().status, 400);

        let bad_path = AppConfig {
            http_path: "/a b".to_string(),
            ..AppConfig::default()
        };
        assert_eq!(handle_update_config(&db, bad_path).unwrap_err().status, 400);

        // Nothing invalid was stored.
        assert_eq!(read_config_from_db(&db), AppConfig::default());
    }

    #[test]
    fn test_update_config_normalizes_blank_cidr() {
        let db = make_test_db();
        let config = AppConfig {
            default_cidr: Some("   ".to_string()),
            ..AppConfig::default()
        };
        let saved = handle_update_config(&db, config).unwrap();
        assert_eq!(saved.default_cidr, None);
    }

    #[test]
    fn test_patch_config_merges_keys() {
        let db = make_test_db();
        let patch = serde_json::json!({ "ping_count": 6, "default_cidr": "192.168.0.0/24" });
        let saved = handle_patch_config(&db, &patch).unwrap();
        assert_eq!(saved.ping_count, 6);
        assert_eq!(saved.default_cidr.as_deref(), Some("192.168.0.0/24"));
        assert_eq!(saved.http_port, 80);

        let again = handle_patch_config(&db, &serde_json::json!({ "http_port": 8080 })).unwrap();
        assert_eq!(again.ping_count, 6);
        assert_eq!(again.http_port, 8080);
    }

    #[test]
    fn test_patch_config_rejects_unknown_and_bad_types() {
        let db = make_test_db();
        let err = handle_patch_config(&db, &serde_json::json!({ "nope": 1 })).unwrap_err();
        assert_eq!(err.status, 400);
        assert!(err.message.contains("nope"));

        let err = handle_patch_config(&db, &serde_json::json!({ "ping_count": "lots" })).unwrap_err();
        assert_eq!(err.status, 400);

        let err = handle_patch_config(&db, &serde_json::json!([1, 2])).unwrap_err();
        assert_eq!(err.status, 400);
    }

    // ── Scan request handling ──────────────────

    #[test]
    fn test_scan_request_falls_back_to_config() {
        let config = AppConfig {
            default_cidr: Some("10.1.2.0/24".to_string()),
            ping_count: 2,
            ..AppConfig::default()
        };
        let opts = ScanRequest::default().to_options(&config);
        assert_eq!(opts.cidr.as_deref(), Some("10.1.2.0/24"));
        assert_eq!(opts.ping_count, 2);

        let req = ScanRequest {
            cidr: Some("192.168.5.0/24".to_string()),
            ping_count: Some(1),
            check_latency: Some(false),
            ..ScanRequest::default()
        };
        let opts = req.to_options(&config);
        assert_eq!(opts.cidr.as_deref(), Some("192.168.5.0/24"));
        assert_eq!(opts.ping_count, 1);
        assert!(!opts.check_latency);
    }

    #[test]
    fn test_scan_rejects_invalid_cidr_before_scanning() {
        let mut db = make_test_db();
        let req = ScanRequest {
            cidr: Some("not-a-subnet".to_string()),
            ..ScanRequest::default()
        };
        assert_eq!(handle_scan(&mut db, &req).unwrap_err().status, 400);

        let too_big = ScanRequest {
            cidr: Some("10.0.0.0/8".to_string()),
            ..ScanRequest::default()
        };
        assert_eq!(handle_scan(&mut db, &too_big).unwrap_err().status, 400);
    }

    #[test]
    fn test_scan_host_rejects_bad_host() {
        let mut db = make_test_db();
        for host in ["", "-f", "1.2.3.4; rm -rf /", "a b"] {
            let err = handle_scan_host(&mut db, host, &ScanRequest::default()).unwrap_err();
            assert_eq!(err.status, 400, "host {host:?} should be rejected");
        }
    }

    #[test]
    fn test_validate_host() {
        assert!(validate_host("192.168.1.10").is_ok());
        assert!(validate_host("printer.local").is_ok());
        assert!(validate_host("fe80::1").is_ok());
        assert!(validate_host("-c").is_err());
        assert!(validate_host("host/../x").is_err());
    }

    #[test]
    fn test_port_scan_request_validation() {
        assert_eq!(handle_scan_ports(&PortScanRequest::default()).unwrap_err().status, 400);
        let zero_port = PortScanRequest {
            hosts: vec!["127.0.0.1".to_string()],
            ports: Some(vec![0]),
            ..PortScanRequest::default()
        };
        assert_eq!(handle_scan_ports(&zero_port).unwrap_err().status, 400);
        let bad_concurrency = PortScanRequest {
            hosts: vec!["127.0.0.1".to_string()],
            concurrency: Some(0),
            ..PortScanRequest::default()
        };
        assert_eq!(handle_scan_ports(&bad_concurrency).unwrap_err().status, 400);
    }

    #[test]
    fn test_latency_request_validation() {
        assert_eq!(handle_scan_latency(&LatencyRequest::default()).unwrap_err().status, 400);
        let bad = LatencyRequest {
            hosts: vec!["127.0.0.1".to_string()],
            ping_count: Some(0),
            ..LatencyRequest::default()
        };
        assert_eq!(handle_scan_latency(&bad).unwrap_err().status, 400);
    }

    #[test]
    fn test_scan_lock_is_exclusive() {
        let guard = acquire_scan_lock().unwrap();
        assert_eq!(acquire_scan_lock().unwrap_err().status, 409);
        drop(guard);
        assert!(acquire_scan_lock().is_ok());
    }

    // ── Read handlers ──────────────────────────

    #[test]
    fn test_device_handlers() {
        let db = make_test_db();
        db.upsert_device(&make_device("192.168.1.1", "AA:BB:CC:DD:EE:01")).unwrap();
        db.upsert_device(&make_device("192.168.1.2", "AA:BB:CC:DD:EE:02")).unwrap();
        db.upsert_port(&make_port("192.168.1.1", 22, "ssh"), &Utc::now().to_rfc3339())
            .unwrap();

        assert_eq!(handle_list_devices(&db).unwrap().len(), 2);
        assert_eq!(handle_get_device(&db, "192.168.1.1").unwrap().mac, "AA:BB:CC:DD:EE:01");
        assert_eq!(handle_get_device(&db, "10.9.9.9").unwrap_err().status, 404);
        assert_eq!(handle_get_device_ports(&db, "192.168.1.1").unwrap().len(), 1);
        assert_eq!(handle_list_ports(&db).unwrap().len(), 1);
    }

    #[test]
    fn test_history_handlers() {
        let db = make_test_db();
        db.append_history(&make_history("192.168.1.1", "discovered")).unwrap();
        db.append_history(&make_history("192.168.1.1", "port_added")).unwrap();
        db.append_history(&make_history("192.168.1.2", "discovered")).unwrap();

        assert_eq!(handle_get_history(&db, None, None).unwrap().len(), 3);
        assert_eq!(handle_get_history(&db, Some(2), None).unwrap().len(), 2);
        let discovered = handle_get_history(&db, None, Some("discovered")).unwrap();
        assert_eq!(discovered.len(), 2);
        assert!(discovered.iter().all(|r| r.event_type == "discovered"));
        assert_eq!(handle_get_history(&db, None, Some("  ")).unwrap().len(), 3);
        assert_eq!(handle_get_device_history(&db, "192.168.1.1", None).unwrap().len(), 2);
    }

    #[test]
    fn test_alert_handlers() {
        let db = make_test_db();
        let id1 = db.create_alert(&make_alert("192.168.1.1", "new_device", "one")).unwrap();
        let id2 = db.create_alert(&make_alert("192.168.1.2", "new_device", "two")).unwrap();
        assert_ne!(id1, id2, "create_alert must return the new row id");

        handle_acknowledge_alert(&db, id2).unwrap();
        assert_eq!(handle_acknowledge_alert(&db, 9999).unwrap_err().status, 404);

        assert_eq!(handle_get_alerts(&db, None, None).unwrap().len(), 2);
        let unacked = handle_get_alerts(&db, Some(false), None).unwrap();
        assert_eq!(unacked.len(), 1);
        assert_eq!(unacked[0].message, "one");
        let acked = handle_get_alerts(&db, Some(true), None).unwrap();
        assert_eq!(acked.len(), 1);
        assert_eq!(acked[0].id, Some(id2));
        assert_eq!(handle_get_alerts(&db, None, Some(1)).unwrap().len(), 1);
        assert_eq!(handle_get_device_alerts(&db, "192.168.1.1").unwrap().len(), 1);
    }

    #[test]
    fn test_stats_handler() {
        let db = make_test_db();
        db.upsert_device(&make_device("192.168.1.1", "AA:BB:CC:DD:EE:01")).unwrap();
        db.upsert_port(&make_port("192.168.1.1", 80, "http"), &Utc::now().to_rfc3339())
            .unwrap();
        db.create_alert(&make_alert("192.168.1.1", "new_device", "x")).unwrap();
        db.append_history(&make_history("192.168.1.1", "discovered")).unwrap();

        let stats = handle_get_stats(&db).unwrap();
        assert_eq!(stats.device_count, 1);
        assert_eq!(stats.port_count, 1);
        assert_eq!(stats.alert_count, 1);
        assert_eq!(stats.history_count, 1);
        assert_eq!(stats.unacknowledged_alerts, 1);
    }

    #[test]
    fn test_export_handlers_produce_json() {
        let db = make_test_db();
        db.upsert_device(&make_device("192.168.1.1", "AA:BB:CC:DD:EE:01")).unwrap();
        let devices: Vec<database::Device> =
            serde_json::from_str(&handle_export_devices(&db).unwrap()).unwrap();
        assert_eq!(devices.len(), 1);
        let history: Vec<database::HistoryRecord> =
            serde_json::from_str(&handle_export_history(&db, None).unwrap()).unwrap();
        assert!(history.is_empty());
        let ports: Vec<database::Port> =
            serde_json::from_str(&handle_export_ports(&db).unwrap()).unwrap();
        assert!(ports.is_empty());
    }

    #[test]
    fn test_cleanup_respects_retention_policy() {
        let db = make_test_db();
        let old = Utc::now() - Duration::days(120);
        db.conn
            .execute(
                "INSERT INTO history (device_ip, event_type, details, timestamp) VALUES ('192.168.1.1', 'discovered', 'old', ?1)",
                [old.to_rfc3339()],
            )
            .unwrap();
        db.append_history(&make_history("192.168.1.1", "discovered")).unwrap();
        let old_alert = database::Alert {
            created_at: old,
            ..make_alert("192.168.1.1", "new_device", "old")
        };
        let old_id = db.create_alert(&old_alert).unwrap();
        db.acknowledge_alert(old_id).unwrap();

        let result = handle_cleanup(&db).unwrap();
        assert_eq!(result.history_deleted, 1);
        assert_eq!(result.alerts_deleted, 1);
        assert_eq!(db.history_count().unwrap(), 1);
    }

    #[test]
    fn test_cleanup_disabled_when_retention_zero() {
        let db = make_test_db();
        handle_patch_config(&db, &serde_json::json!({ "history_retention_days": 0 })).unwrap();
        let old = Utc::now() - Duration::days(1000);
        db.conn
            .execute(
                "INSERT INTO history (device_ip, event_type, details, timestamp) VALUES ('192.168.1.1', 'discovered', 'old', ?1)",
                [old.to_rfc3339()],
            )
            .unwrap();
        let result = handle_cleanup(&db).unwrap();
        assert_eq!(result.history_deleted, 0);
        assert_eq!(db.history_count().unwrap(), 1);
    }

    #[test]
    fn test_clamp_limit() {
        assert_eq!(clamp_limit(None, 50), 50);
        assert_eq!(clamp_limit(Some(0), 50), 1);
        assert_eq!(clamp_limit(Some(usize::MAX), 50), MAX_LIST_LIMIT);
    }

    #[test]
    fn test_open_db_rejects_empty_path_and_creates_file() {
        assert_eq!(open_db("  ").err().unwrap().status, 400);
        let path = std::env::temp_dir().join(format!("sentrynet_api_open_{}.sqlite", std::process::id()));
        let db = open_db(path.to_str().unwrap()).unwrap();
        assert_eq!(db.device_count().unwrap(), 0);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
