//! SentryNet REST API layer.
//!
//! Provides Tauri commands that act as REST-like endpoints for the web dashboard
//! and desktop app. All endpoints operate on a single SQLite database file.
//!
//! **IMPORTANT:** Commands in this module must be re-exported in `lib.rs` so that
//! the `#[tauri::command]` macro can generate its internal helpers at the crate root.

use crate::core;
use crate::database;
use crate::database::Database;
use crate::latency;
use crate::port_scan;
use chrono::Utc;
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
    let map = db.read_all_config().unwrap_or_default();
    AppConfig {
        default_cidr: map.get("default_cidr").cloned(),
        arp_settle_ms: map.get("arp_settle_ms").and_then(|v| v.parse().ok()).unwrap_or(1500),
        port_scan_timeout_ms: map.get("port_scan_timeout_ms").and_then(|v| v.parse().ok()).unwrap_or(crate::port_scan::DEFAULT_SCAN_TIMEOUT_MS),
        port_scan_concurrency: map.get("port_scan_concurrency").and_then(|v| v.parse().ok()).unwrap_or(crate::port_scan::DEFAULT_CONCURRENCY),
        port_service_detection: map.get("port_service_detection").and_then(|v| v.parse().ok()).unwrap_or(true),
        ping_count: map.get("ping_count").and_then(|v| v.parse().ok()).unwrap_or(crate::latency::DEFAULT_PING_COUNT),
        ping_timeout_ms: map.get("ping_timeout_ms").and_then(|v| v.parse().ok()).unwrap_or(crate::latency::DEFAULT_PING_TIMEOUT_MS),
        http_port: map.get("http_port").and_then(|v| v.parse().ok()).unwrap_or(80),
        http_path: map.get("http_path").cloned().unwrap_or_else(|| crate::latency::DEFAULT_HTTP_PATH.to_string()),
        http_timeout_ms: map.get("http_timeout_ms").and_then(|v| v.parse().ok()).unwrap_or(crate::latency::DEFAULT_HTTP_TIMEOUT_MS),
        check_latency: map.get("check_latency").and_then(|v| v.parse().ok()).unwrap_or(true),
        history_retention_days: map.get("history_retention_days").and_then(|v| v.parse().ok()).unwrap_or(90),
        enable_notifications: map.get("enable_notifications").and_then(|v| v.parse().ok()).unwrap_or(true),
    }
}

pub fn write_config_to_db(db: &Database, config: &AppConfig) -> Result<(), String> {
    db.set_config_value("default_cidr", &config.default_cidr.clone().unwrap_or_default())
        .map_err(|e| e.to_string())?;
    db.set_config_value("arp_settle_ms", &config.arp_settle_ms.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("port_scan_timeout_ms", &config.port_scan_timeout_ms.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("port_scan_concurrency", &config.port_scan_concurrency.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("port_service_detection", &config.port_service_detection.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("ping_count", &config.ping_count.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("ping_timeout_ms", &config.ping_timeout_ms.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("http_port", &config.http_port.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("http_path", &config.http_path)
        .map_err(|e| e.to_string())?;
    db.set_config_value("http_timeout_ms", &config.http_timeout_ms.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("check_latency", &config.check_latency.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("history_retention_days", &config.history_retention_days.to_string())
        .map_err(|e| e.to_string())?;
    db.set_config_value("enable_notifications", &config.enable_notifications.to_string())
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ──────────────────────────────────────────────
// REST API commands
// ──────────────────────────────────────────────

/// Run a full network scan via the REST API.
/// Returns an ApiResponse wrapper with the scan result.
#[tauri::command]
pub async fn api_scan(
    db_path: String,
    cidr: Option<String>,
    arp_settle_ms: Option<u64>,
    port_scan_timeout_ms: Option<u64>,
    port_scan_concurrency: Option<usize>,
    port_service_detection: Option<bool>,
    ping_count: Option<u32>,
    ping_timeout_ms: Option<u64>,
    http_port: Option<u16>,
    http_path: Option<String>,
    http_timeout_ms: Option<u64>,
    check_latency: Option<bool>,
) -> Result<ApiResponse<core::FullScanResult>, String> {
    let options = core::FullScanOptions {
        cidr,
        arp_settle_ms: arp_settle_ms.unwrap_or(1500),
        port_scan_timeout_ms: port_scan_timeout_ms.unwrap_or(port_scan::DEFAULT_SCAN_TIMEOUT_MS),
        port_scan_concurrency: port_scan_concurrency.unwrap_or(port_scan::DEFAULT_CONCURRENCY),
        port_service_detection: port_service_detection.unwrap_or(true),
        ping_count: ping_count.unwrap_or(latency::DEFAULT_PING_COUNT),
        ping_timeout_ms: ping_timeout_ms.unwrap_or(latency::DEFAULT_PING_TIMEOUT_MS),
        http_port: http_port.unwrap_or(80),
        http_path: http_path.unwrap_or_else(|| latency::DEFAULT_HTTP_PATH.to_string()),
        http_timeout_ms: http_timeout_ms.unwrap_or(latency::DEFAULT_HTTP_TIMEOUT_MS),
        check_latency: check_latency.unwrap_or(true),
    };

    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut db = Database::open(&db_path).map_err(|e| e.to_string())?;
        core::full_scan(&mut db, &options).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(scan_result) => Ok(ApiResponse::ok(scan_result)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Scan a single host by IP via the REST API.
#[tauri::command]
pub async fn api_scan_host(
    db_path: String,
    host: String,
    port_scan_timeout_ms: Option<u64>,
    port_scan_concurrency: Option<usize>,
    port_service_detection: Option<bool>,
    ping_count: Option<u32>,
    ping_timeout_ms: Option<u64>,
    http_port: Option<u16>,
    http_path: Option<String>,
    http_timeout_ms: Option<u64>,
    check_latency: Option<bool>,
) -> Result<ApiResponse<core::ScannedDevice>, String> {
    let options = core::FullScanOptions {
        cidr: None,
        arp_settle_ms: 0,
        port_scan_timeout_ms: port_scan_timeout_ms.unwrap_or(port_scan::DEFAULT_SCAN_TIMEOUT_MS),
        port_scan_concurrency: port_scan_concurrency.unwrap_or(port_scan::DEFAULT_CONCURRENCY),
        port_service_detection: port_service_detection.unwrap_or(true),
        ping_count: ping_count.unwrap_or(latency::DEFAULT_PING_COUNT),
        ping_timeout_ms: ping_timeout_ms.unwrap_or(latency::DEFAULT_PING_TIMEOUT_MS),
        http_port: http_port.unwrap_or(80),
        http_path: http_path.unwrap_or_else(|| latency::DEFAULT_HTTP_PATH.to_string()),
        http_timeout_ms: http_timeout_ms.unwrap_or(latency::DEFAULT_HTTP_TIMEOUT_MS),
        check_latency: check_latency.unwrap_or(true),
    };

    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut db = Database::open(&db_path).map_err(|e| e.to_string())?;
        core::scan_single_host(&mut db, &host, &options).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(device) => Ok(ApiResponse::ok(device)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Scan TCP ports on one or more hosts via the REST API.
#[tauri::command]
pub async fn api_scan_ports(
    hosts: Vec<String>,
    ports: Option<Vec<u16>>,
    timeout_ms: Option<u64>,
    concurrency: Option<usize>,
    service_detection: Option<bool>,
) -> Result<ApiResponse<Vec<port_scan::HostScanResult>>, String> {
    let options = port_scan::TcpScanOptions {
        hosts,
        ports: ports.unwrap_or_default(),
        timeout_ms: timeout_ms.unwrap_or(port_scan::DEFAULT_SCAN_TIMEOUT_MS),
        concurrency: concurrency.unwrap_or(port_scan::DEFAULT_CONCURRENCY),
        service_detection: service_detection.unwrap_or(true),
    };

    let result = tauri::async_runtime::spawn_blocking(move || port_scan::tcp_scan(&options))
        .await
        .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(results) => Ok(ApiResponse::ok(results)),
        Err(e) => Ok(ApiResponse::err(e.to_string())),
    }
}

/// Check latency to one or more hosts via the REST API.
#[tauri::command]
pub async fn api_scan_latency(
    hosts: Vec<String>,
    ping_count: Option<u32>,
    ping_timeout_ms: Option<u64>,
    http_port: Option<u16>,
    http_path: Option<String>,
    http_timeout_ms: Option<u64>,
) -> Result<ApiResponse<Vec<latency::HostLatencyResult>>, String> {
    let ping_opts = latency::PingOptions {
        host: String::new(),
        count: ping_count.unwrap_or(latency::DEFAULT_PING_COUNT),
        timeout_ms: ping_timeout_ms.unwrap_or(latency::DEFAULT_PING_TIMEOUT_MS),
    };
    let http_opts = latency::HttpHeadOptions {
        host: String::new(),
        port: http_port.unwrap_or(80),
        use_https: false,
        path: http_path.unwrap_or_else(|| latency::DEFAULT_HTTP_PATH.to_string()),
        host_header: "localhost".to_string(),
        timeout_ms: http_timeout_ms.unwrap_or(latency::DEFAULT_HTTP_TIMEOUT_MS),
    };
    let options = latency::LatencyCheckOptions {
        hosts,
        ping: ping_opts,
        http: http_opts,
    };

    let result = tauri::async_runtime::spawn_blocking(move || latency::check_latency(&options))
        .await
        .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(results) => Ok(ApiResponse::ok(results)),
        Err(e) => Ok(ApiResponse::err(e.to_string())),
    }
}

/// Get the list of all discovered devices.
#[tauri::command]
pub async fn api_get_devices(db_path: String) -> Result<ApiResponse<Vec<database::Device>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let devices = db.list_devices().map_err(|e| e.to_string())?;
        Ok::<_, String>(devices)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(devices) => Ok(ApiResponse::ok(devices)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Get a single device by IP address.
#[tauri::command]
pub async fn api_get_device(db_path: String, ip: String) -> Result<ApiResponse<database::Device>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        match db.get_device(&ip).map_err(|e| e.to_string())? {
            Some(device) => Ok::<_, String>(device),
            None => Err(format!("Device not found: {ip}")),
        }
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(device) => Ok(ApiResponse::ok(device)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Get ports for a specific device.
#[tauri::command]
pub async fn api_get_device_ports(
    db_path: String,
    ip: String,
) -> Result<ApiResponse<Vec<database::Port>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let ports = db.get_ports(&ip).map_err(|e| e.to_string())?;
        Ok::<_, String>(ports)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(ports) => Ok(ApiResponse::ok(ports)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Get all open ports across all devices.
#[tauri::command]
pub async fn api_get_ports(db_path: String) -> Result<ApiResponse<Vec<database::Port>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let ports = db.list_open_ports().map_err(|e| e.to_string())?;
        Ok::<_, String>(ports)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(ports) => Ok(ApiResponse::ok(ports)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Get history records for a device.
#[tauri::command]
pub async fn api_get_device_history(
    db_path: String,
    ip: String,
    limit: Option<usize>,
) -> Result<ApiResponse<Vec<database::HistoryRecord>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let records = db.get_history(&ip, limit.unwrap_or(50)).map_err(|e| e.to_string())?;
        Ok::<_, String>(records)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(records) => Ok(ApiResponse::ok(records)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Get recent history across all devices.
#[tauri::command]
pub async fn api_get_history(
    db_path: String,
    limit: Option<usize>,
    event_type: Option<String>,
) -> Result<ApiResponse<Vec<database::HistoryRecord>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let records = if let Some(ref event) = event_type {
            let all = db.get_recent_history(limit.unwrap_or(100)).map_err(|e| e.to_string())?;
            all.into_iter()
                .filter(|r| r.event_type == *event)
                .collect()
        } else {
            db.get_recent_history(limit.unwrap_or(100)).map_err(|e| e.to_string())?
        };
        Ok::<_, String>(records)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(records) => Ok(ApiResponse::ok(records)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Get all alerts.
#[tauri::command]
pub async fn api_get_alerts(
    db_path: String,
    acknowledged: Option<bool>,
    limit: Option<usize>,
) -> Result<ApiResponse<Vec<database::Alert>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let alerts = if acknowledged == Some(true) {
            let mut stmt = db.conn.prepare(
                "SELECT id, device_ip, alert_type, message, acknowledged, created_at \
                 FROM alerts WHERE acknowledged = 1 ORDER BY created_at DESC LIMIT ?1",
            ).map_err(|e| e.to_string())?;
            let alerts = stmt
                .query_map(rusqlite::params![limit.unwrap_or(100) as i64], |row| {
                    Database::row_to_alert(row)
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            alerts
        } else if acknowledged == Some(false) {
            db.get_unacknowledged_alerts().map_err(|e| e.to_string())?
        } else {
            let mut stmt = db.conn.prepare(
                "SELECT id, device_ip, alert_type, message, acknowledged, created_at \
                 FROM alerts ORDER BY created_at DESC LIMIT ?1",
            ).map_err(|e| e.to_string())?;
            let alerts = stmt
                .query_map(rusqlite::params![limit.unwrap_or(100) as i64], |row| {
                    Database::row_to_alert(row)
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            alerts
        };
        Ok::<_, String>(alerts)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(alerts) => Ok(ApiResponse::ok(alerts)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Get alerts for a specific device.
#[tauri::command]
pub async fn api_get_device_alerts(
    db_path: String,
    ip: String,
) -> Result<ApiResponse<Vec<database::Alert>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let alerts = db.get_device_alerts(&ip).map_err(|e| e.to_string())?;
        Ok::<_, String>(alerts)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(alerts) => Ok(ApiResponse::ok(alerts)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Acknowledge an alert by ID.
#[tauri::command]
pub async fn api_acknowledge_alert(db_path: String, id: i64) -> Result<ApiResponse<()>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        db.acknowledge_alert(id).map_err(|e| e.to_string())?;
        Ok::<_, String>(())
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(_) => Ok(ApiResponse::ok(())),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Get application configuration.
#[tauri::command]
pub async fn api_get_config(db_path: String) -> Result<ApiResponse<AppConfig>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let config = read_config_from_db(&db);
        Ok::<_, String>(config)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(config) => Ok(ApiResponse::ok(config)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Update application configuration.
#[tauri::command]
pub async fn api_update_config(
    db_path: String,
    config: AppConfig,
) -> Result<ApiResponse<AppConfig>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        write_config_to_db(&db, &config)?;
        Ok::<_, String>(config)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(config) => Ok(ApiResponse::ok(config)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Get scan statistics.
#[tauri::command]
pub async fn api_get_stats(db_path: String) -> Result<ApiResponse<ScanStats>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let stats = ScanStats {
            device_count: db.device_count().map_err(|e| e.to_string())?,
            port_count: db.list_open_ports().map_err(|e| e.to_string())?.len() as i64,
            alert_count: db.alert_count().map_err(|e| e.to_string())?,
            history_count: db.history_count().map_err(|e| e.to_string())?,
            unacknowledged_alerts: db.get_unacknowledged_alerts().map_err(|e| e.to_string())?.len() as i64,
        };
        Ok::<_, String>(stats)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(stats) => Ok(ApiResponse::ok(stats)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Export device list as JSON.
#[tauri::command]
pub async fn api_export_devices(db_path: String) -> Result<ApiResponse<String>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let devices = db.list_devices().map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(&devices).map_err(|e| e.to_string())?;
        Ok::<_, String>(json)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(json) => Ok(ApiResponse::ok(json)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Export history as JSON.
#[tauri::command]
pub async fn api_export_history(
    db_path: String,
    limit: Option<usize>,
) -> Result<ApiResponse<String>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let records = db.get_recent_history(limit.unwrap_or(1000)).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(&records).map_err(|e| e.to_string())?;
        Ok::<_, String>(json)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(json) => Ok(ApiResponse::ok(json)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Export ports as JSON.
#[tauri::command]
pub async fn api_export_ports(db_path: String) -> Result<ApiResponse<String>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let ports = db.list_open_ports().map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(&ports).map_err(|e| e.to_string())?;
        Ok::<_, String>(json)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(json) => Ok(ApiResponse::ok(json)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

/// Clean up old history and alerts based on retention policy.
#[tauri::command]
pub async fn api_cleanup(db_path: String) -> Result<ApiResponse<CleanupResult>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(&db_path).map_err(|e| e.to_string())?;
        let config = read_config_from_db(&db);
        let cutoff = if config.history_retention_days > 0 {
            Utc::now() - chrono::Duration::days(config.history_retention_days as i64)
        } else {
            return Ok::<_, String>(CleanupResult {
                history_deleted: 0,
                alerts_deleted: 0,
            });
        };

        let history_deleted = db.delete_old_history(&cutoff).map_err(|e| e.to_string())?;
        let alerts_deleted = db.delete_old_alerts(&cutoff).map_err(|e| e.to_string())?;

        Ok::<_, String>(CleanupResult {
            history_deleted,
            alerts_deleted,
        })
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(stats) => Ok(ApiResponse::ok(stats)),
        Err(e) => Ok(ApiResponse::err(e)),
    }
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database;
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

    // ──────────────────────────────────────────
    // ApiResponse tests
    // ──────────────────────────────────────────

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
    fn test_api_response_serialization_ok() {
        let resp = ApiResponse::ok(vec!["a", "b"]);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"data\":[\"a\",\"b\"]"));
        assert!(json.contains("\"error\":null"));
    }

    #[test]
    fn test_api_response_serialization_err() {
        let resp: ApiResponse<()> = ApiResponse::err("error msg".to_string());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"data\":null"));
        assert!(json.contains("\"error\":\"error msg\""));
    }

    // ──────────────────────────────────────────
    // AppConfig tests
    // ──────────────────────────────────────────

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert_eq!(config.arp_settle_ms, 1500);
        assert_eq!(config.ping_count, 4);
        assert_eq!(config.http_port, 80);
        assert_eq!(config.history_retention_days, 90);
        assert!(config.enable_notifications);
        assert!(config.check_latency);
    }

    #[test]
    fn test_app_config_serialization_roundtrip() {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.arp_settle_ms, config.arp_settle_ms);
        assert_eq!(deserialized.ping_count, config.ping_count);
        assert_eq!(deserialized.http_port, config.http_port);
        assert_eq!(deserialized.history_retention_days, config.history_retention_days);
    }

    #[test]
    fn test_app_config_custom_values() {
        let config = AppConfig {
            default_cidr: Some("10.0.0.0/24".to_string()),
            arp_settle_ms: 2000,
            port_scan_timeout_ms: 5000,
            port_scan_concurrency: 100,
            port_service_detection: false,
            ping_count: 5,
            ping_timeout_ms: 3000,
            http_port: 443,
            http_path: "/api/health".to_string(),
            http_timeout_ms: 10000,
            check_latency: false,
            history_retention_days: 30,
            enable_notifications: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.default_cidr, Some("10.0.0.0/24".to_string()));
        assert_eq!(deserialized.arp_settle_ms, 2000);
        assert_eq!(deserialized.ping_count, 5);
        assert_eq!(deserialized.http_port, 443);
        assert_eq!(deserialized.history_retention_days, 30);
        assert!(!deserialized.enable_notifications);
        assert!(!deserialized.check_latency);
    }

    // ──────────────────────────────────────────
    // ScanStats tests
    // ──────────────────────────────────────────

    #[test]
    fn test_scan_stats_serialization() {
        let stats = ScanStats {
            device_count: 5,
            port_count: 12,
            alert_count: 3,
            history_count: 42,
            unacknowledged_alerts: 1,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"device_count\":5"));
        assert!(json.contains("\"port_count\":12"));
        assert!(json.contains("\"alert_count\":3"));
        assert!(json.contains("\"history_count\":42"));
        assert!(json.contains("\"unacknowledged_alerts\":1"));
    }

    // ──────────────────────────────────────────
    // CleanupResult tests
    // ──────────────────────────────────────────

    #[test]
    fn test_cleanup_result_serialization() {
        let result = CleanupResult {
            history_deleted: 10,
            alerts_deleted: 2,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"history_deleted\":10"));
        assert!(json.contains("\"alerts_deleted\":2"));
    }

    // ──────────────────────────────────────────
    // Config persistence tests
    // ──────────────────────────────────────────

    #[test]
    fn test_read_config_empty_db_returns_default() {
        let db = make_test_db();
        let config = read_config_from_db(&db);
        assert_eq!(config.arp_settle_ms, 1500);
        assert_eq!(config.ping_count, 4);
    }

    #[test]
    fn test_write_and_read_config() {
        let db = make_test_db();
        let config = AppConfig {
            default_cidr: Some("192.168.1.0/24".to_string()),
            arp_settle_ms: 2000,
            port_scan_timeout_ms: 5000,
            port_scan_concurrency: 50,
            port_service_detection: false,
            ping_count: 5,
            ping_timeout_ms: 3000,
            http_port: 443,
            http_path: "/health".to_string(),
            http_timeout_ms: 10000,
            check_latency: false,
            history_retention_days: 60,
            enable_notifications: false,
        };
        write_config_to_db(&db, &config).unwrap();

        let read_config = read_config_from_db(&db);
        assert_eq!(read_config.default_cidr, Some("192.168.1.0/24".to_string()));
        assert_eq!(read_config.arp_settle_ms, 2000);
        assert_eq!(read_config.ping_count, 5);
        assert_eq!(read_config.http_port, 443);
        assert_eq!(read_config.history_retention_days, 60);
        assert!(!read_config.enable_notifications);
        assert!(!read_config.check_latency);
    }

    #[test]
    fn test_scan_stats_from_db() {
        let mut db = make_test_db();

        let d1 = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        let d2 = make_device("192.168.1.2", "AA:BB:CC:DD:EE:02");
        db.upsert_device(&d1).unwrap();
        db.upsert_device(&d2).unwrap();

        let p1 = make_port("192.168.1.1", 80, "http");
        let p2 = make_port("192.168.1.1", 443, "https");
        db.upsert_port(&p1, &Utc::now().to_rfc3339()).unwrap();
        db.upsert_port(&p2, &Utc::now().to_rfc3339()).unwrap();

        let a1 = make_alert("192.168.1.1", "new_device", "Device discovered");
        let a2 = make_alert("192.168.1.2", "new_device", "Device discovered");
        db.create_alert(&a1).unwrap();
        db.create_alert(&a2).unwrap();

        let stats = ScanStats {
            device_count: db.device_count().unwrap(),
            port_count: db.list_open_ports().unwrap().len() as i64,
            alert_count: db.alert_count().unwrap(),
            history_count: db.history_count().unwrap(),
            unacknowledged_alerts: db.get_unacknowledged_alerts().unwrap().len() as i64,
        };

        assert_eq!(stats.device_count, 2);
        assert_eq!(stats.port_count, 2);
        assert_eq!(stats.alert_count, 2);
        assert_eq!(stats.history_count, 0);
        assert_eq!(stats.unacknowledged_alerts, 2);
    }

    #[test]
    fn test_acknowledge_alert_reduces_unacknowledged_count() {
        let mut db = make_test_db();
        let alert = make_alert("192.168.1.1", "new_device", "Test alert");
        let id = db.create_alert(&alert).unwrap();

        let unacked_before = db.get_unacknowledged_alerts().unwrap().len();
        assert_eq!(unacked_before, 1);

        db.acknowledge_alert(id).unwrap();

        let unacked_after = db.get_unacknowledged_alerts().unwrap().len();
        assert_eq!(unacked_after, 0);
    }

    #[test]
    fn test_cleanup_respects_retention_policy() {
        let mut db = make_test_db();

        let old_timestamp = Utc::now() - Duration::days(30);
        db.conn.execute(
            "INSERT INTO history (device_ip, event_type, details, timestamp) VALUES ('192.168.1.1', 'discovered', 'old', ?1)",
            [old_timestamp.to_rfc3339()],
        ).unwrap();

        let recent_timestamp = Utc::now() - Duration::days(1);
        db.conn.execute(
            "INSERT INTO history (device_ip, event_type, details, timestamp) VALUES ('192.168.1.1', 'discovered', 'recent', ?1)",
            [recent_timestamp.to_rfc3339()],
        ).unwrap();

        assert_eq!(db.history_count().unwrap(), 2);

        let cutoff = Utc::now() - Duration::days(7);
        let deleted = db.delete_old_history(&cutoff).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.history_count().unwrap(), 1);
    }

    #[test]
    fn test_api_response_with_device_data() {
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        let resp = ApiResponse::ok(vec![device.clone()]);

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"ip\":\"192.168.1.1\""));
        assert!(json.contains("\"mac\":\"AA:BB:CC:DD:EE:01\""));
        assert!(json.contains("\"name\":\"TestDevice\""));
    }

    #[test]
    fn test_api_response_with_port_data() {
        let port = make_port("192.168.1.1", 22, "ssh");
        let resp = ApiResponse::ok(vec![port]);

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"port\":22"));
        assert!(json.contains("\"protocol\":\"tcp\""));
        assert!(json.contains("\"state\":\"open\""));
        assert!(json.contains("\"service\":\"ssh\""));
    }

    #[test]
    fn test_api_response_with_alert_data() {
        let alert = make_alert("192.168.1.1", "new_device", "New device found");
        let resp = ApiResponse::ok(vec![alert]);

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"alert_type\":\"new_device\""));
        assert!(json.contains("\"message\":\"New device found\""));
        assert!(json.contains("\"acknowledged\":false"));
    }
}
