// Tauri v2 Rust library
pub use tauri;

pub mod api;
pub mod arp;
pub mod core;
pub mod database;
pub mod latency;
pub mod port_scan;

use chrono::Utc;
use rusqlite::params;
use std::time::Duration;

// ──────────────────────────────────────────────
// Scanner commands (existing)
// ──────────────────────────────────────────────

/// Discover active hosts via ARP. `cidr` defaults to the local /24 subnet.
#[tauri::command]
async fn arp_scan(
    cidr: Option<String>,
    settle_ms: Option<u64>,
) -> Result<Vec<arp::ArpEntry>, String> {
    let options = arp::ArpScanOptions {
        cidr,
        probe: true,
        settle: Duration::from_millis(settle_ms.unwrap_or(arp::DEFAULT_SETTLE_MS)),
    };
    tauri::async_runtime::spawn_blocking(move || arp::arp_scan(&options))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Scan TCP ports on one or more hosts.
#[tauri::command]
async fn tcp_scan(
    hosts: Vec<String>,
    ports: Option<Vec<u16>>,
    timeout_ms: Option<u64>,
    concurrency: Option<usize>,
    service_detection: Option<bool>,
) -> Result<Vec<port_scan::HostScanResult>, String> {
    let options = port_scan::TcpScanOptions {
        hosts,
        ports: ports.unwrap_or_default(),
        timeout_ms: timeout_ms.unwrap_or(port_scan::DEFAULT_SCAN_TIMEOUT_MS),
        concurrency: concurrency.unwrap_or(port_scan::DEFAULT_CONCURRENCY),
        service_detection: service_detection.unwrap_or(true),
    };
    tauri::async_runtime::spawn_blocking(move || port_scan::tcp_scan(&options))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Check latency to one or more hosts using ICMP ping and HTTP HEAD.
#[tauri::command]
async fn check_latency(
    hosts: Vec<String>,
    ping_count: Option<u32>,
    ping_timeout_ms: Option<u64>,
    http_port: Option<u16>,
    http_path: Option<String>,
    http_timeout_ms: Option<u64>,
) -> Result<Vec<latency::HostLatencyResult>, String> {
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
    tauri::async_runtime::spawn_blocking(move || latency::check_latency(&options))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Run a full network scan: ARP discovery, port scanning, latency check,
/// database persistence, and alert generation.
#[tauri::command]
async fn full_scan(
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
) -> Result<core::FullScanResult, String> {
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
    tauri::async_runtime::spawn_blocking(move || {
        let mut db = database::Database::open(&db_path).map_err(|e| core::CoreError::Database(e.to_string()))?;
        core::full_scan(&mut db, &options)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

/// Scan a single host by IP: port scan + latency check, without ARP.
#[tauri::command]
async fn scan_single_host(
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
) -> Result<core::ScannedDevice, String> {
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
    tauri::async_runtime::spawn_blocking(move || {
        let mut db = database::Database::open(&db_path).map_err(|e| core::CoreError::Database(e.to_string()))?;
        core::scan_single_host(&mut db, &host, &options)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

// ──────────────────────────────────────────────
// REST API commands
// ──────────────────────────────────────────────

/// Run a full network scan via the REST API.
/// Returns an ApiResponse wrapper with the scan result.
#[tauri::command]
async fn api_scan(
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
) -> Result<api::ApiResponse<core::FullScanResult>, String> {
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
        let mut db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        core::full_scan(&mut db, &options).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(scan_result) => Ok(api::ApiResponse::ok(scan_result)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Scan a single host by IP via the REST API.
#[tauri::command]
async fn api_scan_host(
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
) -> Result<api::ApiResponse<core::ScannedDevice>, String> {
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
        let mut db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        core::scan_single_host(&mut db, &host, &options).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(device) => Ok(api::ApiResponse::ok(device)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Scan TCP ports on one or more hosts via the REST API.
#[tauri::command]
async fn api_scan_ports(
    hosts: Vec<String>,
    ports: Option<Vec<u16>>,
    timeout_ms: Option<u64>,
    concurrency: Option<usize>,
    service_detection: Option<bool>,
) -> Result<api::ApiResponse<Vec<port_scan::HostScanResult>>, String> {
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
        Ok(results) => Ok(api::ApiResponse::ok(results)),
        Err(e) => Ok(api::ApiResponse::err(e.to_string())),
    }
}

/// Check latency to one or more hosts via the REST API.
#[tauri::command]
async fn api_scan_latency(
    hosts: Vec<String>,
    ping_count: Option<u32>,
    ping_timeout_ms: Option<u64>,
    http_port: Option<u16>,
    http_path: Option<String>,
    http_timeout_ms: Option<u64>,
) -> Result<api::ApiResponse<Vec<latency::HostLatencyResult>>, String> {
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
        Ok(results) => Ok(api::ApiResponse::ok(results)),
        Err(e) => Ok(api::ApiResponse::err(e.to_string())),
    }
}

/// Get the list of all discovered devices.
#[tauri::command]
async fn api_get_devices(db_path: String) -> Result<api::ApiResponse<Vec<database::Device>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let devices = db.list_devices().map_err(|e| e.to_string())?;
        Ok::<_, String>(devices)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(devices) => Ok(api::ApiResponse::ok(devices)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Get a single device by IP address.
#[tauri::command]
async fn api_get_device(db_path: String, ip: String) -> Result<api::ApiResponse<database::Device>, String> {
    let ip_clone = ip.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        match db.get_device(&ip).map_err(|e| e.to_string())? {
            Some(device) => Ok::<_, String>(device),
            None => Err(format!("Device not found: {ip}")),
        }
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(device) => Ok(api::ApiResponse::ok(device)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Get ports for a specific device.
#[tauri::command]
async fn api_get_device_ports(db_path: String, ip: String) -> Result<api::ApiResponse<Vec<database::Port>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let ports = db.get_ports(&ip).map_err(|e| e.to_string())?;
        Ok::<_, String>(ports)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(ports) => Ok(api::ApiResponse::ok(ports)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Get all open ports across all devices.
#[tauri::command]
async fn api_get_ports(db_path: String) -> Result<api::ApiResponse<Vec<database::Port>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let ports = db.list_open_ports().map_err(|e| e.to_string())?;
        Ok::<_, String>(ports)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(ports) => Ok(api::ApiResponse::ok(ports)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Get history records for a device.
#[tauri::command]
async fn api_get_device_history(
    db_path: String,
    ip: String,
    limit: Option<usize>,
) -> Result<api::ApiResponse<Vec<database::HistoryRecord>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let records = db.get_history(&ip, limit.unwrap_or(50)).map_err(|e| e.to_string())?;
        Ok::<_, String>(records)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(records) => Ok(api::ApiResponse::ok(records)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Get recent history across all devices.
#[tauri::command]
async fn api_get_history(
    db_path: String,
    limit: Option<usize>,
    event_type: Option<String>,
) -> Result<api::ApiResponse<Vec<database::HistoryRecord>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
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
        Ok(records) => Ok(api::ApiResponse::ok(records)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Get all alerts.
#[tauri::command]
async fn api_get_alerts(
    db_path: String,
    acknowledged: Option<bool>,
    limit: Option<usize>,
) -> Result<api::ApiResponse<Vec<database::Alert>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let alerts = if acknowledged == Some(true) {
            let mut stmt = db.conn.prepare(
                "SELECT id, device_ip, alert_type, message, acknowledged, created_at \
                 FROM alerts WHERE acknowledged = 1 ORDER BY created_at DESC LIMIT ?1",
            ).map_err(|e| e.to_string())?;
            let alerts = stmt
                .query_map(params![limit.unwrap_or(100) as i64], |row| {
                    database::Database::row_to_alert(row)
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
                .query_map(params![limit.unwrap_or(100) as i64], |row| {
                    database::Database::row_to_alert(row)
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
        Ok(alerts) => Ok(api::ApiResponse::ok(alerts)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Get alerts for a specific device.
#[tauri::command]
async fn api_get_device_alerts(
    db_path: String,
    ip: String,
) -> Result<api::ApiResponse<Vec<database::Alert>>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let alerts = db.get_device_alerts(&ip).map_err(|e| e.to_string())?;
        Ok::<_, String>(alerts)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(alerts) => Ok(api::ApiResponse::ok(alerts)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Acknowledge an alert by ID.
#[tauri::command]
async fn api_acknowledge_alert(db_path: String, id: i64) -> Result<api::ApiResponse<()>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        db.acknowledge_alert(id).map_err(|e| e.to_string())?;
        Ok::<_, String>(())
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(_) => Ok(api::ApiResponse::ok(())),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Get application configuration.
#[tauri::command]
async fn api_get_config(db_path: String) -> Result<api::ApiResponse<api::AppConfig>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let config = api::read_config_from_db(&db);
        Ok::<_, String>(config)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(config) => Ok(api::ApiResponse::ok(config)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Update application configuration.
#[tauri::command]
async fn api_update_config(
    db_path: String,
    config: api::AppConfig,
) -> Result<api::ApiResponse<api::AppConfig>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        api::write_config_to_db(&db, &config)?;
        Ok::<_, String>(config)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(config) => Ok(api::ApiResponse::ok(config)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Get scan statistics.
#[tauri::command]
async fn api_get_stats(db_path: String) -> Result<api::ApiResponse<api::ScanStats>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let stats = api::ScanStats {
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
        Ok(stats) => Ok(api::ApiResponse::ok(stats)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Export device list as JSON.
#[tauri::command]
async fn api_export_devices(db_path: String) -> Result<api::ApiResponse<String>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let devices = db.list_devices().map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(&devices).map_err(|e| e.to_string())?;
        Ok::<_, String>(json)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(json) => Ok(api::ApiResponse::ok(json)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Export history as JSON.
#[tauri::command]
async fn api_export_history(
    db_path: String,
    limit: Option<usize>,
) -> Result<api::ApiResponse<String>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let records = db.get_recent_history(limit.unwrap_or(1000)).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(&records).map_err(|e| e.to_string())?;
        Ok::<_, String>(json)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(json) => Ok(api::ApiResponse::ok(json)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Export ports as JSON.
#[tauri::command]
async fn api_export_ports(db_path: String) -> Result<api::ApiResponse<String>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let ports = db.list_open_ports().map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(&ports).map_err(|e| e.to_string())?;
        Ok::<_, String>(json)
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(json) => Ok(api::ApiResponse::ok(json)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

/// Clean up old history and alerts based on retention policy.
#[tauri::command]
async fn api_cleanup(db_path: String) -> Result<api::ApiResponse<api::CleanupResult>, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut db = database::Database::open(&db_path).map_err(|e| e.to_string())?;
        let config = api::read_config_from_db(&db);
        let cutoff = if config.history_retention_days > 0 {
            Utc::now() - chrono::Duration::days(config.history_retention_days as i64)
        } else {
            return Ok::<_, String>(api::CleanupResult {
                history_deleted: 0,
                alerts_deleted: 0,
            });
        };

        let history_deleted = db.delete_old_history(&cutoff).map_err(|e| e.to_string())?;
        let alerts_deleted = db.delete_old_alerts(&cutoff).map_err(|e| e.to_string())?;

        Ok::<_, String>(api::CleanupResult {
            history_deleted,
            alerts_deleted,
        })
    })
    .await
    .map_err(|e| format!("spawn error: {e}"))?;

    match result {
        Ok(stats) => Ok(api::ApiResponse::ok(stats)),
        Err(e) => Ok(api::ApiResponse::err(e)),
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            // Scanner commands
            arp_scan,
            tcp_scan,
            check_latency,
            full_scan,
            scan_single_host,
            // REST API commands
            api_scan,
            api_scan_host,
            api_scan_ports,
            api_scan_latency,
            api_get_devices,
            api_get_device,
            api_get_device_ports,
            api_get_ports,
            api_get_device_history,
            api_get_history,
            api_get_alerts,
            api_get_device_alerts,
            api_acknowledge_alert,
            api_get_config,
            api_update_config,
            api_get_stats,
            api_export_devices,
            api_export_history,
            api_export_ports,
            api_cleanup,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
