// Tauri v2 Rust library
pub use tauri;

pub mod api;
pub mod arp;
pub mod core;
pub mod database;
pub mod latency;
pub mod port_scan;

use std::time::Duration;

// ──────────────────────────────────────────────
// Scanner commands
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
            api::api_scan,
            api::api_scan_host,
            api::api_scan_ports,
            api::api_scan_latency,
            api::api_get_devices,
            api::api_get_device,
            api::api_get_device_ports,
            api::api_get_ports,
            api::api_get_device_history,
            api::api_get_history,
            api::api_get_alerts,
            api::api_get_device_alerts,
            api::api_acknowledge_alert,
            api::api_get_config,
            api::api_update_config,
            api::api_get_stats,
            api::api_export_devices,
            api::api_export_history,
            api::api_export_ports,
            api::api_cleanup,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
