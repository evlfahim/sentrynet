// Tauri v2 Rust library
pub use tauri;

pub mod arp;
pub mod database;
pub mod port_scan;

use std::time::Duration;

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

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![arp_scan, tcp_scan])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
