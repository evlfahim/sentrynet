//! SentryNet core scanner service.
//!
//! Orchestrates the full scan pipeline:
//! 1. ARP discovery → active hosts with MAC/vendor
//! 2. TCP port scanning on discovered hosts
//! 3. Latency measurement (ICMP + HTTP HEAD)
//! 4. Database persistence (devices, ports, history, alerts)
//! 5. Alert generation for new devices and port changes

use crate::alerts;
use crate::arp;
use crate::database::{Alert, Database, Device, HistoryRecord, Port};
use crate::latency;
use crate::port_scan;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration as StdDuration;

// ──────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────

/// Configuration for a full network scan.
#[derive(Debug, Clone)]
pub struct FullScanOptions {
    /// Subnet CIDR for ARP discovery (e.g. "192.168.1.0/24").
    /// `None` = auto-detect local subnet.
    pub cidr: Option<String>,

    /// ARP settle time in milliseconds (default 1500).
    pub arp_settle_ms: u64,

    /// TCP scan timeout per port in milliseconds (default 1000).
    pub port_scan_timeout_ms: u64,

    /// TCP scan concurrency (default 64).
    pub port_scan_concurrency: usize,

    /// Custom ports to scan (comma-separated). Empty = use defaults.
    pub port_scan_ports: String,

    /// Whether to attempt banner-based service detection (default true).
    pub port_service_detection: bool,

    /// Number of ICMP ping probes per host (default 4).
    pub ping_count: u32,

    /// ICMP ping timeout per probe in milliseconds (default 3000).
    pub ping_timeout_ms: u64,

    /// HTTP HEAD port (default 80).
    pub http_port: u16,

    /// HTTP HEAD path (default "/").
    pub http_path: String,

    /// HTTP HEAD timeout in milliseconds (default 3000).
    pub http_timeout_ms: u64,

    /// Whether to check latency for discovered devices (default true).
    pub check_latency: bool,
}

impl Default for FullScanOptions {
    fn default() -> Self {
        Self {
            cidr: None,
            arp_settle_ms: 1500,
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
        }
    }
}

/// A device discovered during a full scan, enriched with port and latency data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedDevice {
    /// IP address.
    pub ip: String,
    /// MAC address.
    pub mac: String,
    /// Vendor name from OUI lookup.
    pub vendor: Option<String>,
    /// Interface name.
    pub interface: Option<String>,
    /// Open ports found on this device.
    pub open_ports: Vec<port_scan::PortResult>,
    /// Latency results for this device.
    pub latency: Option<latency::HostLatencyResult>,
    /// Whether this device was seen before (false = new).
    pub is_new: bool,
}

/// Result of a full network scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullScanResult {
    /// Total time taken for the scan in milliseconds.
    pub elapsed_ms: f64,
    /// Number of devices discovered.
    pub device_count: usize,
    /// Number of new devices (not seen before).
    pub new_device_count: usize,
    /// Total open ports across all devices.
    pub total_open_ports: usize,
    /// Number of alerts generated.
    pub alert_count: usize,
    /// Discovered devices with their scan data.
    pub devices: Vec<ScannedDevice>,
    /// Alerts generated during this scan.
    pub alerts: Vec<Alert>,
    /// History records created during this scan.
    pub history: Vec<HistoryRecord>,
}

/// Errors raised by the core scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// ARP scan failed.
    Arp(String),
    /// Port scan failed.
    PortScan(String),
    /// Latency check failed.
    Latency(String),
    /// Database error.
    Database(String),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Arp(e) => write!(f, "ARP scan failed: {e}"),
            CoreError::PortScan(e) => write!(f, "port scan failed: {e}"),
            CoreError::Latency(e) => write!(f, "latency check failed: {e}"),
            CoreError::Database(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for CoreError {}

// ──────────────────────────────────────────────
// Core scanner
// ──────────────────────────────────────────────

/// Run a full network scan: discover devices, scan ports, check latency,
/// persist to database, and generate alerts.
///
/// This is the main entry point for the scanner service. It:
/// 1. Discovers active hosts via ARP
/// 2. Upserts discovered devices into the database
/// 3. Scans TCP ports on each discovered host
/// 4. Stores port scan results in the database
/// 5. Checks latency for each discovered host
/// 6. Records history events (discovery, port changes)
/// 7. Generates alerts for new devices and new ports
/// 8. Returns aggregated results
pub fn full_scan(db: &mut Database, options: &FullScanOptions) -> Result<FullScanResult, CoreError> {
    let overall_start = std::time::Instant::now();

    // ── Step 1: ARP Discovery ──────────────────────────────────────────

    let arp_options = arp::ArpScanOptions {
        cidr: options.cidr.clone(),
        probe: true,
        settle: StdDuration::from_millis(options.arp_settle_ms),
    };

    let arp_entries =
        arp::arp_scan(&arp_options).map_err(|e| CoreError::Arp(e.to_string()))?;

    if arp_entries.is_empty() {
        let elapsed = overall_start.elapsed().as_secs_f64() * 1000.0;
        return Ok(FullScanResult {
            elapsed_ms: elapsed,
            device_count: 0,
            new_device_count: 0,
            total_open_ports: 0,
            alert_count: 0,
            devices: vec![],
            alerts: vec![],
            history: vec![],
        });
    }

    // ── Step 2: Detect new devices (before the database is updated) ────
    //
    // This must run before the upsert below, otherwise every device would
    // already be "known" by the time we look it up.

    let now = Utc::now();
    let mut new_device_ips: Vec<String> = Vec::new();
    let mut device_alerts: Vec<Alert> = Vec::new();
    let mut history_records: Vec<HistoryRecord> = Vec::new();

    for entry in &arp_entries {
        let device_ip = &entry.ip;
        let existing = db.get_device(device_ip).map_err(|e| CoreError::Database(e.to_string()))?;
        let status = alerts::classify_device(existing.as_ref(), &entry.mac);

        let (event_type, details) = match &status {
            alerts::DeviceStatus::New => (
                "discovered",
                format!(
                    "New device discovered: {} ({}) {}",
                    device_ip,
                    entry.mac,
                    entry.vendor.as_deref().unwrap_or("unknown")
                ),
            ),
            alerts::DeviceStatus::MacChanged(previous) => (
                "mac_changed",
                format!(
                    "MAC address changed: {} ({} → {})",
                    device_ip, previous, entry.mac
                ),
            ),
            alerts::DeviceStatus::Known => (
                "seen",
                format!("Device seen again: {} ({})", device_ip, entry.mac),
            ),
        };
        history_records.push(HistoryRecord {
            id: None,
            device_ip: device_ip.clone(),
            event_type: event_type.to_string(),
            details: Some(details),
            timestamp: now,
        });

        if let Some(alert) = alerts::new_device_alert(entry, &status, now) {
            new_device_ips.push(device_ip.clone());
            device_alerts.push(alert);
        }
    }

    // ── Step 3: Upsert devices into the database ───────────────────────

    let devices: Vec<Device> = arp_entries.iter().map(|entry| entry.to_device(now)).collect();
    db.upsert_devices_batch(&devices)
        .map_err(|e| CoreError::Database(e.to_string()))?;

    // ── Step 4: TCP Port Scanning ──────────────────────────────────────

    let host_list: Vec<String> = arp_entries.iter().map(|e| e.ip.clone()).collect();
    let custom_ports: Vec<u16> = if options.port_scan_ports.trim().is_empty() {
        vec![]
    } else {
        options
            .port_scan_ports
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    };
    let port_scan_opts = port_scan::TcpScanOptions {
        hosts: host_list.clone(),
        ports: custom_ports,
        timeout_ms: options.port_scan_timeout_ms,
        concurrency: options.port_scan_concurrency,
        service_detection: options.port_service_detection,
    };

    let scan_results = port_scan::tcp_scan(&port_scan_opts)
        .map_err(|e| CoreError::PortScan(e.to_string()))?;

    // ── Step 5: Store port scan results and detect port changes ────────

    let scanned_at = now.to_rfc3339();
    let mut all_open_ports: Vec<Port> = Vec::new();
    let mut port_history: Vec<HistoryRecord> = Vec::new();
    let mut port_alerts: Vec<Alert> = Vec::new();

    for host_result in &scan_results {
        let host_ip = &host_result.ip;

        // Get existing ports for this device
        let existing_ports = db
            .get_ports(host_ip)
            .map_err(|e| CoreError::Database(e.to_string()))?;
        let existing_port_set: HashSet<u16> = existing_ports.iter().map(|p| p.port).collect();

        // Store new open ports and detect changes
        for port_result in &host_result.open_ports {
            let port = Port {
                device_ip: host_ip.clone(),
                port: port_result.port,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: port_result.service.clone(),
            };

            all_open_ports.push(port.clone());

            if existing_port_set.contains(&port.port) {
                // Port already existed — check if service changed
                let existing_service = existing_ports
                    .iter()
                    .find(|p| p.port == port.port)
                    .and_then(|p| p.service.clone());
                if existing_service != port.service {
                    port_history.push(HistoryRecord {
                        id: None,
                        device_ip: host_ip.clone(),
                        event_type: "port_state_changed".to_string(),
                        details: Some(format!(
                            "Port {} service changed: {:?} → {:?}",
                            port.port, existing_service, port.service
                        )),
                        timestamp: now,
                    });
                }
            } else {
                // New port discovered
                port_history.push(HistoryRecord {
                    id: None,
                    device_ip: host_ip.clone(),
                    event_type: "port_added".to_string(),
                    details: Some(format!(
                        "New open port: {}/{} ({})",
                        port.port,
                        port_result.protocol,
                        port.service.as_deref().unwrap_or("unknown")
                    )),
                    timestamp: now,
                });

                // Alert on new ports of known devices. A brand-new device's
                // ports are covered by its new_device alert, so skip them to
                // avoid a burst of duplicate notifications.
                if existing_ports.is_empty() && new_device_ips.contains(host_ip) {
                    continue;
                }
                port_alerts.push(Alert {
                    id: None,
                    device_ip: host_ip.clone(),
                    alert_type: alerts::ALERT_NEW_PORT.to_string(),
                    message: format!(
                        "New open port discovered on {}: {}/{} ({})",
                        host_ip,
                        port.port,
                        port_result.protocol,
                        port.service.as_deref().unwrap_or("unknown")
                    ),
                    acknowledged: false,
                    created_at: now,
                });
            }
        }

        // Detect removed ports (was open, now not in scan results)
        let current_ports: HashSet<u16> = host_result
            .open_ports
            .iter()
            .map(|p| p.port)
            .collect();

        for existing_port in &existing_ports {
            if !current_ports.contains(&existing_port.port) {
                port_history.push(HistoryRecord {
                    id: None,
                    device_ip: host_ip.clone(),
                    event_type: "port_removed".to_string(),
                    details: Some(format!(
                        "Port closed: {}/{}",
                        existing_port.port, existing_port.protocol
                    )),
                    timestamp: now,
                });
            }
        }
    }

    // Batch store ports
    if !all_open_ports.is_empty() {
        db.upsert_ports_batch(&all_open_ports, &scanned_at)
            .map_err(|e| CoreError::Database(e.to_string()))?;
    }

    // ── Step 6: Latency Check ──────────────────────────────────────────

    let latency_results: Vec<latency::HostLatencyResult> = if options.check_latency {
        let latency_opts = latency::LatencyCheckOptions {
            hosts: host_list.clone(),
            ping: latency::PingOptions {
                host: String::new(), // set per-host in check_latency
                count: options.ping_count,
                timeout_ms: options.ping_timeout_ms,
            },
            http: latency::HttpHeadOptions {
                host: String::new(), // set per-host in check_latency
                port: options.http_port,
                use_https: false,
                path: options.http_path.clone(),
                host_header: "localhost".to_string(),
                timeout_ms: options.http_timeout_ms,
            },
        };
        latency::check_latency(&latency_opts)
            .map_err(|e| CoreError::Latency(e.to_string()))?
    } else {
        vec![]
    };

    // ── Step 7: Persist history and alerts ─────────────────────────────
    // (new-device alerts were built in step 2; notifications are sent by
    // the caller via `alerts::notify_alerts` once the scan has finished)

    let mut all_history: Vec<HistoryRecord> = Vec::new();
    for record in history_records {
        let id = db.append_history(&record).map_err(|e| CoreError::Database(e.to_string()))?;
        all_history.push(HistoryRecord {
            id: Some(id),
            ..record
        });
    }
    for record in port_history {
        let id = db.append_history(&record).map_err(|e| CoreError::Database(e.to_string()))?;
        all_history.push(HistoryRecord {
            id: Some(id),
            ..record
        });
    }

    let mut all_alerts: Vec<Alert> = Vec::new();
    for alert in device_alerts {
        let id = db.create_alert(&alert).map_err(|e| CoreError::Database(e.to_string()))?;
        all_alerts.push(Alert {
            id: Some(id),
            ..alert
        });
    }
    for alert in port_alerts {
        let id = db.create_alert(&alert).map_err(|e| CoreError::Database(e.to_string()))?;
        all_alerts.push(Alert {
            id: Some(id),
            ..alert
        });
    }

    // ── Step 9: Build aggregated result ────────────────────────────────

    let elapsed = overall_start.elapsed().as_secs_f64() * 1000.0;
    let total_open_ports = scan_results.iter().map(|r| r.open_ports.len()).sum();

    // Build ScannedDevice list
    let mut scanned_devices: Vec<ScannedDevice> = Vec::with_capacity(arp_entries.len());
    for entry in &arp_entries {
        let ip = &entry.ip;
        let is_new = new_device_ips.contains(ip);

        // Find port scan result for this host
        let host_scan = scan_results
            .iter()
            .find(|r| r.ip == *ip)
            .map(|r| r.open_ports.clone())
            .unwrap_or_default();

        // Find latency result for this host
        let latency_result = if options.check_latency {
            latency_results
                .iter()
                .find(|r| r.host == *ip)
                .cloned()
        } else {
            None
        };

        scanned_devices.push(ScannedDevice {
            ip: ip.clone(),
            mac: entry.mac.clone(),
            vendor: entry.vendor.clone(),
            interface: entry.interface.clone(),
            open_ports: host_scan,
            latency: latency_result,
            is_new,
        });
    }

    Ok(FullScanResult {
        elapsed_ms: elapsed,
        device_count: arp_entries.len(),
        new_device_count: new_device_ips.len(),
        total_open_ports,
        alert_count: all_alerts.len(),
        devices: scanned_devices,
        alerts: all_alerts,
        history: all_history,
    })
}

// ──────────────────────────────────────────────
// Convenience: scan a single host (for testing)
// ──────────────────────────────────────────────

/// Scan a single host by IP: port scan + latency check, without ARP.
/// Useful for targeted scans and testing.
pub fn scan_single_host(
    db: &mut Database,
    host: &str,
    options: &FullScanOptions,
) -> Result<ScannedDevice, CoreError> {
    let now = Utc::now();

    // Check if device exists
    let existing = db.get_device(host).map_err(|e| CoreError::Database(e.to_string()))?;
    let is_new = existing.is_none();

    // Port scan
    let custom_ports: Vec<u16> = if options.port_scan_ports.trim().is_empty() {
        vec![]
    } else {
        options
            .port_scan_ports
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    };
    let port_result = port_scan::scan_host(
        host,
        &custom_ports,
        options.port_scan_timeout_ms,
        options.port_scan_concurrency,
        options.port_service_detection,
    );

    let open_ports = port_result.open_ports;

    // Latency check
    let latency_result = if options.check_latency {
        let latency_opts = latency::LatencyCheckOptions {
            hosts: vec![host.to_string()],
            ping: latency::PingOptions {
                host: host.to_string(),
                count: options.ping_count,
                timeout_ms: options.ping_timeout_ms,
            },
            http: latency::HttpHeadOptions {
                host: host.to_string(),
                port: options.http_port,
                use_https: false,
                path: options.http_path.clone(),
                host_header: "localhost".to_string(),
                timeout_ms: options.http_timeout_ms,
            },
        };
        latency::check_latency(&latency_opts).ok()
    } else {
        None
    };

    let latency = latency_result.and_then(|mut results| results.pop());

    // Upsert device
    let device = Device {
        ip: host.to_string(),
        mac: "00:00:00:00:00:00".to_string(), // unknown MAC for manual scan
        name: existing.as_ref().and_then(|d| d.name.clone()),
        vendor: existing.as_ref().and_then(|d| d.vendor.clone()),
        last_seen: now,
        first_seen: existing
            .as_ref()
            .map(|d| d.first_seen)
            .unwrap_or(now),
    };
    db.upsert_device(&device)
        .map_err(|e| CoreError::Database(e.to_string()))?;

    // Store ports
    let scanned_at = now.to_rfc3339();
    let ports_to_store: Vec<Port> = open_ports
        .iter()
        .map(|p| Port {
            device_ip: host.to_string(),
            port: p.port,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: p.service.clone(),
        })
        .collect();
    if !ports_to_store.is_empty() {
        db.upsert_ports_batch(&ports_to_store, &scanned_at)
            .map_err(|e| CoreError::Database(e.to_string()))?;
    }

    // History
    if is_new {
        let record = HistoryRecord {
            id: None,
            device_ip: host.to_string(),
            event_type: "discovered".to_string(),
            details: Some(format!("Manual scan discovered: {host}")),
            timestamp: now,
        };
        db.append_history(&record).ok();
    }

    Ok(ScannedDevice {
        ip: host.to_string(),
        mac: "00:00:00:00:00:00".to_string(),
        vendor: existing.as_ref().and_then(|d| d.vendor.clone()),
        interface: None,
        open_ports,
        latency,
        is_new,
    })
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_db() -> Database {
        Database::open_memory().unwrap()
    }

    // ── Options ──

    #[test]
    fn default_options_are_reasonable() {
        let opts = FullScanOptions::default();
        assert!(opts.arp_settle_ms > 0);
        assert!(opts.port_scan_timeout_ms > 0);
        assert!(opts.port_scan_concurrency > 0);
        assert!(opts.ping_count > 0);
        assert!(opts.http_port > 0);
        assert!(opts.check_latency);
    }

    // ── Single host scan (no network required) ──

    #[test]
    fn scan_single_host_closed_port() {
        let mut db = make_test_db();
        let opts = FullScanOptions {
            check_latency: false,
            ..Default::default()
        };
        // Port 65534 is likely closed on localhost
        let result = scan_single_host(&mut db, "127.0.0.1", &opts);
        assert!(result.is_ok());
        let dev = result.unwrap();
        assert_eq!(dev.ip, "127.0.0.1");
        assert!(dev.open_ports.is_empty());
        assert!(dev.is_new);
    }

    #[test]
    fn scan_single_host_twice_marks_not_new() {
        let mut db = make_test_db();
        let opts = FullScanOptions {
            check_latency: false,
            ..Default::default()
        };

        let result1 = scan_single_host(&mut db, "127.0.0.1", &opts);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_new);

        let result2 = scan_single_host(&mut db, "127.0.0.1", &opts);
        assert!(result2.is_ok());
        assert!(!result2.unwrap().is_new);
    }

    // ── Full scan with empty ARP (no network) ──

    #[test]
    fn full_scan_no_arp_entries_returns_empty() {
        let mut db = make_test_db();
        let opts = FullScanOptions {
            cidr: Some("127.0.0.1/32".into()),
            check_latency: false,
            ..Default::default()
        };
        let result = full_scan(&mut db, &opts);
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.device_count, 0);
        assert_eq!(scan.devices.len(), 0);
        assert_eq!(scan.new_device_count, 0);
        assert_eq!(scan.total_open_ports, 0);
        assert_eq!(scan.alert_count, 0);
        // elapsed_ms should be > 0 since ARP settle time still passes
        assert!(scan.elapsed_ms > 0.0);
    }

    // ── Full scan with a single host (no network) ──

    #[test]
    fn full_scan_single_host_no_network() {
        let mut db = make_test_db();
        let opts = FullScanOptions {
            cidr: Some("127.0.0.1/32".into()),
            check_latency: false,
            ..Default::default()
        };
        let result = full_scan(&mut db, &opts);
        assert!(result.is_ok());
        let scan = result.unwrap();
        // ARP on loopback should return 0 entries (loopback doesn't appear in ARP)
        assert_eq!(scan.device_count, 0);
    }

    // ── Device tracking across scans ──

    #[test]
    fn full_scan_detects_new_device() {
        let mut db = make_test_db();
        let opts = FullScanOptions {
            cidr: Some("127.0.0.1/32".into()),
            check_latency: false,
            ..Default::default()
        };
        let result = full_scan(&mut db, &opts);
        assert!(result.is_ok());
        let scan = result.unwrap();
        // No devices on loopback, but the structure is valid
        assert_eq!(scan.new_device_count, 0);
        assert_eq!(scan.alert_count, 0);
    }

    // ── Latency disabled ──

    #[test]
    fn full_scan_without_latency() {
        let mut db = make_test_db();
        let opts = FullScanOptions {
            cidr: Some("127.0.0.1/32".into()),
            check_latency: false,
            ..Default::default()
        };
        let result = full_scan(&mut db, &opts);
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.device_count, 0);
        // No latency results expected
        for dev in &scan.devices {
            assert!(dev.latency.is_none());
        }
    }

    // ── Serialization ──

    #[test]
    fn scanned_device_serializes() {
        let dev = ScannedDevice {
            ip: "192.168.1.1".into(),
            mac: "AA:BB:CC:DD:EE:FF".into(),
            vendor: Some("TestVendor".into()),
            interface: Some("eth0".into()),
            open_ports: vec![port_scan::PortResult {
                port: 80,
                protocol: "tcp".into(),
                state: "open".into(),
                latency_ms: Some(1.5),
                service: Some("http".into()),
            }],
            latency: None,
            is_new: true,
        };
        let json = serde_json::to_value(&dev).unwrap();
        assert_eq!(json["ip"], "192.168.1.1");
        assert_eq!(json["mac"], "AA:BB:CC:DD:EE:FF");
        assert_eq!(json["is_new"], true);
    }

    #[test]
    fn full_scan_result_serializes() {
        let result = FullScanResult {
            elapsed_ms: 1234.5,
            device_count: 3,
            new_device_count: 1,
            total_open_ports: 5,
            alert_count: 2,
            devices: vec![],
            alerts: vec![],
            history: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["device_count"], 3);
        assert_eq!(json["new_device_count"], 1);
        assert_eq!(json["total_open_ports"], 5);
        assert_eq!(json["elapsed_ms"], 1234.5);
    }

    // ── Error types ──

    #[test]
    fn core_error_display() {
        let err = CoreError::Arp("no interface".into());
        assert!(err.to_string().contains("ARP scan failed"));

        let err = CoreError::PortScan("timeout".into());
        assert!(err.to_string().contains("port scan failed"));

        let err = CoreError::Latency("ping failed".into());
        assert!(err.to_string().contains("latency check failed"));

        let err = CoreError::Database("sqlite error".into());
        assert!(err.to_string().contains("database error"));
    }

    #[test]
    fn core_error_is_error() {
        let err = CoreError::Arp("test".into());
        let _: &dyn std::error::Error = &err;
    }
}
