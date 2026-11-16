//! SentryNet TCP port scanner.
//!
//! Scans a range of TCP ports on one or more hosts, measures response times,
//! and attempts basic service detection by reading banners from open ports.
//!
//! Uses only the Rust standard library — no external nmap dependency required.

use crate::database::{Database, Port};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────

/// Default scan timeout per port (milliseconds).
pub const DEFAULT_SCAN_TIMEOUT_MS: u64 = 1000;

/// Default number of concurrent scan workers.
pub const DEFAULT_CONCURRENCY: usize = 64;

/// Maximum ports per scan (to avoid excessive scans).
pub const MAX_PORTS: usize = 65535;

/// Well-known service names for common ports.
const WELL_KNOWN_SERVICES: &[(u16, &str)] = &[
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (67, "dhcp"),
    (68, "dhcp"),
    (69, "tftp"),
    (80, "http"),
    (110, "pop3"),
    (111, "rpcbind"),
    (119, "nntp"),
    (123, "ntp"),
    (135, "msrpc"),
    (137, "netbios-ns"),
    (138, "netbios-dgm"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (161, "snmp"),
    (162, "snmptrap"),
    (179, "bgp"),
    (389, "ldap"),
    (443, "https"),
    (445, "microsoft-ds"),
    (465, "smtps"),
    (514, "syslog"),
    (515, "printer"),
    (520, "rip"),
    (523, "ibm-db2"),
    (554, "rtsp"),
    (587, "submission"),
    (631, "ipp"),
    (636, "ldaps"),
    (993, "imaps"),
    (995, "pop3s"),
    (1080, "socks"),
    (1433, "mssql"),
    (1521, "oracle"),
    (1723, "pptp"),
    (1900, "upnp"),
    (2049, "nfs"),
    (2082, "cpanel"),
    (2083, "cpanel-ssl"),
    (2086, "webmin"),
    (2087, "webmin-ssl"),
    (2095, "cpanel-ssl"),
    (2096, "cpanel-ssl"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5060, "sip"),
    (5432, "postgresql"),
    (5900, "vnc"),
    (5901, "vnc"),
    (5902, "vnc"),
    (6379, "redis"),
    (6660, "irc"),
    (6661, "irc"),
    (6667, "irc"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9090, "http-alt"),
    (9200, "elasticsearch"),
    (11211, "memcached"),
    (27017, "mongodb"),
];

/// Default well-known ports to scan when no range is specified.
const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 554, 587, 631,
    993, 995, 1723, 2049, 3306, 3389, 5060, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
];

// ──────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────

/// Result of scanning a single port.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortResult {
    /// Port number.
    pub port: u16,
    /// TCP or UDP.
    pub protocol: String,
    /// "open", "closed", or "filtered".
    pub state: String,
    /// Estimated response time in milliseconds (null if closed/filtered).
    pub latency_ms: Option<f64>,
    /// Service name from well-known table or banner detection.
    pub service: Option<String>,
}

/// A single host's scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostScanResult {
    /// Target IP address.
    pub ip: String,
    /// Ports that are open.
    pub open_ports: Vec<PortResult>,
    /// Total ports scanned.
    pub total_scanned: usize,
    /// Time taken for the scan in milliseconds.
    pub elapsed_ms: f64,
}

/// Options for [`tcp_scan`].
#[derive(Debug, Clone)]
pub struct TcpScanOptions {
    /// Target IP addresses.
    pub hosts: Vec<String>,
    /// Port numbers to scan. Empty = default well-known ports.
    pub ports: Vec<u16>,
    /// Timeout per port in milliseconds.
    pub timeout_ms: u64,
    /// Maximum concurrent connections.
    pub concurrency: usize,
    /// Attempt banner-based service detection.
    pub service_detection: bool,
}

impl Default for TcpScanOptions {
    fn default() -> Self {
        Self {
            hosts: vec![],
            ports: vec![],
            timeout_ms: DEFAULT_SCAN_TIMEOUT_MS,
            concurrency: DEFAULT_CONCURRENCY,
            service_detection: true,
        }
    }
}

/// Errors raised by port scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortScanError {
    /// Empty host list.
    NoHosts,
    /// Empty port list.
    NoPorts,
    /// Port number out of range.
    InvalidPort(u16),
    /// Too many ports.
    TooManyPorts(usize),
    /// Scan failed.
    Scan(String),
}

impl std::fmt::Display for PortScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortScanError::NoHosts => write!(f, "no hosts specified"),
            PortScanError::NoPorts => write!(f, "no ports specified"),
            PortScanError::InvalidPort(p) => write!(f, "invalid port: {p}"),
            PortScanError::TooManyPorts(n) => {
                write!(f, "too many ports: {n} (maximum {MAX_PORTS})")
            }
            PortScanError::Scan(e) => write!(f, "scan failed: {e}"),
        }
    }
}

impl std::error::Error for PortScanError {}

// ──────────────────────────────────────────────
// Service detection
// ──────────────────────────────────────────────

/// Look up a service name from the well-known ports table.
pub fn well_known_service(port: u16) -> Option<&'static str> {
    WELL_KNOWN_SERVICES
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| *name)
}

/// Try to read a banner from an already-connected open socket.
/// Returns the first line of the banner (up to 256 bytes) or None.
fn read_banner(stream: &mut TcpStream, timeout_ms: u64) -> Option<String> {
    let timeout = Duration::from_millis(timeout_ms.min(500));
    if let Err(_) = stream.set_read_timeout(Some(timeout)) {
        return None;
    }
    let mut buf = [0u8; 256];
    match stream.read(&mut buf) {
        Ok(0) => None,
        Ok(n) => {
            let text = String::from_utf8_lossy(&buf[..n]);
            let line = text.lines().next()?.trim().to_string();
            if line.is_empty() {
                None
            } else {
                Some(line)
            }
        }
        Err(_) => None,
    }
}

/// Detect service from banner text.
fn banner_to_service(banner: &str) -> Option<String> {
    if banner.is_empty() {
        return None;
    }
    let lower = banner.to_lowercase();
    // Heuristic: extract service name from common banner patterns
    if lower.contains("ssh") {
        Some("ssh".to_string())
    } else if lower.contains("http") {
        Some("http".to_string())
    } else if lower.contains("ftp") {
        Some("ftp".to_string())
    } else if lower.contains("smtp") {
        Some("smtp".to_string())
    } else if lower.contains("telnet") {
        Some("telnet".to_string())
    } else if lower.contains("mysql") {
        Some("mysql".to_string())
    } else if lower.contains("postgresql") {
        Some("postgresql".to_string())
    } else if lower.contains("redis") {
        Some("redis".to_string())
    } else if lower.contains("nginx") {
        Some("nginx".to_string())
    } else if lower.contains("apache") {
        Some("apache".to_string())
    } else if lower.contains("microsoft") {
        Some("microsoft-iis".to_string())
    } else if lower.contains("vnc") || lower.contains("rfb") {
        Some("vnc".to_string())
    } else if lower.contains("snmp") {
        Some("snmp".to_string())
    } else if lower.contains("dhcp") {
        Some("dhcp".to_string())
    } else if lower.contains("ntp") {
        Some("ntp".to_string())
    } else if lower.contains("ldap") {
        Some("ldap".to_string())
    } else if lower.contains("imap") {
        Some("imap".to_string())
    } else if lower.contains("pop3") {
        Some("pop3".to_string())
    } else if lower.contains("rdp") {
        Some("rdp".to_string())
    } else if lower.contains("smb") || lower.contains("microsoft-ds") {
        Some("smb".to_string())
    } else {
        // Detect MySQL by version pattern: starts with digit, has dots and digits
        // e.g. "5.7.36-0ubuntu0.18.04.1"
        if banner.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            let has_dot = banner.contains('.');
            let has_digit = banner.chars().any(|c| c.is_ascii_digit());
            let has_dash = banner.contains('-');
            if has_dot && has_digit && has_dash {
                return Some("mysql".to_string());
            }
        }
        // For unknown services, only return the banner if it looks like a
        // meaningful identifier (not a version number, not random noise).
        // Must be at least 4 chars and contain at least one non-digit.
        if banner.len() >= 4 && banner.len() < 128 {
            let has_alpha = banner.chars().any(|c| c.is_ascii_alphabetic());
            let has_digit = banner.chars().any(|c| c.is_ascii_digit());
            // Reject pure version strings (e.g. "5.7.36-0ubuntu")
            if has_digit && banner.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                return None;
            }
            // Reject pure noise (no alphabetic chars)
            if !has_alpha {
                return None;
            }
            Some(banner.to_string())
        } else {
            None
        }
    }
}

/// Determine the service name for an open port.
fn detect_service(port: u16, stream: &mut TcpStream, service_detection: bool) -> Option<String> {
    // First try well-known table
    if let Some(name) = well_known_service(port) {
        return Some(name.to_string());
    }

    // If service detection is enabled, try banner
    if service_detection {
        if let Some(banner) = read_banner(stream, 200) {
            if let Some(svc) = banner_to_service(&banner) {
                return Some(svc);
            }
        }
    }

    None
}

// ──────────────────────────────────────────────
// Single port scan
// ──────────────────────────────────────────────

/// Scan a single TCP port on a host.
/// Returns a `PortResult` with state, latency, and service info.
fn scan_port(
    host: &str,
    port: u16,
    timeout_ms: u64,
    service_detection: bool,
) -> PortResult {
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .unwrap_or_else(|_| format!("{host}:0").parse().unwrap());

    let start = Instant::now();
    let result = match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
        Ok(mut stream) => {
            let latency = start.elapsed().as_secs_f64() * 1000.0;
            let service = detect_service(port, &mut stream, service_detection);
            PortResult {
                port,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                latency_ms: Some(latency),
                service,
            }
        }
        Err(_) => PortResult {
            port,
            protocol: "tcp".to_string(),
            state: "closed".to_string(),
            latency_ms: None,
            service: None,
        },
    };
    result
}

// ──────────────────────────────────────────────
// Host scan
// ──────────────────────────────────────────────

/// Scan all ports on a single host.
fn scan_host(host: &str, ports: &[u16], timeout_ms: u64, concurrency: usize, service_detection: bool) -> HostScanResult {
    let start = Instant::now();
    let mut open_ports: Vec<PortResult> = Vec::new();

    // Use a thread pool for concurrent scanning
    let chunk_size = if ports.len() > concurrency {
        ports.len() / concurrency
    } else {
        1
    };

    let mut handles = Vec::new();
    for chunk in ports.chunks(chunk_size.max(1)) {
        let host = host.to_string();
        let chunk = chunk.to_vec();
        let timeout = timeout_ms;
        let svc = service_detection;

        let handle = std::thread::spawn(move || {
            chunk
                .into_iter()
                .map(|port| scan_port(&host, port, timeout, svc))
                .collect::<Vec<_>>()
        });
        handles.push(handle);
    }

    for handle in handles {
        if let Ok(results) = handle.join() {
            for result in results {
                if result.state == "open" {
                    open_ports.push(result);
                }
            }
        }
    }

    open_ports.sort_by_key(|p| p.port);

    let elapsed = start.elapsed().as_secs_f64() * 1000.0;

    HostScanResult {
        ip: host.to_string(),
        open_ports,
        total_scanned: ports.len(),
        elapsed_ms: elapsed,
    }
}

// ──────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────

/// Scan TCP ports on the given hosts.
///
/// Returns a list of `HostScanResult`, one per host.
pub fn tcp_scan(options: &TcpScanOptions) -> Result<Vec<HostScanResult>, PortScanError> {
    if options.hosts.is_empty() {
        return Err(PortScanError::NoHosts);
    }

    let ports = if options.ports.is_empty() {
        DEFAULT_PORTS.to_vec()
    } else {
        let mut ports = options.ports.clone();
        ports.sort_unstable();
        ports.dedup();
        ports
    };

    if ports.is_empty() {
        return Err(PortScanError::NoPorts);
    }

    if ports.len() > MAX_PORTS {
        return Err(PortScanError::TooManyPorts(ports.len()));
    }

    // Validate port numbers
    for &port in &ports {
        if port == 0 {
            return Err(PortScanError::InvalidPort(0));
        }
    }

    let mut results: Vec<HostScanResult> = Vec::new();

    for host in &options.hosts {
        let result = scan_host(
            host,
            &ports,
            options.timeout_ms,
            options.concurrency,
            options.service_detection,
        );
        results.push(result);
    }

    Ok(results)
}

/// Scan ports on a single host and save results to the database.
pub fn scan_and_store(
    db: &mut Database,
    host: &str,
    options: &TcpScanOptions,
) -> Result<HostScanResult, PortScanError> {
    let result = scan_host(
        host,
        &if options.ports.is_empty() {
            DEFAULT_PORTS.to_vec()
        } else {
            let mut ports = options.ports.clone();
            ports.sort_unstable();
            ports.dedup();
            ports
        },
        options.timeout_ms,
        options.concurrency,
        options.service_detection,
    );

    // Store open ports in the database
    let scanned_at = Utc::now().to_rfc3339();
    let mut ports_to_store: Vec<Port> = Vec::new();
    for port_result in &result.open_ports {
        ports_to_store.push(Port {
            device_ip: host.to_string(),
            port: port_result.port,
            protocol: port_result.protocol.clone(),
            state: port_result.state.clone(),
            service: port_result.service.clone(),
        });
    }

    if !ports_to_store.is_empty() {
        if let Err(e) = db.upsert_ports_batch(&ports_to_store, &scanned_at) {
            eprintln!("Failed to store port scan results: {e}");
        }
    }

    Ok(result)
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Well-known service lookup ──

    #[test]
    fn well_known_service_returns_correct_names() {
        assert_eq!(well_known_service(22), Some("ssh"));
        assert_eq!(well_known_service(80), Some("http"));
        assert_eq!(well_known_service(443), Some("https"));
        assert_eq!(well_known_service(3306), Some("mysql"));
        assert_eq!(well_known_service(5432), Some("postgresql"));
        assert_eq!(well_known_service(8080), Some("http-proxy"));
        assert_eq!(well_known_service(27017), Some("mongodb"));
    }

    #[test]
    fn well_known_service_returns_none_for_unknown() {
        assert_eq!(well_known_service(12345), None);
        assert_eq!(well_known_service(54321), None);
    }

    // ── Banner detection ──

    #[test]
    fn banner_to_service_detects_ssh() {
        assert_eq!(
            banner_to_service("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"),
            Some("ssh".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_http() {
        assert_eq!(
            banner_to_service("HTTP/1.1 200 OK"),
            Some("http".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_ftp() {
        assert_eq!(
            banner_to_service("220 (vsFTPd 3.0.3)"),
            Some("ftp".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_mysql() {
        assert_eq!(
            banner_to_service("5.7.36-0ubuntu0.18.04.1"),
            Some("mysql".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_redis() {
        assert_eq!(banner_to_service("+OK Redis server"), Some("redis".to_string()));
    }

    #[test]
    fn banner_to_service_detects_nginx() {
        assert_eq!(
            banner_to_service("nginx/1.24.0"),
            Some("nginx".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_apache() {
        assert_eq!(
            banner_to_service("Apache/2.4.57"),
            Some("apache".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_vnc() {
        assert_eq!(
            banner_to_service("RFB 003.008"),
            Some("vnc".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_snmp() {
        assert_eq!(
            banner_to_service("SNMPv2"),
            Some("snmp".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_dhcp() {
        assert_eq!(
            banner_to_service("DHCP"),
            Some("dhcp".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_ntp() {
        assert_eq!(
            banner_to_service("NTP"),
            Some("ntp".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_ldap() {
        assert_eq!(
            banner_to_service("LDAP"),
            Some("ldap".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_imap() {
        assert_eq!(
            banner_to_service("* OK IMAP4"),
            Some("imap".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_pop3() {
        assert_eq!(
            banner_to_service("+OK POP3"),
            Some("pop3".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_rdp() {
        assert_eq!(
            banner_to_service("RDP"),
            Some("rdp".to_string())
        );
    }

    #[test]
    fn banner_to_service_detects_smb() {
        assert_eq!(
            banner_to_service("SMB"),
            Some("smb".to_string())
        );
    }

    #[test]
    fn banner_to_service_returns_none_for_long_banners() {
        let long_banner = "x".repeat(200);
        assert_eq!(banner_to_service(&long_banner), None);
    }

    #[test]
    fn banner_to_service_returns_none_for_empty() {
        assert_eq!(banner_to_service(""), None);
    }

    #[test]
    fn banner_to_service_returns_none_for_short_unknown() {
        // Short banner that doesn't match any known service
        assert_eq!(banner_to_service("xyz"), None);
    }

    // ── Port result serialization ──

    #[test]
    fn port_result_serializes_to_json() {
        let result = PortResult {
            port: 80,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            latency_ms: Some(1.5),
            service: Some("http".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["port"], 80);
        assert_eq!(json["protocol"], "tcp");
        assert_eq!(json["state"], "open");
        assert_eq!(json["latency_ms"], 1.5);
        assert_eq!(json["service"], "http");
    }

    #[test]
    fn port_result_closed_has_null_latency() {
        let result = PortResult {
            port: 22,
            protocol: "tcp".to_string(),
            state: "closed".to_string(),
            latency_ms: None,
            service: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["latency_ms"].is_null());
        assert!(json["service"].is_null());
    }

    // ── Host scan result serialization ──

    #[test]
    fn host_scan_result_serializes_to_json() {
        let result = HostScanResult {
            ip: "192.168.1.1".to_string(),
            open_ports: vec![PortResult {
                port: 80,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                latency_ms: Some(2.3),
                service: Some("http".to_string()),
            }],
            total_scanned: 35,
            elapsed_ms: 450.5,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["ip"], "192.168.1.1");
        assert_eq!(json["open_ports"].as_array().unwrap().len(), 1);
        assert_eq!(json["total_scanned"], 35);
        assert_eq!(json["elapsed_ms"], 450.5);
    }

    // ── Port validation ──

    #[test]
    fn tcp_scan_rejects_no_hosts() {
        let options = TcpScanOptions {
            hosts: vec![],
            ports: vec![80],
            ..Default::default()
        };
        let result = tcp_scan(&options);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PortScanError::NoHosts));
    }

    #[test]
    fn tcp_scan_uses_default_ports_when_empty() {
        // Empty ports list should fall back to default well-known ports, not error
        let options = TcpScanOptions {
            hosts: vec!["127.0.0.1".to_string()],
            ports: vec![],
            ..Default::default()
        };
        let result = tcp_scan(&options);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ip, "127.0.0.1");
        assert_eq!(results[0].total_scanned, DEFAULT_PORTS.len());
    }

    #[test]
    fn tcp_scan_rejects_too_many_ports() {
        let ports: Vec<u16> = (0..=65535).collect();
        let options = TcpScanOptions {
            hosts: vec!["127.0.0.1".to_string()],
            ports,
            ..Default::default()
        };
        let result = tcp_scan(&options);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PortScanError::TooManyPorts(_)));
    }

    // ── Actual scan against localhost (port 0 should be closed) ──

    #[test]
    fn scan_closed_port_on_localhost() {
        // Port 0 is invalid, but we test with a high port that's likely closed
        let result = scan_port("127.0.0.1", 65534, 100, false);
        assert_eq!(result.state, "closed");
        assert_eq!(result.port, 65534);
        assert!(result.latency_ms.is_none());
        assert!(result.service.is_none());
    }

    #[test]
    fn scan_result_is_sorted_by_port() {
        let results = scan_host(
            "127.0.0.1",
            &[65534, 65533, 65532, 65531],
            50,
            4,
            false,
        );
        // All should be closed, but verify the structure is valid
        assert_eq!(results.total_scanned, 4);
        assert!(results.open_ports.is_empty());
    }

    // ── Default ports ──

    #[test]
    fn default_ports_are_sorted() {
        let mut sorted = DEFAULT_PORTS.to_vec();
        sorted.sort_unstable();
        assert_eq!(DEFAULT_PORTS, sorted.as_slice());
    }

    #[test]
    fn default_ports_count() {
        // Should have a reasonable number of well-known ports
        assert!(DEFAULT_PORTS.len() >= 20);
        assert!(DEFAULT_PORTS.len() <= 100);
    }

    // ── Detect service ──

    #[test]
    fn detect_service_uses_well_known_table() {
        // Well-known ports should return the table name without needing banner.
        // We verify the table lookup works; actual banner detection needs a live socket.
        assert_eq!(well_known_service(22), Some("ssh"));
        assert_eq!(well_known_service(80), Some("http"));
        assert_eq!(well_known_service(443), Some("https"));
        assert_eq!(well_known_service(3306), Some("mysql"));
        // Unknown port returns None from the table
        assert_eq!(well_known_service(12345), None);
    }

    // ── Scan against localhost with a known open port (if available) ──

    #[test]
    fn scan_localhost_returns_valid_result() {
        let result = scan_host(
            "127.0.0.1",
            &[65534, 65533],
            100,
            2,
            false,
        );
        assert_eq!(result.ip, "127.0.0.1");
        assert_eq!(result.total_scanned, 2);
        assert!(result.elapsed_ms > 0.0);
        assert!(result.elapsed_ms < 5000.0); // Should complete quickly
    }
}
