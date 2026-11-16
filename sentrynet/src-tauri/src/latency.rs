//! SentryNet latency checker.
//!
//! Measures network latency to hosts using:
//! - ICMP ping (via system `ping` command — no raw-socket privileges needed)
//! - HTTP HEAD requests (pure std::net::TcpStream, no external HTTP library)
//!
//! Results are returned as structured latency samples with per-sample timing.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────

/// Default ICMP ping timeout in milliseconds.
pub const DEFAULT_PING_TIMEOUT_MS: u64 = 3000;

/// Default number of ICMP ping probes.
pub const DEFAULT_PING_COUNT: u32 = 4;

/// Default HTTP HEAD timeout in milliseconds.
pub const DEFAULT_HTTP_TIMEOUT_MS: u64 = 3000;

/// Default HTTP HEAD path.
pub const DEFAULT_HTTP_PATH: &str = "/";

/// Default HTTP HEAD host header.
pub const DEFAULT_HTTP_HOST: &str = "localhost";

/// Default HTTP HEAD user-agent.
const DEFAULT_HTTP_USER_AGENT: &str = "SentryNet/1.0";

/// Maximum ICMP ping probes (to avoid runaway processes).
const MAX_PING_COUNT: u32 = 20;

/// Maximum HTTP body to read (bytes) — HEAD should be tiny, but guard anyway.
const MAX_HTTP_BODY: usize = 4096;

// ──────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────

/// A single latency sample from one measurement method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencySample {
    /// Target host (IP or hostname).
    pub host: String,
    /// Measurement method: "icmp" or "http".
    pub method: String,
    /// Response time in milliseconds. `None` if the probe failed.
    pub latency_ms: Option<f64>,
    /// Whether the probe succeeded.
    pub success: bool,
    /// Extra details (e.g. HTTP status code, ICMP TTL).
    pub details: Option<String>,
    /// Timestamp of the measurement (ISO 8601 UTC).
    pub timestamp: String,
}

/// Result of a full latency check on a single host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostLatencyResult {
    /// Target host.
    pub host: String,
    /// All samples collected.
    pub samples: Vec<LatencySample>,
    /// Average latency across successful samples (ms), or `None` if all failed.
    pub avg_latency_ms: Option<f64>,
    /// Minimum latency across successful samples (ms), or `None`.
    pub min_latency_ms: Option<f64>,
    /// Maximum latency across successful samples (ms), or `None`.
    pub max_latency_ms: Option<f64>,
    /// Packet loss percentage (0.0–100.0).
    pub packet_loss: f64,
    /// Total time spent measuring (ms).
    pub elapsed_ms: f64,
}

/// Options for [`ping_host`].
#[derive(Debug, Clone)]
pub struct PingOptions {
    /// Target host (IP or hostname).
    pub host: String,
    /// Number of probes (default 4).
    pub count: u32,
    /// Per-probe timeout in milliseconds (default 3000).
    pub timeout_ms: u64,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            host: String::new(),
            count: DEFAULT_PING_COUNT,
            timeout_ms: DEFAULT_PING_TIMEOUT_MS,
        }
    }
}

/// Options for [`http_head`].
#[derive(Debug, Clone)]
pub struct HttpHeadOptions {
    /// Target host (IP or hostname).
    pub host: String,
    /// TCP port (default 80).
    pub port: u16,
    /// Use HTTPS (TLS). Requires the `native-tls` feature on the HTTP client.
    /// Since we have no external deps, HTTPS is not supported — always HTTP.
    pub use_https: bool,
    /// HTTP path (default "/").
    pub path: String,
    /// HTTP host header (default "localhost").
    pub host_header: String,
    /// Timeout in milliseconds (default 3000).
    pub timeout_ms: u64,
}

impl Default for HttpHeadOptions {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 80,
            use_https: false,
            path: DEFAULT_HTTP_PATH.to_string(),
            host_header: DEFAULT_HTTP_HOST.to_string(),
            timeout_ms: DEFAULT_HTTP_TIMEOUT_MS,
        }
    }
}

/// Options for a full latency check (both ICMP and HTTP).
#[derive(Debug, Clone)]
pub struct LatencyCheckOptions {
    /// Target hosts.
    pub hosts: Vec<String>,
    /// ICMP ping options.
    pub ping: PingOptions,
    /// HTTP HEAD options.
    pub http: HttpHeadOptions,
}

impl Default for LatencyCheckOptions {
    fn default() -> Self {
        Self {
            hosts: vec![],
            ping: PingOptions::default(),
            http: HttpHeadOptions::default(),
        }
    }
}

/// Errors raised by latency checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatencyError {
    /// Empty host list.
    NoHosts,
    /// Invalid host string.
    InvalidHost(String),
    /// ICMP ping failed.
    Ping(String),
    /// HTTP HEAD failed.
    Http(String),
}

impl std::fmt::Display for LatencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LatencyError::NoHosts => write!(f, "no hosts specified"),
            LatencyError::InvalidHost(h) => write!(f, "invalid host: {h}"),
            LatencyError::Ping(e) => write!(f, "ping failed: {e}"),
            LatencyError::Http(e) => write!(f, "HTTP HEAD failed: {e}"),
        }
    }
}

impl std::error::Error for LatencyError {}

// ──────────────────────────────────────────────
// Platform detection
// ──────────────────────────────────────────────

/// Check if we're on Windows (for ping flag differences).
fn is_windows() -> bool {
    cfg!(windows)
}

// ──────────────────────────────────────────────
// ICMP ping (via system `ping` command)
// ──────────────────────────────────────────────

/// Parse a single latency value from a ping reply line.
///
/// Linux format: `time=1.23 ms`
/// macOS/BSD format: `time=1.234 ms`
/// Windows format: `time=<1> ms` or `time=5ms`
fn parse_ping_latency(line: &str) -> Option<f64> {
    // Try "time=" first (Linux/macOS)
    let time_part = if let Some(p) = line.split("time=").nth(1) {
        p
    } else if let Some(p) = line.split("time<").nth(1) {
        // Windows: time<1> ms
        p
    } else {
        return None;
    };
    let time_str: String = time_part
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
        .collect();
    // Replace comma with dot (some locales use comma as decimal separator)
    let time_str = time_str.replace(',', ".");
    time_str.parse::<f64>().ok()
}

/// Parse the TTL value from a ping reply line.
/// Format: `ttl=64` or `TTL=64`
fn parse_ping_ttl(line: &str) -> Option<u16> {
    let ttl_part = if let Some(p) = line.split("ttl=").nth(1) {
        p
    } else if let Some(p) = line.split("TTL=").nth(1) {
        p
    } else {
        return None;
    };
    let ttl_str: String = ttl_part
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    ttl_str.parse::<u16>().ok()
}

/// Run an ICMP ping to the given host.
///
/// Uses the system `ping` command with platform-appropriate flags.
/// Returns a list of latency samples.
pub fn ping_host(options: &PingOptions) -> Result<Vec<LatencySample>, LatencyError> {
    if options.host.is_empty() {
        return Err(LatencyError::InvalidHost("empty host".to_string()));
    }

    let count = options.count.min(MAX_PING_COUNT);
    let timeout_secs = options.timeout_ms as f64 / 1000.0;
    let timestamp = Utc::now().to_rfc3339();

    // Build the ping command with platform-specific flags
    // Convert to owned Strings first to avoid lifetime issues
    let (exe, args): (&str, Vec<String>) = if is_windows() {
        (
            "ping",
            vec![
                "-n".to_string(),
                count.to_string(),
                "-w".to_string(),
                options.timeout_ms.to_string(),
                options.host.clone(),
            ],
        )
    } else {
        (
            "ping",
            vec![
                "-c".to_string(),
                count.to_string(),
                "-W".to_string(),
                timeout_secs.to_string(),
                options.host.clone(),
            ],
        )
    };

    let output = match Command::new(exe).args(&args).output() {
        Ok(o) => o,
        Err(e) => {
            let samples = vec![LatencySample {
                host: options.host.clone(),
                method: "icmp".to_string(),
                latency_ms: None,
                success: false,
                details: Some(format!("command failed: {e}")),
                timestamp: timestamp.clone(),
            }];
            return Ok(samples);
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Parse individual ping replies from stdout
    let mut samples: Vec<LatencySample> = Vec::new();
    let mut ttl: Option<u16> = None;

    for line in stdout.lines() {
        if let Some(latency) = parse_ping_latency(line) {
            let sample = LatencySample {
                host: options.host.clone(),
                method: "icmp".to_string(),
                latency_ms: Some(latency),
                success: true,
                details: ttl.map(|t| format!("ttl={t}")),
                timestamp: timestamp.clone(),
            };
            samples.push(sample);
        }
        // Capture TTL from the first reply line
        if ttl.is_none() {
            ttl = parse_ping_ttl(line);
        }
    }

    // If no samples were parsed from stdout, check stderr for errors
    if samples.is_empty() {
        let detail = if stderr.contains("Name or service not known")
            || stderr.contains("unknown host")
            || stderr.contains("No route to host")
            || stderr.contains("Network is unreachable")
        {
            Some(stderr.trim().to_string())
        } else if output.status.code().map_or(false, |c| c != 0) {
            Some(format!("ping exited with code {}", output.status.code().unwrap_or(-1)))
        } else {
            Some("no ping replies received".to_string())
        };

        for _ in 0..count {
            samples.push(LatencySample {
                host: options.host.clone(),
                method: "icmp".to_string(),
                latency_ms: None,
                success: false,
                details: detail.clone(),
                timestamp: timestamp.clone(),
            });
        }
    }

    Ok(samples)
}

// ──────────────────────────────────────────────
// HTTP HEAD request (pure std::net::TcpStream)
// ──────────────────────────────────────────────

/// Build a minimal HTTP/1.1 HEAD request string.
fn build_http_head_request(
    host: &str,
    port: u16,
    path: &str,
    host_header: &str,
) -> String {
    let port_suffix = if (port == 80 && !host.contains(':')) || (port == 443 && !host.contains(':')) {
        String::new()
    } else {
        format!(":{port}")
    };
    format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host_header}{port_suffix}\r\n\
         User-Agent: {DEFAULT_HTTP_USER_AGENT}\r\n\
         Connection: close\r\n\
         Accept: */*\r\n\
         \r\n"
    )
}

/// Send an HTTP HEAD request and parse the response.
///
/// Returns the status code and response time in milliseconds.
pub fn http_head(options: &HttpHeadOptions) -> Result<LatencySample, LatencyError> {
    if options.host.is_empty() {
        return Err(LatencyError::InvalidHost("empty host".to_string()));
    }

    // HTTPS is not supported without a TLS library (no external deps).
    if options.use_https {
        return Err(LatencyError::Http(
            "HTTPS not supported without a TLS library; use HTTP instead".to_string(),
        ));
    }

    let addr: SocketAddr = SocketAddrV4::new(
        options.host.parse().map_err(|_| {
            LatencyError::Http(format!("invalid host IP: {}", options.host))
        })?,
        options.port,
    )
    .into();

    let request = build_http_head_request(
        &options.host,
        options.port,
        &options.path,
        &options.host_header,
    );

    let timeout = Duration::from_millis(options.timeout_ms);
    let timestamp = Utc::now().to_rfc3339();

    let start = Instant::now();
    let result = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut stream) => {
            let connect_latency = start.elapsed().as_secs_f64() * 1000.0;

            // Set write timeout
            if stream.set_write_timeout(Some(timeout)).is_err() {
                return Ok(LatencySample {
                    host: options.host.clone(),
                    method: "http".to_string(),
                    latency_ms: None,
                    success: false,
                    details: Some("failed to set write timeout".to_string()),
                    timestamp: timestamp.clone(),
                });
            }

            // Set read timeout
            if stream.set_read_timeout(Some(timeout)).is_err() {
                return Ok(LatencySample {
                    host: options.host.clone(),
                    method: "http".to_string(),
                    latency_ms: None,
                    success: false,
                    details: Some("failed to set read timeout".to_string()),
                    timestamp: timestamp.clone(),
                });
            }

            // Send the request
            if stream.write_all(request.as_bytes()).is_err() {
                return Ok(LatencySample {
                    host: options.host.clone(),
                    method: "http".to_string(),
                    latency_ms: Some(connect_latency),
                    success: false,
                    details: Some("write failed".to_string()),
                    timestamp: timestamp.clone(),
                });
            }

            // Read response
            let mut response_buf = Vec::with_capacity(MAX_HTTP_BODY);
            let mut buf = [0u8; 512];

            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        response_buf.extend_from_slice(&buf[..n]);
                        if response_buf.len() >= MAX_HTTP_BODY {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            let total_latency = start.elapsed().as_secs_f64() * 1000.0;

            // Parse HTTP status line: "HTTP/1.1 200 OK"
            let response_str = String::from_utf8_lossy(&response_buf);
            let status_code = response_str
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok());

            let status_text = status_code.map(|c| format!("HTTP {c}"));

            Ok(LatencySample {
                host: options.host.clone(),
                method: "http".to_string(),
                latency_ms: Some(total_latency),
                success: status_code.map_or(false, |c| c >= 200 && c < 400),
                details: status_text,
                timestamp: timestamp.clone(),
            })
        }
        Err(e) => Ok(LatencySample {
            host: options.host.clone(),
            method: "http".to_string(),
            latency_ms: None,
            success: false,
            details: Some(format!("connection failed: {e}")),
            timestamp: timestamp.clone(),
        }),
    };

    result
}

// ──────────────────────────────────────────────
// Full latency check (combines ICMP + HTTP)
// ──────────────────────────────────────────────

/// Check latency to a single host using both ICMP ping and HTTP HEAD.
///
/// Returns a `HostLatencyResult` with all samples and aggregate statistics.
fn check_host_latency(host: &str, ping_opts: &PingOptions, http_opts: &HttpHeadOptions) -> HostLatencyResult {
    let overall_start = Instant::now();
    let mut all_samples: Vec<LatencySample> = Vec::new();

    // ICMP ping
    let ping_samples = ping_host(ping_opts);
    if let Ok(samples) = ping_samples {
        all_samples.extend(samples);
    } else {
        // Record a failed sample
        all_samples.push(LatencySample {
            host: host.to_string(),
            method: "icmp".to_string(),
            latency_ms: None,
            success: false,
            details: Some(ping_opts_err_msg(&ping_samples)),
            timestamp: Utc::now().to_rfc3339(),
        });
    }

    // HTTP HEAD
    let http_sample = http_head(http_opts);
    match http_sample {
        Ok(sample) => all_samples.push(sample),
        Err(e) => {
            all_samples.push(LatencySample {
                host: host.to_string(),
                method: "http".to_string(),
                latency_ms: None,
                success: false,
                details: Some(e.to_string()),
                timestamp: Utc::now().to_rfc3339(),
            });
        }
    }

    // Compute aggregate statistics
    let successful: Vec<f64> = all_samples
        .iter()
        .filter(|s| s.success && s.latency_ms.is_some())
        .filter_map(|s| s.latency_ms)
        .collect();

    let (avg_latency, min_latency, max_latency, packet_loss) = if successful.is_empty() {
        (None, None, None, 100.0)
    } else {
        let sum: f64 = successful.iter().sum();
        let avg_val = sum / successful.len() as f64;
        let min_val = successful.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_val = successful.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let total = all_samples.len();
        let failed = total - successful.len();
        let loss = (failed as f64 / total as f64) * 100.0;
        (Some(avg_val), Some(min_val), Some(max_val), loss)
    };

    let elapsed = overall_start.elapsed().as_secs_f64() * 1000.0;

    HostLatencyResult {
        host: host.to_string(),
        samples: all_samples,
        avg_latency_ms: avg_latency,
        min_latency_ms: min_latency,
        max_latency_ms: max_latency,
        packet_loss,
        elapsed_ms: elapsed,
    }
}

/// Extract a human-readable error message from a ping result.
fn ping_opts_err_msg(result: &Result<Vec<LatencySample>, LatencyError>) -> String {
    match result {
        Err(e) => e.to_string(),
        Ok(samples) => {
            if samples.is_empty() {
                "no ping replies".to_string()
            } else {
                format!(
                    "{} of {} probes failed",
                    samples.iter().filter(|s| !s.success).count(),
                    samples.len()
                )
            }
        }
    }
}

/// Check latency to multiple hosts.
///
/// Returns a list of `HostLatencyResult`, one per host.
pub fn check_latency(options: &LatencyCheckOptions) -> Result<Vec<HostLatencyResult>, LatencyError> {
    if options.hosts.is_empty() {
        return Err(LatencyError::NoHosts);
    }

    let mut results: Vec<HostLatencyResult> = Vec::new();

    for host in &options.hosts {
        let result = check_host_latency(host, &options.ping, &options.http);
        results.push(result);
    }

    Ok(results)
}

// ──────────────────────────────────────────────
// Convenience functions
// ──────────────────────────────────────────────

/// Quick ICMP ping to a single host (default options).
pub fn ping(host: &str) -> Result<Vec<LatencySample>, LatencyError> {
    ping_host(&PingOptions {
        host: host.to_string(),
        ..PingOptions::default()
    })
}

/// Quick HTTP HEAD to a single host (default options).
pub fn http_check(host: &str) -> Result<LatencySample, LatencyError> {
    http_head(&HttpHeadOptions {
        host: host.to_string(),
        ..HttpHeadOptions::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ping_latency_linux() {
        assert_eq!(
            parse_ping_latency("64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms"),
            Some(1.23)
        );
        assert_eq!(
            parse_ping_latency("64 bytes from 10.0.0.1: icmp_seq=2 ttl=128 time=0.045 ms"),
            Some(0.045)
        );
    }

    #[test]
    fn test_parse_ping_latency_windows() {
        assert_eq!(
            parse_ping_latency("Reply from 192.168.1.1: bytes=32 time<1> ms TTL=64"),
            Some(1.0)
        );
        assert_eq!(
            parse_ping_latency("Reply from 192.168.1.1: bytes=32 time=5ms TTL=64"),
            Some(5.0)
        );
    }

    #[test]
    fn test_parse_ping_latency_no_match() {
        assert_eq!(
            parse_ping_latency("Pinging 192.168.1.1 with 32 bytes of data:"),
            None
        );
        assert_eq!(
            parse_ping_latency("--- 192.168.1.1 ping statistics ---"),
            None
        );
        assert_eq!(parse_ping_latency(""), None);
    }

    #[test]
    fn test_parse_ping_ttl() {
        assert_eq!(
            parse_ping_ttl("64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms"),
            Some(64)
        );
        assert_eq!(
            parse_ping_ttl("Reply from 192.168.1.1: bytes=32 time<1> ms TTL=128"),
            Some(128)
        );
        assert_eq!(parse_ping_ttl("no ttl here"), None);
    }

    #[test]
    fn test_build_http_head_request() {
        let req = build_http_head_request("192.168.1.1", 80, "/", "192.168.1.1");
        assert!(req.contains("HEAD / HTTP/1.1"));
        assert!(req.contains("Host: 192.168.1.1"));
        assert!(req.contains("User-Agent: SentryNet/1.0"));
        assert!(req.contains("Connection: close"));
    }

    #[test]
    fn test_build_http_head_request_with_port() {
        let req = build_http_head_request("192.168.1.1", 8080, "/api", "192.168.1.1");
        assert!(req.contains("HEAD /api HTTP/1.1"));
        assert!(req.contains("Host: 192.168.1.1:8080"));
    }

    #[test]
    fn test_build_http_head_request_with_path() {
        let req = build_http_head_request("example.com", 443, "/health", "example.com");
        assert!(req.contains("HEAD /health HTTP/1.1"));
    }

    #[test]
    fn test_ping_host_empty_host() {
        let result = ping_host(&PingOptions {
            host: String::new(),
            ..PingOptions::default()
        });
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            LatencyError::InvalidHost("empty host".to_string())
        );
    }

    #[test]
    fn test_http_head_empty_host() {
        let result = http_head(&HttpHeadOptions {
            host: String::new(),
            ..HttpHeadOptions::default()
        });
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            LatencyError::InvalidHost("empty host".to_string())
        );
    }

    #[test]
    fn test_http_head_https_not_supported() {
        let result = http_head(&HttpHeadOptions {
            host: "example.com".to_string(),
            use_https: true,
            ..HttpHeadOptions::default()
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LatencyError::Http(_)));
    }

    #[test]
    fn test_check_latency_no_hosts() {
        let result = check_latency(&LatencyCheckOptions {
            hosts: vec![],
            ..LatencyCheckOptions::default()
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), LatencyError::NoHosts);
    }

    #[test]
    fn test_latency_sample_serialization() {
        let sample = LatencySample {
            host: "192.168.1.1".to_string(),
            method: "icmp".to_string(),
            latency_ms: Some(1.5),
            success: true,
            details: Some("ttl=64".to_string()),
            timestamp: "2024-01-01T00:00:00+00:00".to_string(),
        };
        let json = serde_json::to_string(&sample).unwrap();
        let parsed: LatencySample = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, "192.168.1.1");
        assert_eq!(parsed.latency_ms, Some(1.5));
        assert!(parsed.success);
    }

    #[test]
    fn test_host_latency_result_serialization() {
        let result = HostLatencyResult {
            host: "192.168.1.1".to_string(),
            samples: vec![
                LatencySample {
                    host: "192.168.1.1".to_string(),
                    method: "icmp".to_string(),
                    latency_ms: Some(1.0),
                    success: true,
                    details: None,
                    timestamp: "2024-01-01T00:00:00+00:00".to_string(),
                },
                LatencySample {
                    host: "192.168.1.1".to_string(),
                    method: "http".to_string(),
                    latency_ms: Some(5.0),
                    success: true,
                    details: Some("HTTP 200".to_string()),
                    timestamp: "2024-01-01T00:00:00+00:00".to_string(),
                },
            ],
            avg_latency_ms: Some(3.0),
            min_latency_ms: Some(1.0),
            max_latency_ms: Some(5.0),
            packet_loss: 0.0,
            elapsed_ms: 100.0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: HostLatencyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, "192.168.1.1");
        assert_eq!(parsed.samples.len(), 2);
        assert_eq!(parsed.avg_latency_ms, Some(3.0));
        assert_eq!(parsed.packet_loss, 0.0);
    }

    #[test]
    fn test_compute_statistics_empty() {
        let samples: Vec<f64> = vec![];
        let (avg, min, max, loss) = if samples.is_empty() {
            (None, None, None, 100.0)
        } else {
            let sum: f64 = samples.iter().sum();
            let avg = sum / samples.len() as f64;
            let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            (Some(avg), Some(min), Some(max), 0.0)
        };
        assert!(avg.is_none());
        assert!(min.is_none());
        assert!(max.is_none());
        assert_eq!(loss, 100.0);
    }

    #[test]
    fn test_compute_statistics_single() {
        let samples = vec![5.0];
        let (avg, min, max, loss) = if samples.is_empty() {
            (None, None, None, 100.0)
        } else {
            let sum: f64 = samples.iter().sum();
            let avg = sum / samples.len() as f64;
            let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            (Some(avg), Some(min), Some(max), 0.0)
        };
        assert_eq!(avg, Some(5.0));
        assert_eq!(min, Some(5.0));
        assert_eq!(max, Some(5.0));
        assert_eq!(loss, 0.0);
    }

    #[test]
    fn test_compute_statistics_multiple() {
        let samples = vec![2.0, 4.0, 6.0];
        let (avg, min, max, loss) = if samples.is_empty() {
            (None, None, None, 100.0)
        } else {
            let sum: f64 = samples.iter().sum();
            let avg = sum / samples.len() as f64;
            let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            (Some(avg), Some(min), Some(max), 0.0)
        };
        assert_eq!(avg, Some(4.0));
        assert_eq!(min, Some(2.0));
        assert_eq!(max, Some(6.0));
        assert_eq!(loss, 0.0);
    }
}
