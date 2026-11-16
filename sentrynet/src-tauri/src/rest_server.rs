//! Local HTTP/1.1 REST server for the web dashboard.
//!
//! Built on `std::net` only (no web framework). Each connection carries one
//! request and is answered with `Connection: close`. All routes return the
//! same JSON envelope as the Tauri commands: `{ success, data, error }`.
//!
//! Security: the server binds to `127.0.0.1` by default, rejects requests whose
//! `Host` header is not a loopback name (DNS-rebinding protection) and rejects
//! cross-origin browser requests unless they come from the app itself or a
//! localhost page.
//!
//! Routes (all under `/api`):
//!
//! | Method | Path                          | Handler                         |
//! |--------|-------------------------------|---------------------------------|
//! | GET    | /api, /api/health             | route list / liveness           |
//! | POST   | /api/scan                     | full scan (body: ScanRequest)   |
//! | POST   | /api/scan/host                | one host (body: ScanRequest + host) |
//! | POST   | /api/scan/ports               | ad-hoc port scan                |
//! | POST   | /api/scan/latency             | ad-hoc latency check            |
//! | GET    | /api/devices                  | device list                     |
//! | GET    | /api/devices/{ip}             | one device                      |
//! | GET    | /api/devices/{ip}/ports       | device ports                    |
//! | GET    | /api/devices/{ip}/history     | device history (`?limit=`)      |
//! | GET    | /api/devices/{ip}/alerts      | device alerts                   |
//! | GET    | /api/ports                    | all open ports                  |
//! | GET    | /api/history                  | `?limit=&event_type=`           |
//! | GET    | /api/alerts                   | `?acknowledged=&limit=`         |
//! | POST   | /api/alerts/{id}/ack          | acknowledge alert               |
//! | GET    | /api/config                   | read config                     |
//! | PUT    | /api/config                   | update config (partial allowed) |
//! | GET    | /api/stats                    | counters                        |
//! | GET    | /api/export/{devices,history,ports} | JSON download             |
//! | POST   | /api/cleanup                  | apply retention policy          |

use crate::api::{self, ApiError, ApiResponse};
use crate::database::Database;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────

/// Default listen address. Override with the `SENTRYNET_API_ADDR` env var.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:7357";

/// Maximum size of the request line plus headers.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Maximum request body size.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Read/write timeout for a client socket.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// How often the accept loop checks for shutdown.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Host names (without port) accepted in `Host` and `Origin` headers.
const LOOPBACK_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]", "tauri.localhost"];

/// Human-readable route list served at `GET /api`.
pub const ROUTES: &[&str] = &[
    "GET /api/health",
    "POST /api/scan",
    "POST /api/scan/host",
    "POST /api/scan/ports",
    "POST /api/scan/latency",
    "GET /api/devices",
    "GET /api/devices/{ip}",
    "GET /api/devices/{ip}/ports",
    "GET /api/devices/{ip}/history?limit=",
    "GET /api/devices/{ip}/alerts",
    "GET /api/ports",
    "GET /api/history?limit=&event_type=",
    "GET /api/alerts?acknowledged=&limit=",
    "POST /api/alerts/{id}/ack",
    "GET /api/config",
    "PUT /api/config",
    "GET /api/stats",
    "GET /api/export/devices",
    "GET /api/export/history?limit=",
    "GET /api/export/ports",
    "POST /api/cleanup",
];

// ──────────────────────────────────────────────
// Request / response types
// ──────────────────────────────────────────────

/// A parsed HTTP request.
#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    pub method: String,
    /// Percent-decoded path without the query string.
    pub path: String,
    pub query: HashMap<String, String>,
    /// Header names are lower-cased.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }
}

/// An HTTP response ready to be written.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self {
                status,
                content_type: "application/json; charset=utf-8",
                headers: Vec::new(),
                body,
            },
            Err(e) => Self::error(&ApiError::internal(format!("serialization failed: {e}"))),
        }
    }

    pub fn error(err: &ApiError) -> Self {
        Self::json(err.status, &ApiResponse::<()>::err(err.message.clone()))
    }

    pub fn from_result<T: Serialize>(result: Result<T, ApiError>) -> Self {
        match result {
            Ok(data) => Self::json(200, &ApiResponse::ok(data)),
            Err(e) => Self::error(&e),
        }
    }

    pub fn no_content() -> Self {
        Self {
            status: 204,
            content_type: "text/plain",
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// The JSON body parsed back (useful for tests and logging).
    pub fn body_json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }

    pub fn write_to<W: Write>(&self, out: &mut W) -> io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
            self.status,
            reason_phrase(self.status),
            self.content_type,
            self.body.len()
        );
        for (name, value) in &self.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        out.write_all(head.as_bytes())?;
        out.write_all(&self.body)?;
        out.flush()
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct RouteList {
    routes: &'static [&'static str],
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HostScanBody {
    host: String,
    #[serde(flatten)]
    options: api::ScanRequest,
}

// ──────────────────────────────────────────────
// Parsing helpers
// ──────────────────────────────────────────────

/// Decode `%XX` escapes (and `+` as space when `plus_as_space`).
pub fn percent_decode(input: &str, plus_as_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit() =>
            {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
                i += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Split a request target into a decoded path and query map.
pub fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let (raw_path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    let mut query = HashMap::new();
    for pair in raw_query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(percent_decode(k, true), percent_decode(v, true));
    }
    (percent_decode(raw_path, false), query)
}

/// Read one HTTP/1.x request (request line, headers and `Content-Length` body).
pub fn parse_request<R: BufRead>(reader: &mut R) -> Result<HttpRequest, ApiError> {
    let io_err = |e: io::Error| ApiError::bad_request(format!("could not read request: {e}"));

    let (method, target, headers) = {
        let mut head = (&mut *reader).take(MAX_HEADER_BYTES as u64);

        let mut line = String::new();
        if head.read_line(&mut line).map_err(io_err)? == 0 {
            return Err(ApiError::bad_request("empty request"));
        }
        let mut parts = line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("missing method"))?
            .to_ascii_uppercase();
        let target = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("missing request target"))?
            .to_string();
        let version = parts.next().unwrap_or("HTTP/1.0");
        if !version.starts_with("HTTP/1.") {
            return Err(ApiError::bad_request(format!("unsupported protocol: {version}")));
        }

        let mut headers = HashMap::new();
        loop {
            let mut header_line = String::new();
            if head.read_line(&mut header_line).map_err(io_err)? == 0 {
                return Err(ApiError::new(413, "request headers too large or truncated"));
            }
            let header_line = header_line.trim_end_matches(|c: char| c == '\r' || c == '\n');
            if header_line.is_empty() {
                break;
            }
            let (name, value) = header_line
                .split_once(':')
                .ok_or_else(|| ApiError::bad_request(format!("malformed header: {header_line:?}")))?;
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
        (method, target, headers)
    };

    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        return Err(ApiError::new(411, "chunked request bodies are not supported; send Content-Length"));
    }
    let length = match headers.get("content-length") {
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| ApiError::bad_request(format!("invalid Content-Length: {v}")))?,
        None => 0,
    };
    if length > MAX_BODY_BYTES {
        return Err(ApiError::new(413, format!("request body exceeds {MAX_BODY_BYTES} bytes")));
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).map_err(io_err)?;

    let (path, query) = split_target(&target);
    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

/// Strip an optional `:port` from a host (handles `[::1]:port`).
fn host_without_port(host: &str) -> &str {
    let host = host.trim();
    if host.starts_with('[') {
        match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        }
    } else {
        host.split(':').next().unwrap_or(host)
    }
}

/// `Host` header check: absent (HTTP/1.0) or a loopback name.
pub fn is_allowed_host(host: Option<&str>) -> bool {
    match host {
        None => true,
        Some(h) => {
            let name = host_without_port(h).to_ascii_lowercase();
            LOOPBACK_HOSTS.contains(&name.as_str())
        }
    }
}

/// `Origin` header check: the Tauri webview or a page served from localhost.
pub fn is_allowed_origin(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.trim().split_once("://") else {
        return false;
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https" | "tauri") {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    let name = host_without_port(authority).to_ascii_lowercase();
    LOOPBACK_HOSTS.contains(&name.as_str())
}

fn body_json<T: DeserializeOwned + Default>(req: &HttpRequest) -> Result<T, ApiError> {
    if req.body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(T::default());
    }
    serde_json::from_slice(&req.body)
        .map_err(|e| ApiError::bad_request(format!("invalid JSON body: {e}")))
}

fn query_usize(req: &HttpRequest, key: &str) -> Result<Option<usize>, ApiError> {
    match req.query_param(key).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| ApiError::bad_request(format!("{key} must be a non-negative integer"))),
    }
}

fn query_bool(req: &HttpRequest, key: &str) -> Result<Option<bool>, ApiError> {
    match req.query_param(key).map(|v| v.to_ascii_lowercase()) {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
        Some(v) if v == "true" || v == "1" => Ok(Some(true)),
        Some(v) if v == "false" || v == "0" => Ok(Some(false)),
        Some(_) => Err(ApiError::bad_request(format!("{key} must be true or false"))),
    }
}

// ──────────────────────────────────────────────
// Routing
// ──────────────────────────────────────────────

fn with_db<T: Serialize>(
    db_path: &str,
    f: impl FnOnce(&Database) -> Result<T, ApiError>,
) -> HttpResponse {
    HttpResponse::from_result(api::open_db(db_path).and_then(|db| f(&db)))
}

fn with_db_mut<T: Serialize>(
    db_path: &str,
    f: impl FnOnce(&mut Database) -> Result<T, ApiError>,
) -> HttpResponse {
    HttpResponse::from_result(api::open_db(db_path).and_then(|mut db| f(&mut db)))
}

fn export(db_path: &str, file_name: &str, f: impl FnOnce(&Database) -> Result<String, ApiError>) -> HttpResponse {
    match api::open_db(db_path).and_then(|db| f(&db)) {
        Ok(json) => HttpResponse {
            status: 200,
            content_type: "application/json; charset=utf-8",
            headers: Vec::new(),
            body: json.into_bytes(),
        }
        .with_header(
            "Content-Disposition",
            &format!("attachment; filename=\"{file_name}\""),
        ),
        Err(e) => HttpResponse::error(&e),
    }
}

/// Dispatch a request to the matching API handler.
pub fn route(req: &HttpRequest, db_path: &str) -> HttpResponse {
    if req.method == "OPTIONS" {
        return HttpResponse::no_content();
    }
    let segments: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    let method = req.method.as_str();

    match (method, segments.as_slice()) {
        ("GET", ["api"]) => HttpResponse::json(200, &ApiResponse::ok(RouteList { routes: ROUTES })),
        ("GET", ["api", "health"]) => HttpResponse::json(
            200,
            &ApiResponse::ok(Health {
                status: "ok",
                version: env!("CARGO_PKG_VERSION"),
            }),
        ),

        // ── Scans ──
        ("POST", ["api", "scan"]) => match body_json::<api::ScanRequest>(req) {
            Ok(body) => with_db_mut(db_path, |db| api::handle_scan(db, &body)),
            Err(e) => HttpResponse::error(&e),
        },
        ("POST", ["api", "scan", "host"]) => match body_json::<HostScanBody>(req) {
            Ok(body) => with_db_mut(db_path, |db| api::handle_scan_host(db, &body.host, &body.options)),
            Err(e) => HttpResponse::error(&e),
        },
        ("POST", ["api", "scan", "ports"]) => {
            HttpResponse::from_result(body_json::<api::PortScanRequest>(req).and_then(|b| api::handle_scan_ports(&b)))
        }
        ("POST", ["api", "scan", "latency"]) => {
            HttpResponse::from_result(body_json::<api::LatencyRequest>(req).and_then(|b| api::handle_scan_latency(&b)))
        }

        // ── Devices ──
        ("GET", ["api", "devices"]) => with_db(db_path, api::handle_list_devices),
        ("GET", ["api", "devices", ip]) => with_db(db_path, |db| api::handle_get_device(db, ip)),
        ("GET", ["api", "devices", ip, "ports"]) => {
            with_db(db_path, |db| api::handle_get_device_ports(db, ip))
        }
        ("GET", ["api", "devices", ip, "history"]) => match query_usize(req, "limit") {
            Ok(limit) => with_db(db_path, |db| api::handle_get_device_history(db, ip, limit)),
            Err(e) => HttpResponse::error(&e),
        },
        ("GET", ["api", "devices", ip, "alerts"]) => {
            with_db(db_path, |db| api::handle_get_device_alerts(db, ip))
        }

        // ── Ports / history / alerts ──
        ("GET", ["api", "ports"]) => with_db(db_path, api::handle_list_ports),
        ("GET", ["api", "history"]) => match query_usize(req, "limit") {
            Ok(limit) => with_db(db_path, |db| {
                api::handle_get_history(db, limit, req.query_param("event_type"))
            }),
            Err(e) => HttpResponse::error(&e),
        },
        ("GET", ["api", "alerts"]) => {
            match (query_bool(req, "acknowledged"), query_usize(req, "limit")) {
                (Ok(ack), Ok(limit)) => with_db(db_path, |db| api::handle_get_alerts(db, ack, limit)),
                (Err(e), _) | (_, Err(e)) => HttpResponse::error(&e),
            }
        }
        ("POST", ["api", "alerts", id, "ack"]) => match id.parse::<i64>() {
            Ok(id) => with_db(db_path, |db| api::handle_acknowledge_alert(db, id)),
            Err(_) => HttpResponse::error(&ApiError::bad_request(format!("invalid alert id: {id}"))),
        },

        // ── Config / stats / maintenance ──
        ("GET", ["api", "config"]) => with_db(db_path, api::handle_get_config),
        ("PUT", ["api", "config"]) | ("PATCH", ["api", "config"]) => {
            match serde_json::from_slice::<serde_json::Value>(&req.body) {
                Ok(patch) => with_db(db_path, |db| api::handle_patch_config(db, &patch)),
                Err(e) => HttpResponse::error(&ApiError::bad_request(format!("invalid JSON body: {e}"))),
            }
        }
        ("GET", ["api", "stats"]) => with_db(db_path, api::handle_get_stats),
        ("GET", ["api", "export", "devices"]) => {
            export(db_path, "sentrynet-devices.json", api::handle_export_devices)
        }
        ("GET", ["api", "export", "ports"]) => {
            export(db_path, "sentrynet-ports.json", api::handle_export_ports)
        }
        ("GET", ["api", "export", "history"]) => match query_usize(req, "limit") {
            Ok(limit) => export(db_path, "sentrynet-history.json", |db| {
                api::handle_export_history(db, limit)
            }),
            Err(e) => HttpResponse::error(&e),
        },
        ("POST", ["api", "cleanup"]) => with_db(db_path, api::handle_cleanup),

        _ => {
            let known_path = ROUTES.iter().any(|r| {
                let pattern = r.split_whitespace().nth(1).unwrap_or("");
                let pattern = pattern.split('?').next().unwrap_or(pattern);
                path_matches(pattern, &segments)
            });
            if known_path {
                HttpResponse::error(&ApiError::new(
                    405,
                    format!("method {} not allowed for {}", req.method, req.path),
                ))
            } else {
                HttpResponse::error(&ApiError::not_found(format!(
                    "no route for {} {}",
                    req.method, req.path
                )))
            }
        }
    }
}

/// Match a route pattern like `/api/devices/{ip}` against path segments.
fn path_matches(pattern: &str, segments: &[&str]) -> bool {
    let parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    parts.len() == segments.len()
        && parts
            .iter()
            .zip(segments)
            .all(|(p, s)| (p.starts_with('{') && p.ends_with('}')) || p == s)
}

/// Apply Host/Origin checks, route, and add CORS headers for allowed origins.
pub fn handle_request(req: &HttpRequest, db_path: &str) -> HttpResponse {
    if !is_allowed_host(req.header("host")) {
        return HttpResponse::error(&ApiError::new(403, "host not allowed"));
    }
    let origin = req.header("origin").map(str::trim).filter(|o| !o.is_empty());
    match origin {
        Some(o) if !is_allowed_origin(o) => {
            HttpResponse::error(&ApiError::new(403, "origin not allowed"))
        }
        Some(o) => route(req, db_path)
            .with_header("Access-Control-Allow-Origin", o)
            .with_header("Vary", "Origin")
            .with_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, OPTIONS")
            .with_header("Access-Control-Allow-Headers", "Content-Type"),
        None => route(req, db_path),
    }
}

// ──────────────────────────────────────────────
// Server
// ──────────────────────────────────────────────

/// A running REST server. Stops when dropped.
pub struct RestServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RestServer {
    /// Bind to `bind` (e.g. `127.0.0.1:7357`, or port 0 for any free port) and
    /// serve the API backed by the database at `db_path`.
    pub fn start(bind: &str, db_path: impl Into<String>) -> io::Result<Self> {
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let db_path: Arc<str> = Arc::from(db_path.into());
        let thread = thread::Builder::new()
            .name("sentrynet-rest".to_string())
            .spawn(move || accept_loop(listener, flag, db_path))?;
        Ok(Self {
            addr,
            shutdown,
            thread: Some(thread),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Base URL, e.g. `http://127.0.0.1:7357`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stop accepting connections and wait for the accept thread.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for RestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>, db_path: Arc<str>) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let db_path = Arc::clone(&db_path);
                let spawned = thread::Builder::new()
                    .name("sentrynet-rest-conn".to_string())
                    .spawn(move || {
                        if let Err(e) = handle_connection(stream, &db_path) {
                            eprintln!("[sentrynet] REST connection error: {e}");
                        }
                    });
                if let Err(e) = spawned {
                    eprintln!("[sentrynet] could not spawn REST worker: {e}");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(e) => {
                eprintln!("[sentrynet] REST accept error: {e}");
                thread::sleep(ACCEPT_POLL);
            }
        }
    }
}

fn handle_connection(stream: TcpStream, db_path: &str) -> io::Result<()> {
    // Accepted sockets may inherit the listener's non-blocking mode on some platforms.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    let response = match parse_request(&mut reader) {
        Ok(req) => handle_request(&req, db_path),
        Err(e) => HttpResponse::error(&e),
    };
    response.write_to(&mut writer)
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database;
    use chrono::Utc;
    use std::io::Cursor;
    use std::path::PathBuf;

    /// A temp database file removed on drop.
    struct TempDb(PathBuf);

    impl TempDb {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sentrynet_rest_{}_{}.sqlite",
                std::process::id(),
                name
            ));
            let _ = std::fs::remove_file(&path);
            Database::open(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }

        fn db(&self) -> Database {
            Database::open(&self.0).unwrap()
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn request(method: &str, target: &str, body: &str) -> HttpRequest {
        let (path, query) = split_target(target);
        HttpRequest {
            method: method.to_string(),
            path,
            query,
            headers: HashMap::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn seed(db: &Database) -> i64 {
        let now = Utc::now();
        db.upsert_device(&database::Device {
            ip: "192.168.1.10".to_string(),
            mac: "AA:BB:CC:DD:EE:10".to_string(),
            name: None,
            vendor: Some("Acme".to_string()),
            last_seen: now,
            first_seen: now,
        })
        .unwrap();
        db.upsert_port(
            &database::Port {
                device_ip: "192.168.1.10".to_string(),
                port: 22,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: Some("ssh".to_string()),
            },
            &now.to_rfc3339(),
        )
        .unwrap();
        db.append_history(&database::HistoryRecord {
            id: None,
            device_ip: "192.168.1.10".to_string(),
            event_type: "discovered".to_string(),
            details: None,
            timestamp: now,
        })
        .unwrap();
        db.create_alert(&database::Alert {
            id: None,
            device_ip: "192.168.1.10".to_string(),
            alert_type: "new_device".to_string(),
            message: "New device".to_string(),
            acknowledged: false,
            created_at: now,
        })
        .unwrap()
    }

    // ── Parsing ────────────────────────────────

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("a%20b", false), "a b");
        assert_eq!(percent_decode("a+b", true), "a b");
        assert_eq!(percent_decode("a+b", false), "a+b");
        assert_eq!(percent_decode("100%", false), "100%");
        assert_eq!(percent_decode("%zz", false), "%zz");
        assert_eq!(percent_decode("%3A%3a", false), "::");
    }

    #[test]
    fn test_split_target() {
        let (path, query) = split_target("/api/history?limit=5&event_type=port%5Fadded&flag");
        assert_eq!(path, "/api/history");
        assert_eq!(query.get("limit").map(String::as_str), Some("5"));
        assert_eq!(query.get("event_type").map(String::as_str), Some("port_added"));
        assert_eq!(query.get("flag").map(String::as_str), Some(""));
    }

    #[test]
    fn test_parse_request_with_body() {
        let raw = "PUT /api/config?x=1 HTTP/1.1\r\nHost: 127.0.0.1:7357\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"ping_count\":2}";
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let req = parse_request(&mut cursor).unwrap();
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/api/config");
        assert_eq!(req.query_param("x"), Some("1"));
        assert_eq!(req.header("Host"), Some("127.0.0.1:7357"));
        assert_eq!(req.body, b"{\"ping_count\":2}".to_vec());
    }

    #[test]
    fn test_parse_request_rejects_bad_input() {
        let mut empty = Cursor::new(Vec::new());
        assert_eq!(parse_request(&mut empty).unwrap_err().status, 400);

        let mut bad_version = Cursor::new(b"GET / SPDY/3\r\n\r\n".to_vec());
        assert_eq!(parse_request(&mut bad_version).unwrap_err().status, 400);

        let mut chunked =
            Cursor::new(b"POST /api/scan HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec());
        assert_eq!(parse_request(&mut chunked).unwrap_err().status, 411);

        let big = format!("POST /api/scan HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY_BYTES + 1);
        let mut too_big = Cursor::new(big.into_bytes());
        assert_eq!(parse_request(&mut too_big).unwrap_err().status, 413);

        let huge_header = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEADER_BYTES));
        let mut too_long = Cursor::new(huge_header.into_bytes());
        assert_eq!(parse_request(&mut too_long).unwrap_err().status, 413);
    }

    #[test]
    fn test_host_and_origin_checks() {
        assert!(is_allowed_host(None));
        assert!(is_allowed_host(Some("127.0.0.1:7357")));
        assert!(is_allowed_host(Some("localhost")));
        assert!(is_allowed_host(Some("[::1]:7357")));
        assert!(!is_allowed_host(Some("evil.example:7357")));
        assert!(!is_allowed_host(Some("192.168.1.5:7357")));

        assert!(is_allowed_origin("http://localhost:1420"));
        assert!(is_allowed_origin("tauri://localhost"));
        assert!(is_allowed_origin("http://tauri.localhost"));
        assert!(is_allowed_origin("https://tauri.localhost"));
        assert!(!is_allowed_origin("https://evil.example"));
        assert!(!is_allowed_origin("http://localhost.evil.example"));
        assert!(!is_allowed_origin("null"));
    }

    #[test]
    fn test_handle_request_blocks_foreign_origin_and_host() {
        let tmp = TempDb::new("guard");
        let mut req = request("GET", "/api/devices", "");
        req.headers.insert("origin".to_string(), "https://evil.example".to_string());
        assert_eq!(handle_request(&req, tmp.path()).status, 403);

        let mut req = request("GET", "/api/devices", "");
        req.headers.insert("host".to_string(), "attacker.example".to_string());
        assert_eq!(handle_request(&req, tmp.path()).status, 403);

        let mut req = request("GET", "/api/devices", "");
        req.headers.insert("origin".to_string(), "http://localhost:1420".to_string());
        let resp = handle_request(&req, tmp.path());
        assert_eq!(resp.status, 200);
        assert!(resp
            .headers
            .iter()
            .any(|(k, v)| k == "Access-Control-Allow-Origin" && v == "http://localhost:1420"));
    }

    // ── Routing ────────────────────────────────

    #[test]
    fn test_route_health_and_index() {
        let resp = route(&request("GET", "/api/health", ""), "unused");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body_json().unwrap()["data"]["status"], "ok");

        let resp = route(&request("GET", "/api", ""), "unused");
        assert_eq!(resp.status, 200);
        assert!(resp.body_json().unwrap()["data"]["routes"].as_array().unwrap().len() > 10);
    }

    #[test]
    fn test_route_not_found_and_method_not_allowed() {
        assert_eq!(route(&request("GET", "/api/nope", ""), "unused").status, 404);
        assert_eq!(route(&request("DELETE", "/api/devices", ""), "unused").status, 405);
        assert_eq!(route(&request("OPTIONS", "/api/devices", ""), "unused").status, 204);
    }

    #[test]
    fn test_route_device_endpoints() {
        let tmp = TempDb::new("devices");
        seed(&tmp.db());

        let resp = route(&request("GET", "/api/devices", ""), tmp.path());
        assert_eq!(resp.status, 200);
        let json = resp.body_json().unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["data"][0]["ip"], "192.168.1.10");

        let resp = route(&request("GET", "/api/devices/192.168.1.10", ""), tmp.path());
        assert_eq!(resp.body_json().unwrap()["data"]["vendor"], "Acme");

        assert_eq!(route(&request("GET", "/api/devices/10.0.0.1", ""), tmp.path()).status, 404);

        let resp = route(&request("GET", "/api/devices/192.168.1.10/ports", ""), tmp.path());
        assert_eq!(resp.body_json().unwrap()["data"][0]["port"], 22);

        let resp = route(&request("GET", "/api/devices/192.168.1.10/history?limit=5", ""), tmp.path());
        assert_eq!(resp.body_json().unwrap()["data"][0]["event_type"], "discovered");

        let resp = route(&request("GET", "/api/devices/192.168.1.10/alerts", ""), tmp.path());
        assert_eq!(resp.body_json().unwrap()["data"].as_array().unwrap().len(), 1);

        let resp = route(&request("GET", "/api/ports", ""), tmp.path());
        assert_eq!(resp.body_json().unwrap()["data"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_route_history_and_alerts() {
        let tmp = TempDb::new("alerts");
        let alert_id = seed(&tmp.db());

        let resp = route(&request("GET", "/api/history?event_type=discovered", ""), tmp.path());
        assert_eq!(resp.body_json().unwrap()["data"].as_array().unwrap().len(), 1);
        let resp = route(&request("GET", "/api/history?event_type=port_added", ""), tmp.path());
        assert!(resp.body_json().unwrap()["data"].as_array().unwrap().is_empty());
        assert_eq!(route(&request("GET", "/api/history?limit=abc", ""), tmp.path()).status, 400);

        let resp = route(&request("GET", "/api/alerts?acknowledged=false", ""), tmp.path());
        assert_eq!(resp.body_json().unwrap()["data"].as_array().unwrap().len(), 1);
        assert_eq!(route(&request("GET", "/api/alerts?acknowledged=maybe", ""), tmp.path()).status, 400);

        let ack = format!("/api/alerts/{alert_id}/ack");
        assert_eq!(route(&request("POST", &ack, ""), tmp.path()).status, 200);
        let resp = route(&request("GET", "/api/alerts?acknowledged=false", ""), tmp.path());
        assert!(resp.body_json().unwrap()["data"].as_array().unwrap().is_empty());
        assert_eq!(route(&request("POST", "/api/alerts/999999/ack", ""), tmp.path()).status, 404);
        assert_eq!(route(&request("POST", "/api/alerts/abc/ack", ""), tmp.path()).status, 400);
    }

    #[test]
    fn test_route_config_stats_export_cleanup() {
        let tmp = TempDb::new("config");
        seed(&tmp.db());

        let resp = route(&request("GET", "/api/config", ""), tmp.path());
        assert_eq!(resp.body_json().unwrap()["data"]["ping_count"], 4);

        let resp = route(&request("PUT", "/api/config", r#"{"ping_count": 2}"#), tmp.path());
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body_json().unwrap()["data"]["ping_count"], 2);
        assert_eq!(api::read_config_from_db(&tmp.db()).ping_count, 2);

        assert_eq!(route(&request("PUT", "/api/config", "{not json"), tmp.path()).status, 400);
        assert_eq!(route(&request("PUT", "/api/config", r#"{"ping_count": 0}"#), tmp.path()).status, 400);

        let resp = route(&request("GET", "/api/stats", ""), tmp.path());
        let stats = resp.body_json().unwrap();
        assert_eq!(stats["data"]["device_count"], 1);
        assert_eq!(stats["data"]["unacknowledged_alerts"], 1);

        let resp = route(&request("GET", "/api/export/devices", ""), tmp.path());
        assert_eq!(resp.status, 200);
        assert!(resp.headers.iter().any(|(k, _)| k == "Content-Disposition"));
        let exported: Vec<database::Device> = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(exported.len(), 1);

        let resp = route(&request("POST", "/api/cleanup", ""), tmp.path());
        assert_eq!(resp.body_json().unwrap()["data"]["history_deleted"], 0);
    }

    #[test]
    fn test_route_scan_validation_errors() {
        let tmp = TempDb::new("scan");
        assert_eq!(route(&request("POST", "/api/scan", r#"{"cidr":"bogus"}"#), tmp.path()).status, 400);
        assert_eq!(route(&request("POST", "/api/scan", "[1,"), tmp.path()).status, 400);
        assert_eq!(route(&request("POST", "/api/scan/host", "{}"), tmp.path()).status, 400);
        assert_eq!(route(&request("POST", "/api/scan/host", r#"{"host":"-n"}"#), tmp.path()).status, 400);
        assert_eq!(route(&request("POST", "/api/scan/ports", "{}"), tmp.path()).status, 400);
        assert_eq!(route(&request("POST", "/api/scan/latency", r#"{"hosts":[]}"#), tmp.path()).status, 400);
    }

    // ── Live server ────────────────────────────

    fn http_get(addr: SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn test_live_server_round_trip() {
        let tmp = TempDb::new("live");
        seed(&tmp.db());
        let mut server = RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
        let addr = server.local_addr();
        assert!(server.url().starts_with("http://127.0.0.1:"));

        let resp = http_get(addr, "GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("\"status\":\"ok\""));

        let resp = http_get(addr, "GET /api/devices HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("192.168.1.10"));

        let resp = http_get(addr, "GET /api/devices HTTP/1.1\r\nHost: evil.example\r\n\r\n");
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");

        let body = r#"{"http_port":8080}"#;
        let put = format!(
            "PUT /api/config HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_get(addr, &put);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("\"http_port\":8080"));

        server.stop();
        assert!(http_get_fails(addr));
    }

    /// After `stop`, the listener is closed; a connect may still succeed briefly on
    /// some platforms, but no response will be produced.
    fn http_get_fails(addr: SocketAddr) -> bool {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Err(_) => true,
            Ok(mut s) => {
                let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = s.write_all(b"GET /api/health HTTP/1.1\r\n\r\n");
                let mut buf = String::new();
                s.read_to_string(&mut buf).map(|_| buf.is_empty()).unwrap_or(true)
            }
        }
    }
}
