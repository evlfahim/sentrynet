//! Integration tests for Step 14: Desktop app functionality, REST server access, and alert mechanisms.

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sentrynet_lib::alerts;
use sentrynet_lib::api;
use sentrynet_lib::database;
use sentrynet_lib::rest_server;

/// Mutex to serialize tests that interact with the global notifier state.
static NOTIFIER_TEST_MUTEX: Mutex<()> = Mutex::new(());

struct TempDb(PathBuf);

impl TempDb {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sentrynet_integ_{}_{}.sqlite",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&path);
        database::Database::open(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }

    fn db(&self) -> database::Database {
        database::Database::open(&self.0).unwrap()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn http_raw(addr: std::net::SocketAddr, raw: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut response = String::new();
    reader.read_to_string(&mut response).unwrap();
    response
}

fn extract_body(response: &str) -> String {
    response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .to_string()
}

fn json_data(response: &str) -> serde_json::Value {
    let body = extract_body(response);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    value["data"].clone()
}

fn check_success(response: &str) -> bool {
    let body = extract_body(response);
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["success"].as_bool().unwrap()
}

fn seed(db: &database::Database) -> i64 {
    let now = chrono::Utc::now();
    db.upsert_device(&database::Device {
        ip: "192.168.1.10".to_string(),
        mac: "AA:BB:CC:DD:EE:10".to_string(),
        name: None,
        vendor: Some("Acme".to_string()),
        last_seen: now,
        first_seen: now,
    }).unwrap();
    db.upsert_port(&database::Port {
        device_ip: "192.168.1.10".to_string(),
        port: 22,
        protocol: "tcp".to_string(),
        state: "open".to_string(),
        service: Some("ssh".to_string()),
    }, &now.to_rfc3339()).unwrap();
    db.append_history(&database::HistoryRecord {
        id: None,
        device_ip: "192.168.1.10".to_string(),
        event_type: "discovered".to_string(),
        details: None,
        timestamp: now,
    }).unwrap();
    db.create_alert(&database::Alert {
        id: None,
        device_ip: "192.168.1.10".to_string(),
        alert_type: "new_device".to_string(),
        message: "New device discovered".to_string(),
        acknowledged: false,
        created_at: now,
    }).unwrap()
}

/// 1. Desktop app binary exists and is executable.
#[test]
fn test_desktop_binary_exists() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let binary = PathBuf::from(manifest_dir).join("target/release/sentrynet");
    assert!(binary.exists(), "Desktop binary not found at {:?}", binary);
}

/// 2. REST server starts and responds to health check.
#[test]
fn test_rest_server_starts_and_health() {
    let tmp = TempDb::new("health");
    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "Expected 200, got: {resp}");
    assert!(resp.contains("\"status\":\"ok\""), "Health check missing status=ok");
    assert!(resp.contains("\"version\""), "Health check missing version");

    server.stop();
}

/// 3. REST server serves device list.
#[test]
fn test_rest_server_device_list() {
    let tmp = TempDb::new("devlist");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/devices HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(check_success(&resp));
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);
    assert_eq!(data.as_array().unwrap()[0]["ip"], serde_json::Value::String("192.168.1.10".to_string()));

    server.stop();
}

/// 4. REST server serves single device.
#[test]
fn test_rest_server_single_device() {
    let tmp = TempDb::new("single_dev");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/devices/192.168.1.10 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(check_success(&resp));
    let data = json_data(&resp);
    assert_eq!(data["ip"], "192.168.1.10");
    assert_eq!(data["vendor"], "Acme");

    let resp = http_raw(addr, "GET /api/devices/10.0.0.99 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");

    server.stop();
}

/// 5. REST server serves device ports.
#[test]
fn test_rest_server_device_ports() {
    let tmp = TempDb::new("dev_ports");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/devices/192.168.1.10/ports HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);
    assert_eq!(data.as_array().unwrap()[0]["port"], 22);
    assert_eq!(data.as_array().unwrap()[0]["service"], "ssh");

    server.stop();
}

/// 6. REST server serves device history.
#[test]
fn test_rest_server_device_history() {
    let tmp = TempDb::new("dev_hist");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/devices/192.168.1.10/history?limit=10 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);
    assert_eq!(data.as_array().unwrap()[0]["event_type"], "discovered");

    server.stop();
}

/// 7. REST server serves all open ports.
#[test]
fn test_rest_server_all_ports() {
    let tmp = TempDb::new("all_ports");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/ports HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);

    server.stop();
}

/// 8. REST server serves history.
#[test]
fn test_rest_server_history() {
    let tmp = TempDb::new("hist");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/history?limit=10 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);

    server.stop();
}

/// 9. REST server serves alerts.
#[test]
fn test_rest_server_alerts() {
    let tmp = TempDb::new("alerts");
    let _alert_id = seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/alerts?acknowledged=false HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);

    server.stop();
}

/// 10. REST server serves device alerts.
#[test]
fn test_rest_server_device_alerts() {
    let tmp = TempDb::new("dev_alerts");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/devices/192.168.1.10/alerts HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);
    assert_eq!(data.as_array().unwrap()[0]["alert_type"], "new_device");

    server.stop();
}

/// 11. REST server config endpoint.
#[test]
fn test_rest_server_config() {
    let tmp = TempDb::new("cfg");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/config HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(check_success(&resp));
    let data = json_data(&resp);
    assert_eq!(data["ping_count"], 4);
    assert_eq!(data["enable_notifications"], true);

    let body = r#"{"ping_count": 2, "enable_notifications": false}"#;
    let put = format!("PUT /api/config HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &put);
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(check_success(&resp));
    let data = json_data(&resp);
    assert_eq!(data["ping_count"], 2);
    assert_eq!(data["enable_notifications"], false);

    let resp = http_raw(addr, "GET /api/config HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let data = json_data(&resp);
    assert_eq!(data["ping_count"], 2);
    assert_eq!(data["enable_notifications"], false);

    server.stop();
}

/// 12. REST server stats endpoint.
#[test]
fn test_rest_server_stats() {
    let tmp = TempDb::new("stats");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/stats HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert_eq!(data["device_count"], 1);
    assert_eq!(data["port_count"], 1);
    assert_eq!(data["alert_count"], 1);
    assert_eq!(data["history_count"], 1);
    assert_eq!(data["unacknowledged_alerts"], 1);

    server.stop();
}

/// 13. REST server export endpoints (JSON).
#[test]
fn test_rest_server_export_json() {
    let tmp = TempDb::new("export_json");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/export/devices HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(resp.contains("Content-Disposition"));
    let body = extract_body(&resp);
    let devices: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert!(devices.len() >= 1);
    assert_eq!(devices[0]["ip"], "192.168.1.10");

    let resp = http_raw(addr, "GET /api/export/ports HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let body = extract_body(&resp);
    let ports: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert!(ports.len() >= 1);

    let resp = http_raw(addr, "GET /api/export/history?limit=100 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let body = extract_body(&resp);
    let history: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert!(history.len() >= 1);

    server.stop();
}

/// 14. REST server export endpoints (CSV).
#[test]
fn test_rest_server_export_csv() {
    let tmp = TempDb::new("export_csv");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/export/devices.csv HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let body = extract_body(&resp);
    assert!(body.starts_with("ip,mac,name,vendor,last_seen,first_seen\n"));
    assert!(body.contains("192.168.1.10"));

    let resp = http_raw(addr, "GET /api/export/ports.csv HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let body = extract_body(&resp);
    assert!(body.starts_with("device_ip,port,protocol,state,service\n"));
    assert!(body.contains("22"));
    assert!(body.contains("ssh"));

    let resp = http_raw(addr, "GET /api/export/history.csv?limit=100 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let body = extract_body(&resp);
    assert!(body.starts_with("device_ip,event_type,details,timestamp\n"));
    assert!(body.contains("discovered"));

    server.stop();
}

/// 15. REST server cleanup endpoint.
#[test]
fn test_rest_server_cleanup() {
    let tmp = TempDb::new("cleanup");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let body = r#"{"history_retention_days": 0}"#;
    let post = format!("POST /api/cleanup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &post);
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert_eq!(data["history_deleted"], 0);

    server.stop();
}

/// 16. REST server acknowledge alert.
#[test]
fn test_rest_server_acknowledge_alert() {
    let tmp = TempDb::new("ack");
    let alert_id = seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, &format!("POST /api/alerts/{alert_id}/ack HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(check_success(&resp));

    let resp = http_raw(addr, "GET /api/alerts?acknowledged=false HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().is_empty());

    let resp = http_raw(addr, "GET /api/alerts?acknowledged=true HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);

    server.stop();
}

/// 17. REST server notifications: unacknowledged alerts.
#[test]
fn test_rest_server_notifications_unack() {
    let tmp = TempDb::new("notif_unack");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/notifications/unacknowledged HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);

    server.stop();
}

/// 18. REST server notifications: test notification.
#[test]
fn test_rest_server_notifications_test() {
    let tmp = TempDb::new("notif_test");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "POST /api/notifications/test HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data["skipped"].as_bool().unwrap_or(false));

    server.stop();
}

/// 19. REST server notifications: resend pending alerts.
#[test]
fn test_rest_server_notifications_resend() {
    let tmp = TempDb::new("notif_resend");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "POST /api/notifications/resend HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data["skipped"].as_bool().unwrap_or(false));

    server.stop();
}

/// 20. REST server security: reject non-loopback host.
#[test]
fn test_rest_server_security_host_rejection() {
    let tmp = TempDb::new("sec_host");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/health HTTP/1.1\r\nHost: evil.example\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");

    server.stop();
}

/// 21. REST server security: reject non-loopback origin.
#[test]
fn test_rest_server_security_origin_rejection() {
    let tmp = TempDb::new("sec_origin");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/health HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");

    server.stop();
}

/// 22. REST server security: allow localhost origin with CORS headers.
#[test]
fn test_rest_server_security_cors_headers() {
    let tmp = TempDb::new("cors");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/health HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost:1420\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(resp.contains("Access-Control-Allow-Origin"));
    assert!(resp.contains("http://localhost:1420"));

    server.stop();
}

/// 23. REST server: server_info endpoint.
#[test]
fn test_rest_server_server_info() {
    let tmp = TempDb::new("sinfo");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/server_info HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    assert!(data["db_path"].as_str().unwrap().ends_with(".sqlite"));

    server.stop();
}

/// 24. REST server: route list endpoint.
#[test]
fn test_rest_server_route_list() {
    let tmp = TempDb::new("rlist");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    let data = json_data(&resp);
    let routes = data["routes"].as_array().unwrap();
    assert!(routes.len() >= 20);
    assert!(routes.iter().any(|r| r.as_str().unwrap().contains("/api/health")));

    server.stop();
}

/// 25. REST server: method not allowed.
#[test]
fn test_rest_server_method_not_allowed() {
    let tmp = TempDb::new("mna");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "DELETE /api/devices HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 405"), "{resp}");

    let resp = http_raw(addr, "OPTIONS /api/devices HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 204"), "{resp}");

    server.stop();
}

/// 26. REST server: 404 for unknown routes.
#[test]
fn test_rest_server_not_found() {
    let tmp = TempDb::new("404");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");

    server.stop();
}

/// 27. Alert mechanism: end-to-end notification planning.
#[test]
fn test_alert_planning_end_to_end() {
    let _guard = NOTIFIER_TEST_MUTEX.lock().unwrap();
    // Ensure clean state
    alerts::clear_notifier();

    let shown = Arc::new(std::sync::Mutex::new(Vec::new()));
    let shown_clone = Arc::clone(&shown);
    alerts::set_notifier(Arc::new(move |n: &alerts::Notification| {
        shown_clone.lock().unwrap().push(n.clone());
        Ok(())
    }));

    let tmp = TempDb::new("alert_e2e");
    let db = tmp.db();
    seed(&db);

    let alerts_list = db.get_unacknowledged_alerts().unwrap();
    assert!(!alerts_list.is_empty());

    let outcome = alerts::notify_alerts(&db, &alerts_list);
    assert!(!outcome.skipped, "Expected notifications to be sent, but got: {:?}", outcome);
    assert!(outcome.sent >= 1);

    let shown_notifications = shown.lock().unwrap();
    assert!(!shown_notifications.is_empty());
    assert_eq!(shown_notifications[0].title, "New device discovered");

    alerts::clear_notifier();
}

/// 28. Alert mechanism: notifications disabled in config.
#[test]
fn test_alert_notifications_disabled() {
    let _guard = NOTIFIER_TEST_MUTEX.lock().unwrap();
    let tmp = TempDb::new("alert_disabled");
    let db = tmp.db();
    seed(&db);

    api::write_config_to_db(&db, &api::AppConfig {
        enable_notifications: false,
        ..api::AppConfig::default()
    }).unwrap();

    let shown = Arc::new(std::sync::Mutex::new(Vec::new()));
    let shown_clone = Arc::clone(&shown);
    alerts::set_notifier(Arc::new(move |n: &alerts::Notification| {
        shown_clone.lock().unwrap().push(n.clone());
        Ok(())
    }));

    let alerts_list = db.get_unacknowledged_alerts().unwrap();
    let outcome = alerts::notify_alerts(&db, &alerts_list);
    assert!(outcome.skipped);
    assert_eq!(outcome.reason.as_deref(), Some("notifications are disabled in config"));
    assert_eq!(outcome.sent, 0);

    let shown_notifications = shown.lock().unwrap();
    assert!(shown_notifications.is_empty());

    alerts::clear_notifier();
}

/// 29. Alert mechanism: no notifier installed.
#[test]
fn test_alert_no_notifier() {
    let _guard = NOTIFIER_TEST_MUTEX.lock().unwrap();
    alerts::clear_notifier();

    let tmp = TempDb::new("alert_no_notif");
    let db = tmp.db();
    seed(&db);

    let alerts_list = db.get_unacknowledged_alerts().unwrap();
    let outcome = alerts::notify_alerts(&db, &alerts_list);
    assert!(outcome.skipped);
    assert_eq!(outcome.reason.as_deref(), Some("no desktop notifier available"));
}

/// 30. Alert mechanism: acknowledged alerts are skipped.
#[test]
fn test_alert_acknowledged_skipped() {
    let _guard = NOTIFIER_TEST_MUTEX.lock().unwrap();
    let tmp = TempDb::new("alert_ack");
    let db = tmp.db();
    let alert_id = seed(&db);

    db.acknowledge_alert(alert_id).unwrap();

    let shown = Arc::new(std::sync::Mutex::new(Vec::new()));
    let shown_clone = Arc::clone(&shown);
    alerts::set_notifier(Arc::new(move |n: &alerts::Notification| {
        shown_clone.lock().unwrap().push(n.clone());
        Ok(())
    }));

    let alerts_list = db.get_unacknowledged_alerts().unwrap();
    assert!(alerts_list.is_empty());

    let outcome = alerts::notify_alerts(&db, &alerts_list);
    assert!(outcome.skipped);
    assert_eq!(outcome.reason.as_deref(), Some("no unacknowledged alerts"));

    alerts::clear_notifier();
}

/// 31. Alert mechanism: notify_unacknowledged (re-send on restart).
#[test]
fn test_alert_notify_unacknowledged() {
    let _guard = NOTIFIER_TEST_MUTEX.lock().unwrap();
    let tmp = TempDb::new("alert_renotify");
    let db = tmp.db();
    seed(&db);

    let shown = Arc::new(std::sync::Mutex::new(Vec::new()));
    let shown_clone = Arc::clone(&shown);
    alerts::set_notifier(Arc::new(move |n: &alerts::Notification| {
        shown_clone.lock().unwrap().push(n.clone());
        Ok(())
    }));

    let outcome = alerts::notify_unacknowledged(&db).unwrap();
    assert!(!outcome.skipped);
    assert!(outcome.sent >= 1);

    alerts::clear_notifier();
}

/// 32. Alert mechanism: notify_one (test notification).
#[test]
fn test_alert_notify_one() {
    let _guard = NOTIFIER_TEST_MUTEX.lock().unwrap();
    let tmp = TempDb::new("alert_one");
    let db = tmp.db();
    seed(&db);

    let shown = Arc::new(std::sync::Mutex::new(Vec::new()));
    let shown_clone = Arc::clone(&shown);
    alerts::set_notifier(Arc::new(move |n: &alerts::Notification| {
        shown_clone.lock().unwrap().push(n.clone());
        Ok(())
    }));

    let notification = alerts::Notification {
        title: "Test notification".to_string(),
        body: "This is a test".to_string(),
    };
    let outcome = alerts::notify_one(&db, &notification);
    assert!(!outcome.skipped);
    assert_eq!(outcome.sent, 1);
    assert_eq!(outcome.failed, 0);

    let shown_notifications = shown.lock().unwrap();
    assert!(!shown_notifications.is_empty());
    assert_eq!(shown_notifications[0].title, "Test notification");
    assert_eq!(shown_notifications[0].body, "This is a test");

    alerts::clear_notifier();
}

/// 33. Alert mechanism: notify_one with notifications disabled.
#[test]
fn test_alert_notify_one_disabled() {
    let _guard = NOTIFIER_TEST_MUTEX.lock().unwrap();
    let tmp = TempDb::new("alert_one_dis");
    let db = tmp.db();

    api::write_config_to_db(&db, &api::AppConfig {
        enable_notifications: false,
        ..api::AppConfig::default()
    }).unwrap();

    let notification = alerts::Notification {
        title: "Test".to_string(),
        body: "Test".to_string(),
    };
    let outcome = alerts::notify_one(&db, &notification);
    assert!(outcome.skipped);
    assert_eq!(outcome.sent, 0);

    alerts::clear_notifier();
}

/// 34. REST server: scan ports endpoint (ad-hoc).
#[test]
fn test_rest_server_scan_ports() {
    let tmp = TempDb::new("scan_ports");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let body = r#"{"hosts": ["127.0.0.1"], "ports": [22], "timeout_ms": 2000}"#;
    let post = format!("POST /api/scan/ports HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &post);
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(check_success(&resp));
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);

    server.stop();
}

/// 35. REST server: scan latency endpoint (ad-hoc).
#[test]
fn test_rest_server_scan_latency() {
    let tmp = TempDb::new("scan_lat");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let body = r#"{"hosts": ["127.0.0.1"], "ping_count": 1, "ping_timeout_ms": 2000}"#;
    let post = format!("POST /api/scan/latency HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &post);
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(check_success(&resp));
    let data = json_data(&resp);
    assert!(data.as_array().unwrap().len() >= 1);

    server.stop();
}

/// 36. REST server: scan single host endpoint.
#[test]
fn test_rest_server_scan_single_host() {
    let tmp = TempDb::new("scan_host");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let body = r#"{"host": "127.0.0.1", "ping_count": 1, "ping_timeout_ms": 2000}"#;
    let post = format!("POST /api/scan/host HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &post);
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(check_success(&resp));
    let data = json_data(&resp);
    assert_eq!(data["ip"], "127.0.0.1");

    server.stop();
}

/// 37. REST server: scan validation errors.
#[test]
fn test_rest_server_scan_validation_errors() {
    let tmp = TempDb::new("scan_val");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let body = r#"{"cidr": "bogus"}"#;
    let post = format!("POST /api/scan HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &post);
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");

    let body = r#"{"host": "-n"}"#;
    let post = format!("POST /api/scan/host HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &post);
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");

    let body = r#"{"hosts": []}"#;
    let post = format!("POST /api/scan/ports HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &post);
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");

    let body = r#"{"hosts": []}"#;
    let post = format!("POST /api/scan/latency HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &post);
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");

    server.stop();
}

/// 38. REST server: invalid JSON body.
#[test]
fn test_rest_server_invalid_json() {
    let tmp = TempDb::new("inv_json");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "PUT /api/config HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{not}");
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");

    server.stop();
}

/// 39. REST server: config validation (out of range).
#[test]
fn test_rest_server_config_validation() {
    let tmp = TempDb::new("cfg_val");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let body = r#"{"ping_count": 0}"#;
    let post = format!("PUT /api/config HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let resp = http_raw(addr, &post);
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");

    server.stop();
}

/// 40. REST server: server stops cleanly.
#[test]
fn test_rest_server_stop() {
    let tmp = TempDb::new("stop");
    seed(&tmp.db());

    let mut server = rest_server::RestServer::start("127.0.0.1:0", tmp.path()).unwrap();
    let addr = server.local_addr();

    let resp = http_raw(addr, "GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");

    server.stop();

    let result = std::panic::catch_unwind(|| {
        let resp = http_raw(addr, "GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        resp
    });
    if let Ok(resp) = result {
        assert!(resp.is_empty() || resp.contains("403") || resp.contains("404"));
    }
}
