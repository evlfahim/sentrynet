//! SentryNet database module.
//!
//! Provides SQLite-backed storage for devices, ports, history, and alerts
//! with efficient indexes for common query patterns.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Result, Row};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ──────────────────────────────────────────────
// Schema version
// ──────────────────────────────────────────────

/// Schema version (used for future migrations).
#[allow(dead_code)]
const SCHEMA_VERSION: i32 = 1;

// ──────────────────────────────────────────────
// Domain types
// ──────────────────────────────────────────────

/// A network device discovered on the LAN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
}

/// An open port on a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub device_ip: String,
    pub port: u16,
    pub protocol: String, // "tcp" or "udp"
    pub state: String,    // "open", "closed", "filtered"
    pub service: Option<String>,
}

/// A history record capturing a device state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub id: Option<i64>,
    pub device_ip: String,
    pub event_type: String, // "discovered", "disconnected", "port_added", "port_removed", "port_state_changed"
    pub details: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// An alert triggered by the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Option<i64>,
    pub device_ip: String,
    pub alert_type: String, // "new_device", "new_port", "device_offline", "port_closed"
    pub message: String,
    pub acknowledged: bool,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────
// Schema creation
// ──────────────────────────────────────────────

/// SQL statements that create the full schema.
fn create_schema_sql() -> &'static str {
    r#"
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY CHECK (version = 1),
    created_at TEXT NOT NULL
);

-- Devices table: one row per unique IP
CREATE TABLE IF NOT EXISTS devices (
    ip              TEXT PRIMARY KEY,
    mac             TEXT NOT NULL,
    name            TEXT,
    vendor          TEXT,
    last_seen       TEXT NOT NULL,  -- ISO 8601 UTC
    first_seen      TEXT NOT NULL   -- ISO 8601 UTC
);

-- Ports table: one row per open port per device
CREATE TABLE IF NOT EXISTS ports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip       TEXT NOT NULL REFERENCES devices(ip) ON DELETE CASCADE,
    port            INTEGER NOT NULL,
    protocol        TEXT NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp','udp')),
    state           TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','closed','filtered')),
    service         TEXT,
    scanned_at      TEXT NOT NULL,  -- ISO 8601 UTC
    UNIQUE(device_ip, port, protocol)
);

-- History table: append-only log of state changes
CREATE TABLE IF NOT EXISTS history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    details         TEXT,
    timestamp       TEXT NOT NULL   -- ISO 8601 UTC
);

-- Alerts table: actionable notifications
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip       TEXT NOT NULL,
    alert_type      TEXT NOT NULL,
    message         TEXT NOT NULL,
    acknowledged    INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0,1)),
    created_at      TEXT NOT NULL   -- ISO 8601 UTC
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_ip);
CREATE INDEX IF NOT EXISTS idx_ports_device_port ON ports(device_ip, port);
CREATE INDEX IF NOT EXISTS idx_history_device ON history(device_ip);
CREATE INDEX IF NOT EXISTS idx_history_event ON history(event_type);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_history_device_timestamp ON history(device_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_ip);

-- Configuration table: key-value store for app settings
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#
}

// ──────────────────────────────────────────────
// Database handle
// ──────────────────────────────────────────────

/// Opaque handle to the SQLite connection.
pub struct Database {
    pub conn: Connection,
}

impl Database {
    /// Open (or create) the database at the given path and run migrations.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    /// Open an in-memory database (useful for tests).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    /// Run the initial schema migration.
    fn init(conn: &Connection) -> Result<()> {
        conn.execute_batch(create_schema_sql())?;
        conn.execute(
            "INSERT OR REPLACE INTO schema_version (version, created_at) VALUES (1, ?)",
            [Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    // ──────────────────────────────────────────
    // Device CRUD
    // ──────────────────────────────────────────

    /// Upsert a device (insert or update last_seen / name / vendor).
    pub fn upsert_device(&self, device: &Device) -> Result<()> {
        self.conn.execute(
            r#"INSERT INTO devices (ip, mac, name, vendor, last_seen, first_seen)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(ip) DO UPDATE SET
                   mac = excluded.mac,
                   name = excluded.name,
                   vendor = excluded.vendor,
                   last_seen = excluded.last_seen
               WHERE devices.last_seen < excluded.last_seen"#,
            params![
                &device.ip,
                &device.mac,
                device.name.as_deref(),
                device.vendor.as_deref(),
                device.last_seen.to_rfc3339(),
                device.first_seen.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Get a device by IP.
    pub fn get_device(&self, ip: &str) -> Result<Option<Device>> {
        match self.conn.query_row(
            "SELECT ip, mac, name, vendor, last_seen, first_seen FROM devices WHERE ip = ?1",
            params![ip],
            |row| Self::row_to_device(row),
        ) {
            Ok(device) => Ok(Some(device)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// List all devices ordered by last_seen descending.
    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, mac, name, vendor, last_seen, first_seen FROM devices ORDER BY last_seen DESC",
        )?;
        let devices = stmt
            .query_map(params![], |row| Self::row_to_device(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(devices)
    }

    /// Count devices.
    pub fn device_count(&self) -> Result<i64> {
        self.conn.query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))
    }

    /// Remove a device by IP.
    pub fn remove_device(&self, ip: &str) -> Result<usize> {
        self.conn.execute("DELETE FROM devices WHERE ip = ?1", params![ip])
    }

    // ──────────────────────────────────────────
    // Port CRUD
    // ──────────────────────────────────────────

    /// Upsert a port record.
    pub fn upsert_port(&self, port: &Port, scanned_at: &str) -> Result<()> {
        self.conn.execute(
            r#"INSERT INTO ports (device_ip, port, protocol, state, service, scanned_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(device_ip, port, protocol) DO UPDATE SET
                   state = excluded.state,
                   service = excluded.service,
                   scanned_at = excluded.scanned_at"#,
            params![
                &port.device_ip,
                port.port,
                &port.protocol,
                &port.state,
                port.service.as_deref(),
                scanned_at,
            ],
        )?;
        Ok(())
    }

    /// Get all ports for a device.
    pub fn get_ports(&self, device_ip: &str) -> Result<Vec<Port>> {
        let mut stmt = self.conn.prepare(
            "SELECT device_ip, port, protocol, state, service FROM ports \
             WHERE device_ip = ?1 ORDER BY port",
        )?;
        let ports = stmt
            .query_map(params![device_ip], |row| Self::row_to_port(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ports)
    }

    /// Get all open ports across all devices.
    pub fn list_open_ports(&self) -> Result<Vec<Port>> {
        let mut stmt = self.conn.prepare(
            "SELECT device_ip, port, protocol, state, service FROM ports \
             WHERE state = 'open' ORDER BY device_ip, port",
        )?;
        let ports = stmt
            .query_map(params![], |row| Self::row_to_port(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ports)
    }

    /// Remove all ports for a device (cascade).
    pub fn remove_device_ports(&self, device_ip: &str) -> Result<usize> {
        self.conn.execute("DELETE FROM ports WHERE device_ip = ?1", params![device_ip])
    }

    // ──────────────────────────────────────────
    // History CRUD
    // ──────────────────────────────────────────

    /// Append a history record.
    pub fn append_history(&self, record: &HistoryRecord) -> Result<i64> {
        let row_id = self.conn.execute(
            "INSERT INTO history (device_ip, event_type, details, timestamp) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                &record.device_ip,
                &record.event_type,
                record.details.as_deref(),
                record.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(row_id as i64)
    }

    /// Get history for a device, ordered by timestamp descending.
    pub fn get_history(&self, device_ip: &str, limit: usize) -> Result<Vec<HistoryRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_ip, event_type, details, timestamp FROM history \
             WHERE device_ip = ?1 ORDER BY timestamp DESC LIMIT ?2",
        )?;
        let records = stmt
            .query_map(params![device_ip, limit as i64], |row| Self::row_to_history(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Get the most recent N history records across all devices.
    pub fn get_recent_history(&self, limit: usize) -> Result<Vec<HistoryRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_ip, event_type, details, timestamp FROM history \
             ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let records = stmt
            .query_map(params![limit as i64], |row| Self::row_to_history(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Delete history older than the given cutoff.
    pub fn delete_old_history(&self, cutoff: &DateTime<Utc>) -> Result<usize> {
        self.conn.execute(
            "DELETE FROM history WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )
    }

    /// Count history records.
    pub fn history_count(&self) -> Result<i64> {
        self.conn.query_row("SELECT COUNT(*) FROM history", [], |row| row.get(0))
    }

    // ──────────────────────────────────────────
    // Alert CRUD
    // ──────────────────────────────────────────

    /// Create an alert.
    pub fn create_alert(&self, alert: &Alert) -> Result<i64> {
        let row_id = self.conn.execute(
            "INSERT INTO alerts (device_ip, alert_type, message, acknowledged, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &alert.device_ip,
                &alert.alert_type,
                &alert.message,
                if alert.acknowledged { 1 } else { 0 },
                alert.created_at.to_rfc3339(),
            ],
        )?;
        Ok(row_id as i64)
    }

    /// Get unacknowledged alerts.
    pub fn get_unacknowledged_alerts(&self) -> Result<Vec<Alert>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_ip, alert_type, message, acknowledged, created_at FROM alerts \
             WHERE acknowledged = 0 ORDER BY created_at DESC",
        )?;
        let alerts = stmt
            .query_map(params![], |row| Self::row_to_alert(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(alerts)
    }

    /// Get all alerts for a device.
    pub fn get_device_alerts(&self, device_ip: &str) -> Result<Vec<Alert>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_ip, alert_type, message, acknowledged, created_at FROM alerts \
             WHERE device_ip = ?1 ORDER BY created_at DESC",
        )?;
        let alerts = stmt
            .query_map(params![device_ip], |row| Self::row_to_alert(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(alerts)
    }

    /// Acknowledge an alert by ID.
    pub fn acknowledge_alert(&self, id: i64) -> Result<usize> {
        self.conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?1",
            params![id],
        )
    }

    /// Delete acknowledged alerts older than cutoff.
    pub fn delete_old_alerts(&self, cutoff: &DateTime<Utc>) -> Result<usize> {
        self.conn.execute(
            "DELETE FROM alerts WHERE acknowledged = 1 AND created_at < ?1",
            params![cutoff.to_rfc3339()],
        )
    }

    /// Count alerts.
    pub fn alert_count(&self) -> Result<i64> {
        self.conn.query_row("SELECT COUNT(*) FROM alerts", [], |row| row.get(0))
    }

    // ──────────────────────────────────────────
    // Bulk operations
    // ──────────────────────────────────────────

    /// Upsert multiple devices in a single transaction.
    pub fn upsert_devices_batch(&mut self, devices: &[Device]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for device in devices {
            tx.execute(
                r#"INSERT INTO devices (ip, mac, name, vendor, last_seen, first_seen)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                   ON CONFLICT(ip) DO UPDATE SET
                       mac = excluded.mac,
                       name = excluded.name,
                       vendor = excluded.vendor,
                       last_seen = excluded.last_seen
                   WHERE devices.last_seen < excluded.last_seen"#,
                params![
                    &device.ip,
                    &device.mac,
                    device.name.as_deref(),
                    device.vendor.as_deref(),
                    device.last_seen.to_rfc3339(),
                    device.first_seen.to_rfc3339(),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Upsert multiple ports in a single transaction.
    pub fn upsert_ports_batch(&mut self, ports: &[Port], scanned_at: &str) -> Result<()> {
        let tx = self.conn.transaction()?;
        for port in ports {
            tx.execute(
                r#"INSERT INTO ports (device_ip, port, protocol, state, service, scanned_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                   ON CONFLICT(device_ip, port, protocol) DO UPDATE SET
                       state = excluded.state,
                       service = excluded.service,
                       scanned_at = excluded.scanned_at"#,
                params![
                    &port.device_ip,
                    port.port,
                    &port.protocol,
                    &port.state,
                    port.service.as_deref(),
                    scanned_at,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Clear all data (useful for testing).
    pub fn clear_all(&self) -> Result<()> {
        self.conn.execute_batch(
            "DELETE FROM alerts;
             DELETE FROM history;
             DELETE FROM ports;
             DELETE FROM devices;",
        )?;
        Ok(())
    }

    // ──────────────────────────────────────────
    // Configuration CRUD
    // ──────────────────────────────────────────

    /// Get a config value by key.
    pub fn get_config_value(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT value FROM config WHERE key = ?1",
        )?;
        match stmt.query_row(params![key], |row| row.get(0)) {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Set a config value.
    pub fn set_config_value(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Read all config keys into a HashMap.
    pub fn read_all_config(&self) -> Result<HashMap<String, String>> {
        let mut stmt = self.conn.prepare("SELECT key, value FROM config")?;
        let rows = stmt.query_map(params![], |row| {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            Ok((key, value))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            map.insert(k, v);
        }
        Ok(map)
    }

    /// Get the full application configuration as JSON string.
    pub fn get_config_json(&self) -> Result<String> {
        let map = self.read_all_config()?;
        serde_json::to_string(&map).map_err(|_| rusqlite::Error::QueryReturnedNoRows)
    }

    /// Update the full application configuration from a JSON string.
    pub fn update_config_json(&self, json: &str) -> Result<()> {
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|_| rusqlite::Error::QueryReturnedNoRows)?;
        if let Some(obj) = value.as_object() {
            for (key, value) in obj {
                let value_str = value.to_string();
                self.set_config_value(key, &value_str)?;
            }
        }
        Ok(())
    }

    /// Get the full application configuration as a deserializable value.
    pub fn get_config_all(&self) -> Result<serde_json::Value> {
        let map = self.read_all_config()?;
        serde_json::to_value(&map).map_err(|_| rusqlite::Error::QueryReturnedNoRows)
    }
}

// ──────────────────────────────────────────────
// Row → struct helpers
// ──────────────────────────────────────────────

/// Parse an ISO 8601 UTC timestamp string into DateTime<Utc>.
fn parse_utc_timestamp(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

impl Database {
    fn row_to_device(row: &Row) -> Result<Device> {
        Ok(Device {
            ip: row.get("ip")?,
            mac: row.get("mac")?,
            name: row.get("name")?,
            vendor: row.get("vendor")?,
            last_seen: parse_utc_timestamp(&row.get::<_, String>("last_seen")?),
            first_seen: parse_utc_timestamp(&row.get::<_, String>("first_seen")?),
        })
    }

    fn row_to_port(row: &Row) -> Result<Port> {
        Ok(Port {
            device_ip: row.get("device_ip")?,
            port: row.get("port")?,
            protocol: row.get("protocol")?,
            state: row.get("state")?,
            service: row.get("service")?,
        })
    }

    fn row_to_history(row: &Row) -> Result<HistoryRecord> {
        Ok(HistoryRecord {
            id: row.get("id")?,
            device_ip: row.get("device_ip")?,
            event_type: row.get("event_type")?,
            details: row.get("details")?,
            timestamp: parse_utc_timestamp(&row.get::<_, String>("timestamp")?),
        })
    }

    pub fn row_to_alert(row: &Row) -> Result<Alert> {
        Ok(Alert {
            id: row.get("id")?,
            device_ip: row.get("device_ip")?,
            alert_type: row.get("alert_type")?,
            message: row.get("message")?,
            acknowledged: row.get("acknowledged")?,
            created_at: parse_utc_timestamp(&row.get::<_, String>("created_at")?),
        })
    }
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_device(ip: &str, mac: &str) -> Device {
        let now = Utc::now();
        Device {
            ip: ip.to_string(),
            mac: mac.to_string(),
            name: Some("TestDevice".to_string()),
            vendor: Some("TestVendor".to_string()),
            last_seen: now,
            first_seen: now - Duration::hours(1),
        }
    }

    fn make_port(device_ip: &str, port: u16, service: &str) -> Port {
        Port {
            device_ip: device_ip.to_string(),
            port,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(service.to_string()),
        }
    }

    fn make_history(device_ip: &str, event: &str) -> HistoryRecord {
        HistoryRecord {
            id: None,
            device_ip: device_ip.to_string(),
            event_type: event.to_string(),
            details: Some("test detail".to_string()),
            timestamp: Utc::now(),
        }
    }

    fn make_alert(device_ip: &str, alert_type: &str, message: &str) -> Alert {
        Alert {
            id: None,
            device_ip: device_ip.to_string(),
            alert_type: alert_type.to_string(),
            message: message.to_string(),
            acknowledged: false,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_schema_creation() {
        let db = Database::open_memory().unwrap();
        assert_eq!(db.device_count().unwrap(), 0);
        assert_eq!(db.history_count().unwrap(), 0);
        assert_eq!(db.alert_count().unwrap(), 0);
    }

    #[test]
    fn test_upsert_device() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();
        assert_eq!(db.device_count().unwrap(), 1);

        let fetched = db.get_device("192.168.1.1").unwrap();
        assert!(fetched.is_some());
        let d = fetched.unwrap();
        assert_eq!(d.ip, "192.168.1.1");
        assert_eq!(d.mac, "AA:BB:CC:DD:EE:01");
        assert_eq!(d.name, Some("TestDevice".to_string()));
    }

    #[test]
    fn test_device_update_last_seen() {
        let db = Database::open_memory().unwrap();
        let now = Utc::now();
        let device1 = Device {
            ip: "192.168.1.1".to_string(),
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            name: Some("Old".to_string()),
            vendor: None,
            last_seen: now - Duration::hours(2),
            first_seen: now - Duration::hours(3),
        };
        db.upsert_device(&device1).unwrap();

        let device2 = Device {
            ip: "192.168.1.1".to_string(),
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            name: Some("Updated".to_string()),
            vendor: Some("NewVendor".to_string()),
            last_seen: now,
            first_seen: now - Duration::hours(3),
        };
        db.upsert_device(&device2).unwrap();

        let fetched = db.get_device("192.168.1.1").unwrap().unwrap();
        assert_eq!(fetched.name, Some("Updated".to_string()));
        assert_eq!(fetched.vendor, Some("NewVendor".to_string()));
    }

    #[test]
    fn test_list_devices() {
        let db = Database::open_memory().unwrap();
        let d1 = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        let d2 = make_device("192.168.1.2", "AA:BB:CC:DD:EE:02");
        db.upsert_device(&d1).unwrap();
        db.upsert_device(&d2).unwrap();

        let devices = db.list_devices().unwrap();
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn test_remove_device() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();
        db.remove_device("192.168.1.1").unwrap();
        assert_eq!(db.device_count().unwrap(), 0);
    }

    #[test]
    fn test_upsert_port() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let port = make_port("192.168.1.1", 80, "http");
        db.upsert_port(&port, &Utc::now().to_rfc3339()).unwrap();

        let ports = db.get_ports("192.168.1.1").unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[0].service, Some("http".to_string()));
    }

    #[test]
    fn test_port_upsert_updates_existing() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let port1 = make_port("192.168.1.1", 80, "http");
        db.upsert_port(&port1, &Utc::now().to_rfc3339()).unwrap();

        // Update the same port with a different service
        let port2 = make_port("192.168.1.1", 80, "nginx");
        db.upsert_port(&port2, &Utc::now().to_rfc3339()).unwrap();

        let ports = db.get_ports("192.168.1.1").unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].service, Some("nginx".to_string()));
    }

    #[test]
    fn test_list_open_ports() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let port1 = make_port("192.168.1.1", 80, "http");
        let port2 = make_port("192.168.1.1", 443, "https");
        let port3 = make_port("192.168.1.1", 22, "ssh");
        db.upsert_port(&port1, &Utc::now().to_rfc3339()).unwrap();
        db.upsert_port(&port2, &Utc::now().to_rfc3339()).unwrap();
        db.upsert_port(&port3, &Utc::now().to_rfc3339()).unwrap();

        let open_ports = db.list_open_ports().unwrap();
        assert_eq!(open_ports.len(), 3);
    }

    #[test]
    fn test_append_history() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let record = make_history("192.168.1.1", "discovered");
        let id = db.append_history(&record).unwrap();
        assert!(id > 0);

        let records = db.get_history("192.168.1.1", 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_type, "discovered");
    }

    #[test]
    fn test_get_recent_history() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let r1 = make_history("192.168.1.1", "discovered");
        let r2 = make_history("192.168.1.1", "port_added");
        db.append_history(&r1).unwrap();
        db.append_history(&r2).unwrap();

        let records = db.get_recent_history(1).unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn test_create_alert() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let alert = make_alert("192.168.1.1", "new_device", "New device discovered: 192.168.1.1");
        let id = db.create_alert(&alert).unwrap();
        assert!(id > 0);

        let unacked = db.get_unacknowledged_alerts().unwrap();
        assert_eq!(unacked.len(), 1);
    }

    #[test]
    fn test_acknowledge_alert() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let alert = make_alert("192.168.1.1", "new_device", "New device discovered");
        let id = db.create_alert(&alert).unwrap();
        db.acknowledge_alert(id).unwrap();

        let unacked = db.get_unacknowledged_alerts().unwrap();
        assert_eq!(unacked.len(), 0);
    }

    #[test]
    fn test_batch_upsert_devices() {
        let mut db = Database::open_memory().unwrap();
        let devices: Vec<Device> = (1..=5)
            .map(|i| {
                make_device(&format!("192.168.1.{}", i), &format!("AA:BB:CC:DD:EE:{:02X}", i))
            })
            .collect();
        db.upsert_devices_batch(&devices).unwrap();
        assert_eq!(db.device_count().unwrap(), 5);
    }

    #[test]
    fn test_batch_upsert_ports() {
        let mut db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let ports: Vec<Port> = vec![
            make_port("192.168.1.1", 22, "ssh"),
            make_port("192.168.1.1", 80, "http"),
            make_port("192.168.1.1", 443, "https"),
        ];
        db.upsert_ports_batch(&ports, &Utc::now().to_rfc3339()).unwrap();

        let all_ports = db.get_ports("192.168.1.1").unwrap();
        assert_eq!(all_ports.len(), 3);
    }

    #[test]
    fn test_delete_old_history() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let old = make_history("192.168.1.1", "discovered");
        let old_timestamp = old.timestamp - Duration::days(30);
        // Manually insert with old timestamp
        db.conn.execute(
            "INSERT INTO history (device_ip, event_type, details, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![
                &old.device_ip,
                &old.event_type,
                old.details.as_deref(),
                old_timestamp.to_rfc3339(),
            ],
        ).unwrap();

        let new = make_history("192.168.1.1", "discovered");
        db.append_history(&new).unwrap();

        let cutoff = Utc::now() - Duration::days(7);
        let deleted = db.delete_old_history(&cutoff).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.history_count().unwrap(), 1);
    }

    #[test]
    fn test_delete_old_alerts() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let old_alert = make_alert("192.168.1.1", "new_device", "Old alert");
        let old_timestamp = old_alert.created_at - Duration::days(30);
        let old_alert = Alert {
            created_at: old_timestamp,
            ..old_alert
        };
        let id = db.create_alert(&old_alert).unwrap();
        db.acknowledge_alert(id).unwrap();

        let new_alert = make_alert("192.168.1.1", "new_device", "New alert");
        db.create_alert(&new_alert).unwrap();

        let cutoff = Utc::now() - Duration::days(7);
        let deleted = db.delete_old_alerts(&cutoff).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.alert_count().unwrap(), 1);
    }

    #[test]
    fn test_clear_all() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();
        let port = make_port("192.168.1.1", 80, "http");
        db.upsert_port(&port, &Utc::now().to_rfc3339()).unwrap();
        let record = make_history("192.168.1.1", "discovered");
        db.append_history(&record).unwrap();
        let alert = make_alert("192.168.1.1", "new_device", "New device");
        db.create_alert(&alert).unwrap();

        assert_eq!(db.device_count().unwrap(), 1);
        assert_eq!(db.history_count().unwrap(), 1);
        assert_eq!(db.alert_count().unwrap(), 1);

        db.clear_all().unwrap();
        assert_eq!(db.device_count().unwrap(), 0);
        assert_eq!(db.history_count().unwrap(), 0);
        assert_eq!(db.alert_count().unwrap(), 0);
    }

    #[test]
    fn test_device_cascade_delete() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let port = make_port("192.168.1.1", 80, "http");
        db.upsert_port(&port, &Utc::now().to_rfc3339()).unwrap();

        let record = make_history("192.168.1.1", "discovered");
        db.append_history(&record).unwrap();

        let alert = make_alert("192.168.1.1", "new_device", "Test");
        db.create_alert(&alert).unwrap();

        db.remove_device("192.168.1.1").unwrap();
        assert_eq!(db.device_count().unwrap(), 0);
        // Without FK constraints, related records remain; caller must clean up
        assert_eq!(db.history_count().unwrap(), 1);
        assert_eq!(db.alert_count().unwrap(), 1);
        assert_eq!(db.get_ports("192.168.1.1").unwrap().len(), 1);
    }

    #[test]
    fn test_unique_constraint_on_ports() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let port1 = make_port("192.168.1.1", 80, "http");
        let port2 = make_port("192.168.1.1", 80, "nginx");
        db.upsert_port(&port1, &Utc::now().to_rfc3339()).unwrap();
        db.upsert_port(&port2, &Utc::now().to_rfc3339()).unwrap();

        let ports = db.get_ports("192.168.1.1").unwrap();
        assert_eq!(ports.len(), 1);
    }

    #[test]
    fn test_udp_port() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let port = Port {
            device_ip: "192.168.1.1".to_string(),
            port: 53,
            protocol: "udp".to_string(),
            state: "open".to_string(),
            service: Some("dns".to_string()),
        };
        db.upsert_port(&port, &Utc::now().to_rfc3339()).unwrap();

        let ports = db.get_ports("192.168.1.1").unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].protocol, "udp");
    }

    #[test]
    fn test_file_based_database() {
        let tmp_dir = std::env::temp_dir();
        let db_path = tmp_dir.join("sentrynet_test_schema.sqlite");
        let db = Database::open(&db_path).unwrap();
        assert!(db_path.exists());

        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();
        assert_eq!(db.device_count().unwrap(), 1);

        // Clean up
        drop(db);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_get_nonexistent_device() {
        let db = Database::open_memory().unwrap();
        let result = db.get_device("10.0.0.99").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_device_alerts() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let alert1 = make_alert("192.168.1.1", "new_device", "Alert 1");
        let alert2 = make_alert("192.168.1.1", "new_port", "Alert 2");
        db.create_alert(&alert1).unwrap();
        db.create_alert(&alert2).unwrap();

        let alerts = db.get_device_alerts("192.168.1.1").unwrap();
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn test_get_device_alerts_other_device() {
        let db = Database::open_memory().unwrap();
        let d1 = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        let d2 = make_device("192.168.1.2", "AA:BB:CC:DD:EE:02");
        db.upsert_device(&d1).unwrap();
        db.upsert_device(&d2).unwrap();

        db.create_alert(&make_alert("192.168.1.1", "new_device", "Alert for d1")).unwrap();
        db.create_alert(&make_alert("192.168.1.2", "new_device", "Alert for d2")).unwrap();

        let alerts = db.get_device_alerts("192.168.1.1").unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].message, "Alert for d1");
    }

    #[test]
    fn test_remove_device_ports() {
        let db = Database::open_memory().unwrap();
        let device = make_device("192.168.1.1", "AA:BB:CC:DD:EE:01");
        db.upsert_device(&device).unwrap();

        let port1 = make_port("192.168.1.1", 80, "http");
        let port2 = make_port("192.168.1.1", 443, "https");
        db.upsert_port(&port1, &Utc::now().to_rfc3339()).unwrap();
        db.upsert_port(&port2, &Utc::now().to_rfc3339()).unwrap();

        let deleted = db.remove_device_ports("192.168.1.1").unwrap();
        assert_eq!(deleted, 2);
        assert!(db.get_ports("192.168.1.1").unwrap().is_empty());
    }
}
