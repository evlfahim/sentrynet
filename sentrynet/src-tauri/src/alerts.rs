//! SentryNet alert logic and desktop notifications.
//!
//! This module has two jobs:
//!
//! 1. **Detection** — decide whether a device found by an ARP scan is new to
//!    the network ([`classify_device`]) and build the matching alert
//!    ([`new_device_alert`]). The core scanner calls these *before* it writes
//!    the scan results, so the comparison is made against what was known
//!    before this scan.
//! 2. **Delivery** — turn freshly created alerts into desktop notifications
//!    ([`plan_notifications`]) and hand them to the installed notifier
//!    ([`notify_alerts`]). The desktop app installs a notifier backed by the
//!    Tauri notification plugin at startup ([`set_notifier`]); without one
//!    (unit tests, headless use) delivery is a no-op.
//!
//! Delivery is wired into the shared scan handlers in [`crate::api`], so a
//! scan started from the desktop window, the REST API, or the web dashboard
//! all trigger the same notifications. Notifications respect the
//! `enable_notifications` config flag.
//!
//! Alert types and their notification titles:
//!
//! | alert_type      | title                   |
//! |-----------------|-------------------------|
//! | new_device      | "New device discovered" |
//! | new_port        | "New port opened"       |
//! | device_offline  | "Device offline"        |
//! | port_closed     | "Port closed"           |

use crate::api::read_config_from_db;
use crate::arp::ArpEntry;
use crate::database::{Alert, Database, Device};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────

pub const ALERT_NEW_DEVICE: &str = "new_device";
pub const ALERT_NEW_PORT: &str = "new_port";
pub const ALERT_DEVICE_OFFLINE: &str = "device_offline";
pub const ALERT_PORT_CLOSED: &str = "port_closed";

/// MAC stored for devices added by a manual single-host scan (MAC unknown).
pub const PLACEHOLDER_MAC: &str = "00:00:00:00:00:00";

/// Up to this many alerts of one type get their own notification; more are
/// collapsed into a single summary so a first scan doesn't flood the desktop.
pub const MAX_INDIVIDUAL_NOTIFICATIONS: usize = 3;

/// Order in which alert types are notified (most important first).
const TYPE_ORDER: [&str; 4] = [
    ALERT_NEW_DEVICE,
    ALERT_NEW_PORT,
    ALERT_DEVICE_OFFLINE,
    ALERT_PORT_CLOSED,
];

// ──────────────────────────────────────────────
// Detection
// ──────────────────────────────────────────────

/// How a device found by a scan relates to what the database already knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    /// The IP has never been seen before.
    New,
    /// The IP is known but now answers with a different MAC address, i.e. a
    /// different piece of hardware took over the address. Holds the old MAC.
    MacChanged(String),
    /// Same IP and MAC as before.
    Known,
}

impl DeviceStatus {
    /// Whether this status should raise a `new_device` alert.
    pub fn is_new(&self) -> bool {
        !matches!(self, DeviceStatus::Known)
    }
}

/// Classify a scanned device against the stored record for the same IP.
///
/// A stored placeholder MAC (from a manual scan) or an empty MAC on either side
/// never counts as a change.
pub fn classify_device(existing: Option<&Device>, scanned_mac: &str) -> DeviceStatus {
    let Some(existing) = existing else {
        return DeviceStatus::New;
    };
    let old = existing.mac.trim();
    let new = scanned_mac.trim();
    if old.is_empty()
        || new.is_empty()
        || old.eq_ignore_ascii_case(PLACEHOLDER_MAC)
        || new.eq_ignore_ascii_case(PLACEHOLDER_MAC)
        || old.eq_ignore_ascii_case(new)
    {
        DeviceStatus::Known
    } else {
        DeviceStatus::MacChanged(old.to_string())
    }
}

/// Human-readable description of a scanned device: `ip (mac, vendor)`.
fn describe(entry: &ArpEntry) -> String {
    match entry.vendor.as_deref().filter(|v| !v.trim().is_empty()) {
        Some(vendor) => format!("{} ({}, {})", entry.ip, entry.mac, vendor),
        None => format!("{} ({})", entry.ip, entry.mac),
    }
}

/// Build the `new_device` alert for a device classified as new.
///
/// Returns `None` for [`DeviceStatus::Known`].
pub fn new_device_alert(entry: &ArpEntry, status: &DeviceStatus, now: DateTime<Utc>) -> Option<Alert> {
    let message = match status {
        DeviceStatus::New => format!("New device joined the network: {}", describe(entry)),
        DeviceStatus::MacChanged(previous) => format!(
            "Different device now uses {}: MAC changed from {} to {}",
            describe(entry),
            previous,
            entry.mac
        ),
        DeviceStatus::Known => return None,
    };
    Some(Alert {
        id: None,
        device_ip: entry.ip.clone(),
        alert_type: ALERT_NEW_DEVICE.to_string(),
        message,
        acknowledged: false,
        created_at: now,
    })
}

// ──────────────────────────────────────────────
// Notification planning
// ──────────────────────────────────────────────

/// A desktop notification ready to be shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub title: String,
    pub body: String,
}

/// What happened when alerts were handed to the notifier.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyOutcome {
    /// Notifications shown successfully.
    pub sent: usize,
    /// Notifications the notifier failed to show.
    pub failed: usize,
    /// True when nothing was attempted (disabled, no notifier, no alerts).
    pub skipped: bool,
    /// Why nothing was attempted, or the last delivery error.
    pub reason: Option<String>,
}

/// Map an alert type to a human-readable notification title.
pub fn alert_title(alert_type: &str) -> &'static str {
    match alert_type {
        ALERT_NEW_DEVICE => "New device discovered",
        ALERT_NEW_PORT => "New port opened",
        ALERT_DEVICE_OFFLINE => "Device offline",
        ALERT_PORT_CLOSED => "Port closed",
        _ => "SentryNet alert",
    }
}

/// Title of the summary notification for `count` alerts of one type.
fn summary_title(alert_type: &str, count: usize) -> String {
    match alert_type {
        ALERT_NEW_DEVICE => format!("{count} new devices discovered"),
        ALERT_NEW_PORT => format!("{count} new open ports"),
        ALERT_DEVICE_OFFLINE => format!("{count} devices went offline"),
        ALERT_PORT_CLOSED => format!("{count} ports closed"),
        _ => format!("{count} SentryNet alerts"),
    }
}

/// Body of a summary notification: the first few IPs, then "and N more".
fn summary_body(alerts: &[&Alert]) -> String {
    let mut ips: Vec<&str> = Vec::new();
    for alert in alerts {
        if !ips.contains(&alert.device_ip.as_str()) {
            ips.push(&alert.device_ip);
        }
    }
    let shown = ips.len().min(MAX_INDIVIDUAL_NOTIFICATIONS);
    let mut body = ips[..shown].join(", ");
    if ips.len() > shown {
        body.push_str(&format!(" and {} more", ips.len() - shown));
    }
    body.push_str(". Open SentryNet to review.");
    body
}

/// Turn alerts into notifications.
///
/// Acknowledged alerts are ignored. Alerts are grouped by type (new devices
/// first); a group of up to [`MAX_INDIVIDUAL_NOTIFICATIONS`] alerts produces
/// one notification per alert, a larger group produces one summary.
pub fn plan_notifications(alerts: &[Alert]) -> Vec<Notification> {
    let pending: Vec<&Alert> = alerts.iter().filter(|a| !a.acknowledged).collect();

    let mut types: Vec<&str> = TYPE_ORDER.to_vec();
    for alert in &pending {
        if !types.contains(&alert.alert_type.as_str()) {
            types.push(&alert.alert_type);
        }
    }

    let mut out = Vec::new();
    for alert_type in types {
        let group: Vec<&Alert> = pending
            .iter()
            .copied()
            .filter(|a| a.alert_type == alert_type)
            .collect();
        if group.is_empty() {
            continue;
        }
        if group.len() <= MAX_INDIVIDUAL_NOTIFICATIONS {
            out.extend(group.iter().map(|a| Notification {
                title: alert_title(&a.alert_type).to_string(),
                body: a.message.clone(),
            }));
        } else {
            out.push(Notification {
                title: summary_title(alert_type, group.len()),
                body: summary_body(&group),
            });
        }
    }
    out
}

// ──────────────────────────────────────────────
// Delivery
// ──────────────────────────────────────────────

/// Something that can show a desktop notification.
pub type Notifier = Arc<dyn Fn(&Notification) -> Result<(), String> + Send + Sync>;

static NOTIFIER: RwLock<Option<Notifier>> = RwLock::new(None);

/// Install the process-wide notifier (the desktop app does this at startup).
pub fn set_notifier(notifier: Notifier) {
    let mut slot = NOTIFIER.write().unwrap_or_else(|e| e.into_inner());
    *slot = Some(notifier);
}

/// Remove the installed notifier.
pub fn clear_notifier() {
    let mut slot = NOTIFIER.write().unwrap_or_else(|e| e.into_inner());
    *slot = None;
}

/// The installed notifier, if any.
fn current_notifier() -> Option<Notifier> {
    NOTIFIER.read().unwrap_or_else(|e| e.into_inner()).clone()
}

fn skipped(reason: &str) -> NotifyOutcome {
    NotifyOutcome {
        sent: 0,
        failed: 0,
        skipped: true,
        reason: Some(reason.to_string()),
    }
}

/// Plan notifications for `alerts` and deliver them through `notifier`.
///
/// Delivery errors are counted and logged but never returned: a failed
/// notification must not fail the scan that produced the alert.
pub fn notify_with(
    enabled: bool,
    alerts: &[Alert],
    notifier: &dyn Fn(&Notification) -> Result<(), String>,
) -> NotifyOutcome {
    if !enabled {
        return skipped("notifications are disabled in config");
    }
    let planned = plan_notifications(alerts);
    if planned.is_empty() {
        return skipped("no unacknowledged alerts");
    }
    let mut outcome = NotifyOutcome::default();
    for notification in &planned {
        match notifier(notification) {
            Ok(()) => outcome.sent += 1,
            Err(e) => {
                eprintln!(
                    "[sentrynet] failed to show notification \"{}\": {e}",
                    notification.title
                );
                outcome.failed += 1;
                outcome.reason = Some(e);
            }
        }
    }
    outcome
}

/// Notify about `alerts` using the stored config and the installed notifier.
pub fn notify_alerts(db: &Database, alerts: &[Alert]) -> NotifyOutcome {
    if alerts.is_empty() {
        return skipped("no unacknowledged alerts");
    }
    let enabled = read_config_from_db(db).enable_notifications;
    if !enabled {
        return skipped("notifications are disabled in config");
    }
    match current_notifier() {
        Some(notifier) => notify_with(true, alerts, notifier.as_ref()),
        None => skipped("no desktop notifier available"),
    }
}

/// Re-send notifications for every unacknowledged alert in the database
/// (e.g. after the app restarted while alerts were pending).
pub fn notify_unacknowledged(db: &Database) -> Result<NotifyOutcome, rusqlite::Error> {
    let alerts = db.get_unacknowledged_alerts()?;
    Ok(notify_alerts(db, &alerts))
}

/// Show one notification directly, bypassing alert planning but still
/// honouring the `enable_notifications` flag. Used for "send test notification".
pub fn notify_one(db: &Database, notification: &Notification) -> NotifyOutcome {
    if !read_config_from_db(db).enable_notifications {
        return skipped("notifications are disabled in config");
    }
    let Some(notifier) = current_notifier() else {
        return skipped("no desktop notifier available");
    };
    match notifier(notification) {
        Ok(()) => NotifyOutcome {
            sent: 1,
            ..NotifyOutcome::default()
        },
        Err(e) => NotifyOutcome {
            sent: 0,
            failed: 1,
            skipped: false,
            reason: Some(e),
        },
    }
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{write_config_to_db, AppConfig};
    use std::sync::Mutex;

    fn device(ip: &str, mac: &str) -> Device {
        let now = Utc::now();
        Device {
            ip: ip.to_string(),
            mac: mac.to_string(),
            name: None,
            vendor: None,
            last_seen: now,
            first_seen: now,
        }
    }

    fn entry(ip: &str, mac: &str, vendor: Option<&str>) -> ArpEntry {
        ArpEntry {
            ip: ip.to_string(),
            mac: mac.to_string(),
            vendor: vendor.map(str::to_string),
            interface: None,
        }
    }

    fn alert(ip: &str, alert_type: &str) -> Alert {
        Alert {
            id: None,
            device_ip: ip.to_string(),
            alert_type: alert_type.to_string(),
            message: format!("{alert_type} on {ip}"),
            acknowledged: false,
            created_at: Utc::now(),
        }
    }

    // ── Detection ──

    #[test]
    fn unknown_ip_is_new() {
        assert_eq!(classify_device(None, "AA:BB:CC:DD:EE:FF"), DeviceStatus::New);
        assert!(DeviceStatus::New.is_new());
    }

    #[test]
    fn same_mac_is_known_case_insensitive() {
        let d = device("192.168.1.10", "aa:bb:cc:dd:ee:ff");
        assert_eq!(classify_device(Some(&d), "AA:BB:CC:DD:EE:FF"), DeviceStatus::Known);
        assert!(!DeviceStatus::Known.is_new());
    }

    #[test]
    fn different_mac_is_mac_changed() {
        let d = device("192.168.1.10", "AA:BB:CC:DD:EE:FF");
        let status = classify_device(Some(&d), "11:22:33:44:55:66");
        assert_eq!(status, DeviceStatus::MacChanged("AA:BB:CC:DD:EE:FF".into()));
        assert!(status.is_new());
    }

    #[test]
    fn placeholder_mac_is_not_a_change() {
        let d = device("192.168.1.10", PLACEHOLDER_MAC);
        assert_eq!(classify_device(Some(&d), "11:22:33:44:55:66"), DeviceStatus::Known);
        let d = device("192.168.1.10", "11:22:33:44:55:66");
        assert_eq!(classify_device(Some(&d), PLACEHOLDER_MAC), DeviceStatus::Known);
        assert_eq!(classify_device(Some(&d), ""), DeviceStatus::Known);
    }

    #[test]
    fn new_device_alert_messages() {
        let now = Utc::now();
        let e = entry("192.168.1.20", "AA:BB:CC:DD:EE:FF", Some("Raspberry Pi"));

        let a = new_device_alert(&e, &DeviceStatus::New, now).unwrap();
        assert_eq!(a.alert_type, ALERT_NEW_DEVICE);
        assert_eq!(a.device_ip, "192.168.1.20");
        assert!(!a.acknowledged);
        assert!(a.message.contains("192.168.1.20"));
        assert!(a.message.contains("AA:BB:CC:DD:EE:FF"));
        assert!(a.message.contains("Raspberry Pi"));

        let a = new_device_alert(&e, &DeviceStatus::MacChanged("11:22:33:44:55:66".into()), now)
            .unwrap();
        assert_eq!(a.alert_type, ALERT_NEW_DEVICE);
        assert!(a.message.contains("11:22:33:44:55:66"));
        assert!(a.message.contains("MAC changed"));

        assert!(new_device_alert(&e, &DeviceStatus::Known, now).is_none());
    }

    #[test]
    fn new_device_alert_without_vendor() {
        let e = entry("192.168.1.21", "AA:BB:CC:DD:EE:01", None);
        let a = new_device_alert(&e, &DeviceStatus::New, Utc::now()).unwrap();
        assert!(a.message.ends_with("192.168.1.21 (AA:BB:CC:DD:EE:01)"));
    }

    // ── Planning ──

    #[test]
    fn test_alert_title_mapping() {
        assert_eq!(alert_title("new_device"), "New device discovered");
        assert_eq!(alert_title("new_port"), "New port opened");
        assert_eq!(alert_title("device_offline"), "Device offline");
        assert_eq!(alert_title("port_closed"), "Port closed");
        assert_eq!(alert_title("unknown_type"), "SentryNet alert");
    }

    #[test]
    fn plan_empty_is_empty() {
        assert!(plan_notifications(&[]).is_empty());
    }

    #[test]
    fn plan_skips_acknowledged() {
        let mut a = alert("192.168.1.1", ALERT_NEW_DEVICE);
        a.acknowledged = true;
        assert!(plan_notifications(&[a]).is_empty());
    }

    #[test]
    fn plan_individual_and_ordered() {
        let alerts = vec![
            alert("192.168.1.5", ALERT_NEW_PORT),
            alert("192.168.1.6", ALERT_NEW_DEVICE),
        ];
        let planned = plan_notifications(&alerts);
        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0].title, "New device discovered");
        assert_eq!(planned[0].body, "new_device on 192.168.1.6");
        assert_eq!(planned[1].title, "New port opened");
    }

    #[test]
    fn plan_collapses_large_groups() {
        let mut alerts: Vec<Alert> = (1..=10)
            .map(|i| alert(&format!("192.168.1.{i}"), ALERT_NEW_DEVICE))
            .collect();
        alerts.push(alert("192.168.1.1", ALERT_NEW_PORT));
        let planned = plan_notifications(&alerts);
        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0].title, "10 new devices discovered");
        assert!(planned[0].body.starts_with("192.168.1.1, 192.168.1.2, 192.168.1.3"));
        assert!(planned[0].body.contains("and 7 more"));
        assert_eq!(planned[1].title, "New port opened");
    }

    #[test]
    fn plan_keeps_unknown_types() {
        let planned = plan_notifications(&[alert("10.0.0.1", "custom")]);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].title, "SentryNet alert");
    }

    // ── Delivery ──

    #[test]
    fn notify_with_sends_each_planned_notification() {
        let shown = Mutex::new(Vec::new());
        let sink = |n: &Notification| -> Result<(), String> {
            shown.lock().unwrap().push(n.clone());
            Ok(())
        };
        let alerts = vec![alert("192.168.1.7", ALERT_NEW_DEVICE)];
        let outcome = notify_with(true, &alerts, &sink);
        assert_eq!(outcome.sent, 1);
        assert_eq!(outcome.failed, 0);
        assert!(!outcome.skipped);
        assert_eq!(shown.lock().unwrap()[0].title, "New device discovered");
    }

    #[test]
    fn notify_with_disabled_sends_nothing() {
        let sink = |_: &Notification| -> Result<(), String> { panic!("must not be called") };
        let outcome = notify_with(false, &[alert("192.168.1.7", ALERT_NEW_DEVICE)], &sink);
        assert!(outcome.skipped);
        assert_eq!(outcome.sent, 0);
    }

    #[test]
    fn notify_with_counts_failures() {
        let sink = |_: &Notification| -> Result<(), String> { Err("no display".into()) };
        let outcome = notify_with(true, &[alert("192.168.1.7", ALERT_NEW_DEVICE)], &sink);
        assert_eq!(outcome.sent, 0);
        assert_eq!(outcome.failed, 1);
        assert_eq!(outcome.reason.as_deref(), Some("no display"));
    }

    #[test]
    fn notify_alerts_respects_config() {
        let db = Database::open_memory().unwrap();
        write_config_to_db(
            &db,
            &AppConfig {
                enable_notifications: false,
                ..AppConfig::default()
            },
        )
        .unwrap();
        let outcome = notify_alerts(&db, &[alert("192.168.1.8", ALERT_NEW_DEVICE)]);
        assert!(outcome.skipped);
        assert_eq!(outcome.reason.as_deref(), Some("notifications are disabled in config"));
    }

    #[test]
    fn notify_alerts_empty_is_skipped() {
        let db = Database::open_memory().unwrap();
        assert!(notify_alerts(&db, &[]).skipped);
    }

    #[test]
    fn test_notifications_enabled_default() {
        let db = Database::open_memory().unwrap();
        assert!(read_config_from_db(&db).enable_notifications);
    }
}
