//! SentryNet cleanup job module.
//!
//! Provides a background scheduler that periodically deletes old history
//! and acknowledged alerts based on the configured retention policy.

use crate::api::{self, AppConfig};
use crate::database::Database;
use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Default cleanup interval: every 6 hours (21 600 seconds).
pub const DEFAULT_CLEANUP_INTERVAL_SECONDS: u64 = 21_600;

/// A running cleanup scheduler. Stops when dropped.
pub struct CleanupScheduler {
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl CleanupScheduler {
    /// Start a background thread that runs cleanup at the configured interval.
    ///
    /// The scheduler reads the retention policy from the database on every
    /// iteration so that changes to `history_retention_days` take effect
    /// without a restart.
    ///
    /// If `interval_seconds` is 0 the scheduler does nothing (disabled).
    pub fn start(db_path: String, interval_seconds: u64) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);

        let thread = thread::Builder::new()
            .name("sentrynet-cleanup".to_string())
            .spawn(move || {
                if interval_seconds == 0 {
                    return;
                }
                let interval = Duration::from_secs(interval_seconds);
                loop {
                    if flag.load(Ordering::SeqCst) {
                        break;
                    }

                    // Sleep in small increments so shutdown is responsive.
                    let mut slept = Duration::ZERO;
                    while slept < interval {
                        if flag.load(Ordering::SeqCst) {
                            break;
                        }
                        let tick = interval.saturating_sub(slept).min(Duration::from_secs(1));
                        thread::sleep(tick);
                        slept += tick;
                    }

                    if flag.load(Ordering::SeqCst) {
                        break;
                    }

                    // Run the cleanup.
                    if let Err(e) = run_cleanup_once(&db_path) {
                        eprintln!("[sentrynet] cleanup job error: {e}");
                    }
                }
            })
            .expect("failed to spawn cleanup thread");

        Self {
            shutdown,
            thread: Some(thread),
        }
    }

    /// Stop the scheduler and wait for the thread to finish.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for CleanupScheduler {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Run a single cleanup pass: read the retention policy from the database
/// and delete old history and acknowledged alerts.
fn run_cleanup_once(db_path: &str) -> Result<(), String> {
    let db = Database::open(db_path).map_err(|e| format!("open db: {e}"))?;
    let config = api::read_config_from_db(&db);

    if config.history_retention_days == 0 {
        return Ok(());
    }

    let cutoff = Utc::now() - chrono::Duration::days(config.history_retention_days as i64);
    let history_deleted = db.delete_old_history(&cutoff).map_err(|e| e.to_string())?;
    let alerts_deleted = db.delete_old_alerts(&cutoff).map_err(|e| e.to_string())?;

    if history_deleted > 0 || alerts_deleted > 0 {
        println!(
            "[sentrynet] cleanup: deleted {} history records and {} alerts",
            history_deleted, alerts_deleted
        );
    }

    Ok(())
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api;
    use crate::database;
    use chrono::Duration as ChronoDuration;
    use std::path::PathBuf;

    /// A temp database file removed on drop.
    struct TempDb(PathBuf);

    impl TempDb {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sentrynet_cleanup_{}_{}.sqlite",
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

    #[test]
    fn test_run_cleanup_once_deletes_old_records() {
        let tmp = TempDb::new("once");
        let db = tmp.db();

        // Insert an old history record (100 days old).
        let old_ts = Utc::now() - ChronoDuration::days(100);
        db.conn
            .execute(
                "INSERT INTO history (device_ip, event_type, details, timestamp) \
                 VALUES ('192.168.1.1', 'discovered', 'old', ?1)",
                [old_ts.to_rfc3339()],
            )
            .unwrap();

        // Insert a recent history record.
        db.append_history(&database::HistoryRecord {
            id: None,
            device_ip: "192.168.1.1".to_string(),
            event_type: "discovered".to_string(),
            details: Some("recent".to_string()),
            timestamp: Utc::now(),
        })
        .unwrap();

        // Insert an old acknowledged alert (100 days old).
        let old_alert_ts = Utc::now() - ChronoDuration::days(100);
        let old_alert = database::Alert {
            id: None,
            device_ip: "192.168.1.1".to_string(),
            alert_type: "new_device".to_string(),
            message: "old alert".to_string(),
            acknowledged: true,
            created_at: old_alert_ts,
        };
        let old_id = db.create_alert(&old_alert).unwrap();
        db.acknowledge_alert(old_id).unwrap();

        // Insert a recent unacknowledged alert.
        db.create_alert(&database::Alert {
            id: None,
            device_ip: "192.168.1.1".to_string(),
            alert_type: "new_device".to_string(),
            message: "recent alert".to_string(),
            acknowledged: false,
            created_at: Utc::now(),
        })
        .unwrap();

        // Set retention to 30 days.
        api::write_config_to_db(&db, &AppConfig {
            history_retention_days: 30,
            ..AppConfig::default()
        })
        .unwrap();

        // Run cleanup.
        run_cleanup_once(tmp.path()).unwrap();

        // Old history should be gone, recent should remain.
        assert_eq!(db.history_count().unwrap(), 1);

        // Old acknowledged alert should be gone, recent unacknowledged should remain.
        assert_eq!(db.alert_count().unwrap(), 1);
    }

    #[test]
    fn test_run_cleanup_once_respects_zero_retention() {
        let tmp = TempDb::new("zero");
        let db = tmp.db();

        let old_ts = Utc::now() - ChronoDuration::days(1000);
        db.conn
            .execute(
                "INSERT INTO history (device_ip, event_type, details, timestamp) \
                 VALUES ('192.168.1.1', 'discovered', 'ancient', ?1)",
                [old_ts.to_rfc3339()],
            )
            .unwrap();

        api::write_config_to_db(&db, &AppConfig {
            history_retention_days: 0,
            ..AppConfig::default()
        })
        .unwrap();

        run_cleanup_once(tmp.path()).unwrap();

        // Nothing should be deleted when retention is 0.
        assert_eq!(db.history_count().unwrap(), 1);
    }

    #[test]
    fn test_run_cleanup_once_no_records() {
        let tmp = TempDb::new("empty");
        run_cleanup_once(tmp.path()).unwrap();
        // Should not panic on empty db.
    }

    #[test]
    fn test_cleanup_scheduler_stops() {
        let tmp = TempDb::new("stop");
        let db_path = tmp.path().to_string();

        // Start with a short interval (1 second).
        let mut scheduler = CleanupScheduler::start(db_path, 1);

        // Let it run briefly.
        thread::sleep(std::time::Duration::from_secs(2));

        // Stop it.
        scheduler.stop();

        // After stop, no more cleanup should happen.
        // We can't easily verify this without waiting, but at least
        // the thread should have joined without panicking.
    }

    #[test]
    fn test_cleanup_scheduler_disabled_with_zero_interval() {
        let tmp = TempDb::new("disabled");
        let db_path = tmp.path().to_string();

        let mut scheduler = CleanupScheduler::start(db_path, 0);

        // Should stop immediately since interval is 0.
        scheduler.stop();
    }

    #[test]
    fn test_cleanup_scheduler_respects_retention_change() {
        let tmp = TempDb::new("change");
        let db = tmp.db();
        let db_path = tmp.path().to_string();

        // Insert a record that is 10 days old.
        let old_ts = Utc::now() - ChronoDuration::days(10);
        db.conn
            .execute(
                "INSERT INTO history (device_ip, event_type, details, timestamp) \
                 VALUES ('192.168.1.1', 'discovered', 'old', ?1)",
                [old_ts.to_rfc3339()],
            )
            .unwrap();

        // Set retention to 30 days (should NOT delete 10-day-old record).
        api::write_config_to_db(&db, &AppConfig {
            history_retention_days: 30,
            ..AppConfig::default()
        })
        .unwrap();

        // Start scheduler with 1-second interval.
        let mut scheduler = CleanupScheduler::start(db_path.clone(), 1);

        // Wait for at least one cleanup cycle.
        thread::sleep(std::time::Duration::from_secs(2));

        // 10-day-old record should still be there (retention is 30 days).
        assert_eq!(db.history_count().unwrap(), 1);

        // Now change retention to 5 days (should delete 10-day-old record).
        api::write_config_to_db(&db, &AppConfig {
            history_retention_days: 5,
            ..AppConfig::default()
        })
        .unwrap();

        // Wait for another cleanup cycle.
        thread::sleep(std::time::Duration::from_secs(2));

        // 10-day-old record should now be deleted.
        assert_eq!(db.history_count().unwrap(), 0);

        scheduler.stop();
    }
}
