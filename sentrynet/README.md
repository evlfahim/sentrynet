# SentryNet — LAN Security Scanner

A cross-platform desktop application and local web dashboard for scanning your home LAN. Discover devices, scan open ports, measure latency, and track history — all stored locally in SQLite with zero external dependencies.

## Features

- **Device Discovery** — ARP scan to find active IPs, MAC addresses, and vendor names on your LAN
- **Port Scanning** — TCP port scan per device with service detection
- **Latency Tracking** — ICMP ping and HTTP HEAD response time measurement
- **Persistent History** — SQLite database stores device connections, disconnections, and port changes
- **Real-time Alerts** — Desktop notifications on new devices (Tauri) or browser notifications (web dashboard)
- **Web Dashboard** — Local REST API serves a full-featured dashboard in any browser
- **Data Export** — Export devices, ports, and history as JSON or CSV
- **Configurable** — Scan intervals, port ranges, alert rules, and history retention
- **Zero Cloud** — All data stays on your machine; no accounts or paid services

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        SentryNet App                              │
├──────────────────┬───────────────────────────────────────────────┤
│  Desktop (Tauri) │              Web Dashboard                    │
│  ┌────────────┐  │   ┌─────────────────────────────────────────┐ │
│  │  Tauri    │  │   │  Browser (any)                           │ │
│  │  Webview  │  │   │  ──────────────────────────────────────  │ │
│  └─────┬─────┘  │   └─────────────────────┬───────────────────┘ │
│        │       │                         │                       │
│  ┌─────▼─────┐  │   ┌─────────────────────▼───────────────────┐  │
│  │ Tauri    │  │   │  Local REST API (127.0.0.1:7357)        │  │
│  │ Commands │  │   │  (plain HTTP/1.1, no framework)          │  │
│  └─────┬─────┘  │   └─────────────────────┬───────────────────┘  │
│        │       │                         │                       │
│  ┌─────▼─────┐  │   ┌─────────────────────▼───────────────────┐  │
│  │ Core Scan │◄─┼───┤  Shared handler layer (api.rs)          │  │
│  │ Service   │  │   └─────────────────────┬───────────────────┘  │
│  └─────┬─────┘  │                         │                       │
│        │       │   ┌─────────────────────▼───────────────────┐  │
│  ┌─────▼─────┐  │   │  Background services                   │  │
│  │ SQLite DB │  │   │  ├── CleanupScheduler (periodic)       │  │
│  └───────────┘  │   │  └── Notification delivery             │  │
├──────────────────┴───────────────────────────────────────────────┤
│  Rust Backend (Tauri v2)                                         │
│  ├── arp.rs          (ARP device discovery)                      │
│  ├── port_scan.rs    (TCP port scanning)                         │
│  ├── latency.rs      (ICMP + HTTP latency checks)                │
│  ├── core.rs         (scan orchestration)                        │
│  ├── database.rs     (SQLite schema & queries)                   │
│  ├── alerts.rs       (alert detection & notifications)           │
│  ├── api.rs          (Tauri command handlers + REST handlers)    │
│  ├── rest_server.rs  (local HTTP API server)                     │
│  └── cleanup.rs      (periodic history cleanup scheduler)        │
└──────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- **Node.js 22+** and **npm**
- **Rust 1.75+** (via [rustup](https://rustup.rs/))
- **Linux**: `libwebkit2gtk-4.1`, `libgtk-3`, `libayatana-appindicator3-dev`
- **macOS**: Xcode Command Line Tools
- **Windows**: Visual Studio Build Tools + WebView2

### Install Dependencies

```bash
cd sentrynet
npm install
```

### Run in Development Mode

```bash
npm run dev
```

This starts the Tauri development server with hot-reload. The app opens at `http://localhost:1420` and the REST API listens on `http://127.0.0.1:7357`.

### Build for Production

```bash
npm run build
```

This compiles the Rust backend in release mode and bundles the application.

### Run Tests

```bash
# TypeScript tests
npm run test

# Rust tests
cd src-tauri && cargo test
```

## Bundled Formats

The `npm run build` command produces three Linux packages:

| Format | File | Size |
|--------|------|------|
| Debian | `SentryNet_0.1.0_amd64.deb` | ~7 MB |
| RPM | `SentryNet-0.1.0-1.x86_64.rpm` | ~7 MB |
| AppImage | `SentryNet_0.1.0_amd64.AppImage` | ~98 MB |

Install a `.deb` with:

```bash
sudo dpkg -i target/x86_64-unknown-linux-gnu/release/bundle/deb/SentryNet_0.1.0_amd64.deb
```

## Usage

### Desktop App

Launch SentryNet from your application menu or run:

```bash
sentrynet
```

The app window shows:

- **Devices** tab — table of discovered LAN devices with IPs, MACs, names, open ports, and latency
- **Ports** tab — all open ports across all devices
- **Latency** tab — ICMP and HTTP response times
- **History** tab — timeline of device events (connect/disconnect/port changes)
- **Alerts** tab — unacknowledged alerts (new devices, new ports, offline devices)
- **Settings** tab — scan configuration, alert rules, and data maintenance

### Web Dashboard

Open your browser to the REST API URL shown in the console:

```
http://127.0.0.1:7357
```

The dashboard is fully functional without the desktop app. Browser notifications work when permission is granted.

### REST API

The local server exposes these endpoints (all responses use the JSON envelope `{"success": true/false, "data": ..., "error": ...}`):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api` | Route list |
| `GET` | `/api/health` | Liveness check (`{"status":"ok","version":"0.1.0"}`) |
| `GET` | `/api/server_info` | Database path and REST URL |
| `POST` | `/api/scan` | Run a full LAN scan (body: `ScanRequest`) |
| `POST` | `/api/scan/host` | Scan a single host (body: `{host, ...ScanRequest}`) |
| `POST` | `/api/scan/ports` | Ad-hoc TCP port scan (body: `PortScanRequest`) |
| `POST` | `/api/scan/latency` | Ad-hoc latency check (body: `LatencyRequest`) |
| `GET` | `/api/devices` | List all devices |
| `GET` | `/api/devices/:ip` | Get device details |
| `GET` | `/api/devices/:ip/ports` | Get device ports |
| `GET` | `/api/devices/:ip/history` | Device history (`?limit=`) |
| `GET` | `/api/devices/:ip/alerts` | Device alerts |
| `GET` | `/api/ports` | List all open ports |
| `GET` | `/api/history` | Full history timeline (`?limit=&event_type=`) |
| `GET` | `/api/alerts` | List alerts (`?acknowledged=&limit=`) |
| `POST` | `/api/alerts/:id/ack` | Acknowledge an alert |
| `GET` | `/api/config` | Get scan configuration |
| `PUT` | `/api/config` | Update configuration (partial allowed) |
| `GET` | `/api/stats` | Scan statistics (device/port/alert/history counts) |
| `GET` | `/api/export/devices` | Export devices as JSON |
| `GET` | `/api/export/devices.csv` | Export devices as CSV |
| `GET` | `/api/export/ports` | Export ports as JSON |
| `GET` | `/api/export/ports.csv` | Export ports as CSV |
| `GET` | `/api/export/history` | Export history as JSON (`?limit=`) |
| `GET` | `/api/export/history.csv` | Export history as CSV |
| `POST` | `/api/cleanup` | Delete old history and acknowledged alerts |
| `GET` | `/api/cleanup/status` | Cleanup scheduler status |
| `GET` | `/api/notifications/unacknowledged` | Count of unacknowledged alerts |
| `POST` | `/api/notifications/resend` | Re-send notifications for pending alerts |
| `POST` | `/api/notifications/test` | Send a test notification |

#### Example: Run a full scan

```bash
curl -X POST http://127.0.0.1:7357/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"cidr": "192.168.1.0/24"}'
```

#### Example: List devices

```bash
curl http://127.0.0.1:7357/api/devices
```

#### Example: Acknowledge an alert

```bash
curl -X POST http://127.0.0.1:7357/api/alerts/1/ack
```

#### Example: Export devices as CSV

```bash
curl -o devices.csv http://127.0.0.1:7357/api/export/devices.csv
```

### Tauri Commands

The desktop app also exposes these Rust commands via Tauri's IPC (invoked from the frontend with `invoke('command_name', ...)`):

| Command | Parameters | Returns |
|---------|-----------|---------|
| `arpScan` | `cidr?`, `settleMs?` | `ArpEntry[]` |
| `tcpScan` | `hosts`, `ports?`, `timeoutMs?`, `concurrency?`, `serviceDetection?` | `HostScanResult[]` |
| `checkLatency` | `hosts`, `pingCount?`, `pingTimeoutMs?`, `httpPort?`, `httpPath?`, `httpTimeoutMs?` | `HostLatencyResult[]` |
| `fullScan` | `dbPath`, `cidr?`, `arpSettleMs?`, `portScanTimeoutMs?`, `portScanConcurrency?`, `portServiceDetection?`, `pingCount?`, `pingTimeoutMs?`, `httpPort?`, `httpPath?`, `httpTimeoutMs?`, `checkLatency?` | `FullScanResult` |
| `scanSingleHost` | `dbPath`, `host`, `portScanTimeoutMs?`, `portScanConcurrency?`, `portServiceDetection?`, `pingCount?`, `pingTimeoutMs?`, `httpPort?`, `httpPath?`, `httpTimeoutMs?`, `checkLatency?` | `ScannedDevice` |

### Configuration

Edit settings in the Settings tab or via the REST API:

```bash
curl http://127.0.0.1:7357/api/config
```

Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `default_cidr` | — | Default CIDR for ARP scan (e.g. `192.168.1.0/24`) |
| `arp_settle_ms` | 1500 | ARP probe settle time in milliseconds |
| `port_scan_timeout_ms` | 3000 | Port scan timeout per host |
| `port_scan_concurrency` | 100 | Concurrent port scan connections |
| `port_scan_ports` | — | Custom port list (e.g. `22,80,443,8080-8090`) |
| `port_service_detection` | true | Detect service names from ports |
| `ping_count` | 3 | ICMP ping count per host |
| `ping_timeout_ms` | 1000 | ICMP ping timeout |
| `http_port` | 80 | HTTP HEAD port |
| `http_path` | `/` | HTTP HEAD path |
| `http_timeout_ms` | 2000 | HTTP HEAD timeout |
| `check_latency` | true | Enable latency checks |
| `history_retention_days` | 90 | History retention (0 = unlimited) |
| `enable_notifications` | true | Enable desktop/browser notifications |
| `auto_scan_interval_seconds` | 0 | Auto-scan interval (0 = disabled) |
| `cleanup_interval_seconds` | 21600 | Cleanup scheduler interval (0 = disabled) |

Alert rules (checkboxes):

- **New device discovered** — fires when an IP has never been seen before, or when a known IP's MAC address changes
- **New open port** — fires when a previously unseen port opens on a known device
- **Device goes offline** — fires when a known device stops responding to ARP
- **Open port closes** — fires when a previously open port is no longer detected

## Data Storage

All data is stored in a local SQLite database at:

- **Linux**: `~/.local/share/com.sentrynet.desktop/sentrynet.sqlite`
- **macOS**: `~/Library/Application Support/com.sentrynet.desktop/sentrynet.sqlite`
- **Windows**: `%APPDATA%\com.sentrynet.desktop\sentrynet.sqlite`

The database contains four tables:

| Table | Description |
|-------|-------------|
| `devices` | One row per unique IP (mac, name, vendor, first/last seen) |
| `ports` | One row per open port per device (port, protocol, state, service) |
| `history` | Append-only log of state changes (discovered, disconnected, port_added, port_removed) |
| `alerts` | Actionable notifications (new_device, new_port, device_offline, port_closed) |
| `config` | Key-value store for application settings |

## Plugin Integration Architecture

SentryNet is designed as a modular scanner with a clean separation between layers. This makes it straightforward to add new scanner types, integrate with external monitoring systems, or embed the scanner library in another application.

### Layer Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend (Tauri Webview / Browser)                         │
│  └── invoke() / fetch() calls to api layer                  │
├─────────────────────────────────────────────────────────────┤
│  API Layer (api.rs)                                         │
│  ├── Tauri command handlers (invoke handlers)               │
│  ├── REST route handlers (rest_server.rs)                    │
│  └── Shared business logic (handle_scan, handle_get_*)      │
├─────────────────────────────────────────────────────────────┤
│  Core Service (core.rs)                                     │
│  ├── full_scan() — orchestrates ARP → ports → latency       │
│  ├── scan_single_host() — scan one host without ARP         │
│  └── Device classification (new / known / mac_changed)      │
├─────────────────────────────────────────────────────────────┤
│  Scanner Modules (pure functions, no I/O)                   │
│  ├── arp.rs   — ArpScanOptions → ArpEntry[]                 │
│  ├── port_scan.rs — TcpScanOptions → HostScanResult[]       │
│  └── latency.rs — LatencyCheckOptions → HostLatencyResult[] │
├─────────────────────────────────────────────────────────────┤
│  Persistence (database.rs)                                  │
│  └── SQLite CRUD for devices, ports, history, alerts, config│
├─────────────────────────────────────────────────────────────┤
│  Notifications (alerts.rs)                                  │
│  ├── classify_device() — device status detection            │
│  ├── plan_notifications() — alert → notification mapping    │
│  ├── notify_alerts() — delivery via installed Notifier      │
│  └── set_notifier() — pluggable delivery callback           │
└─────────────────────────────────────────────────────────────┘
```

### Adding a New Scanner Module

1. **Create a new `.rs` file** in `src-tauri/src/` with a public function that takes options and returns a result:

   ```rust
   pub struct MyScanOptions {
       pub hosts: Vec<String>,
       // ... other options
   }

   pub struct MyScanResult {
       pub host: String,
       pub result: String,
   }

   pub fn my_scan(options: &MyScanOptions) -> Result<Vec<MyScanResult>, MyScanError> {
       // Pure computation / network I/O
       Ok(results)
   }
   ```

2. **Add a Tauri command** in `src-tauri/src/lib.rs`:

   ```rust
   #[tauri::command]
   async fn my_scan_cmd(hosts: Vec<String>) -> Result<Vec<MyScanResult>, String> {
       let options = MyScanOptions { hosts };
       tauri::async_runtime::spawn_blocking(move || my_scan(&options))
           .await
           .map_err(|e| e.to_string())?
           .map_err(|e| e.to_string())
   }
   ```

3. **Register the command** in the `tauri::generate_handler![]` macro in `lib.rs`.

4. **Add a REST route** in `src-tauri/src/rest_server.rs` if you want web dashboard access.

5. **Add a tab or section** in `src/index.html` and `src/dashboard.ts` for the UI.

### Embedding the Scanner Library

The Rust code is compiled as a static library (`crate-type = ["staticlib", "cdylib", "rlib"]`), so it can be linked from other Rust projects. The scanner modules (`arp.rs`, `port_scan.rs`, `latency.rs`) are pure functions with no global state — they can be called directly:

```rust
use sentrynet_lib::arp;
use sentrynet_lib::port_scan;
use sentrynet_lib::latency;

fn main() {
    let entries = arp::arp_scan(&arp::ArpScanOptions {
        cidr: Some("192.168.1.0/24".into()),
        probe: true,
        settle: std::time::Duration::from_millis(1500),
    }).unwrap();

    let results = port_scan::tcp_scan(&port_scan::TcpScanOptions {
        hosts: vec!["192.168.1.1".into()],
        ports: vec![22, 80, 443],
        timeout_ms: 3000,
        concurrency: 100,
        service_detection: true,
    }).unwrap();
}
```

### Pluggable Notifications

The notification system uses a callback-based approach. Any code can install a notifier:

```rust
use sentrynet_lib::alerts;

// Install a custom notifier
alerts::set_notifier(Arc::new(|notification: &alerts::Notification| {
    println!("{}: {}", notification.title, notification.body);
    Ok(())
}));

// Later, alerts will be delivered through this callback
```

The desktop app installs a notifier backed by the Tauri notification plugin at startup. Without one (unit tests, headless use), delivery is a no-op.

### Security

The REST server binds to `127.0.0.1` by default, preventing remote access. It also:

- **Rejects non-loopback `Host` headers** — DNS rebinding protection
- **Validates `Origin` headers** — only allows `tauri://localhost`, `http://localhost`, `https://localhost`, and `http://127.0.0.1`
- **Validates all host inputs** — rejects special characters, leading dashes, and overly long values
- **Limits request body size** — 1 MB maximum
- **Uses a scan lock** — only one database-writing scan runs at a time (409 Conflict if another is in progress)

## License

Private project — all rights reserved.
