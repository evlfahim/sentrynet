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
┌──────────────────────────────────────────────────────┐
│                    SentryNet App                      │
├──────────────────┬───────────────────────────────────┤
│  Desktop (Tauri) │       Web Dashboard               │
│  ┌────────────┐  │   ┌─────────────────────────────┐ │
│  │  Electron- │  │   │  Browser (any)              │ │
│  │  like UI   │  │   │  └─────────────────────────┘ │
│  └─────┬──────┘  │   ┌─────────────────────────────┐ │
│        │         │   │  Local REST API (port 7357) │ │
│  ┌─────▼──────┐  │   └─────────────┬───────────────┘ │
│  │ Tauri Cmds │  │   │             │                 │
│  └─────┬──────┘  │   │             │                 │
│        │         │   │             │                 │
│  ┌─────▼──────┐  │   │             │                 │
│  │ Core Scan  │◄─┼───┼─────────────┤                 │
│  │ Service    │  │   │             │                 │
│  └─────┬──────┘  │   │             │                 │
│        │         │   │             │                 │
│  ┌─────▼──────┐  │   │             │                 │
│  │ SQLite DB  │  │   │             │                 │
│  └────────────┘  │   └───────────────────────────────┘ │
├──────────────────┴───────────────────────────────────┤
│  Rust Backend (Tauri v2)                             │
│  ├── arp.rs          (ARP device discovery)           │
│  ├── port_scan.rs    (TCP port scanning)              │
│  ├── latency.rs      (ICMP + HTTP latency checks)     │
│  ├── core.rs         (scan orchestration)             │
│  ├── database.rs     (SQLite schema & queries)        │
│  ├── alerts.rs       (alert detection & notifications)│
│  ├── api.rs          (Tauri command handlers)         │
│  └── rest_server.rs  (local HTTP API server)          │
└──────────────────────────────────────────────────────┘
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

The local server exposes these endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/info` | Server info and status |
| `POST` | `/api/scan` | Run a full LAN scan |
| `POST` | `/api/scan/host` | Scan a single host |
| `POST` | `/api/scan/ports` | Port scan hosts |
| `POST` | `/api/scan/latency` | Latency check hosts |
| `GET` | `/api/devices` | List all devices |
| `GET` | `/api/devices/:ip` | Get device details |
| `GET` | `/api/devices/:ip/ports` | Get device ports |
| `GET` | `/api/ports` | List all ports |
| `GET` | `/api/devices/:ip/history` | Device history |
| `GET` | `/api/history` | Full history timeline |
| `GET` | `/api/alerts` | List alerts |
| `GET` | `/api/alerts?unacknowledged=true` | Unacknowledged alerts |
| `POST` | `/api/alerts/:id/ack` | Acknowledge an alert |
| `GET` | `/api/config` | Get scan configuration |
| `PUT` | `/api/config` | Update configuration |
| `GET` | `/api/stats` | Scan statistics |
| `GET` | `/api/export/devices.json` | Export devices as JSON |
| `GET` | `/api/export/ports.json` | Export ports as JSON |
| `GET` | `/api/export/history.json` | Export history as JSON |
| `GET` | `/api/export/devices.csv` | Export devices as CSV |
| `GET` | `/api/export/ports.csv` | Export ports as CSV |
| `GET` | `/api/export/history.csv` | Export history as CSV |
| `POST` | `/api/cleanup` | Delete old history/alerts |
| `POST` | `/api/notifications/resend` | Resend pending alerts |
| `POST` | `/api/notifications/test` | Send a test notification |

### Tauri Commands

The desktop app also exposes these Rust commands via Tauri's IPC:

- `arpScan(cidr?, settleMs?)` — Discover active hosts
- `tcpScan(hosts, ports?, timeoutMs?, concurrency?, serviceDetection?)` — Port scan
- `checkLatency(hosts, pingCount?, pingTimeoutMs?, httpPort?, httpPath?, httpTimeoutMs?)` — Latency check
- `fullScan(dbPath, ...)` — Full scan with database persistence and alerts
- `scanSingleHost(dbPath, host, ...)` — Scan one host without ARP

## Configuration

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
| `history_retention_days` | 0 | History retention (0 = unlimited) |
| `enable_notifications` | true | Enable desktop/browser notifications |
| `auto_scan_interval_seconds` | 0 | Auto-scan interval (0 = disabled) |

Alert rules (checkboxes):

- New device discovered
- New open port
- Device goes offline
- Open port closes

## Data Storage

All data is stored in a local SQLite database at:

- **Linux**: `~/.local/share/com.sentrynet.desktop/sentrynet.db`
- **macOS**: `~/Library/Application Support/com.sentrynet.desktop/sentrynet.db`
- **Windows**: `%APPDATA%\com.sentrynet.desktop\sentrynet.db`

## Plugin Integration Architecture

SentryNet is designed as a modular scanner with a clean separation between:

1. **Scanner modules** (`arp.rs`, `port_scan.rs`, `latency.rs`) — Pure functions that take options and return results. No I/O, no side effects.
2. **Core service** (`core.rs`) — Orchestrates scanner modules, persists results to the database, and generates alerts.
3. **API layer** (`api.rs`, `rest_server.rs`) — Exposes scanner functionality via Tauri commands and a local REST API.
4. **Notification layer** (`alerts.rs`) — Pluggable notification system supporting desktop (Tauri) and browser notifications.

To add a new scanner module:

1. Create a new `.rs` file with a public function that takes options and returns a result.
2. Add a `#[tauri::command]` wrapper in `lib.rs` or a handler in `api.rs`.
3. Register the command in the `tauri::generate_handler![]` macro.
4. Add a tab or section in `dashboard.ts` and `index.html`.

## License

Private project — all rights reserved.
