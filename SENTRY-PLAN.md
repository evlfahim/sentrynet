# SentryNet

> A cross-platform LAN security scanner providing device discovery, port scanning, latency tracking, and persistent history via a lightweight desktop app and web dashboard, with zero external dependencies.

Task: Network device scanner for the home LAN: lists devices with names, open ports and response times, saves history and alerts on new devices #desktop #web

## Why it is better than what exists
- aceberg/WatchYourLAN
- CWS6206/EasyNetworkScanner

## Features
- Device discovery with names, IPs, and MAC addresses
- Open port scanning per device with service detection
- Response time measurement via ICMP and HTTP checks
- Persistent history of device connections, disconnections, and port changes
- Real-time alerts on new devices with desktop notifications
- Desktop application and local web dashboard
- Local SQLite storage with no cloud or paid services
- Data export to CSV/JSON and history retention policies
- Configurable scan intervals, port ranges, and alert rules

## Stack
Node.js, TypeScript, Tauri, SQLite, Nmap

## Steps
- [x] 1. Initialize Tauri project with TypeScript, install dependencies (sqlite3, nmap, axios), and run initial test suite to verify build environment.
- [x] 2. Create SQLite schema for devices, ports, history, and alerts with indexes for efficient querying.
- [x] 3. Implement ARP scan function to discover active IPs, MAC addresses, and vendor names.
- [x] 4. Implement TCP port scanner using Nmap or raw sockets to detect open ports and services.
- [x] 5. Implement latency checker using ICMP ping and HTTP HEAD requests for response times.
- [x] 6. Combine modules into a core scanner service that aggregates device data and updates the database.
- [x] 7. Build REST API endpoints for scanning, fetching device list, history, alerts, and configuration.
- [x] 8. Develop Web UI dashboard with device table, port details, latency graphs, and history timeline.
- [x] 9. Add alert logic to detect new devices and trigger desktop notifications via Tauri.
- [x] 10. Create settings page for scan intervals, port lists, notification preferences, and history retention.
- [x] 11. Add data export feature to save history and device lists as CSV or JSON files.
- [ ] 12. Write unit tests for scanner modules, API handlers, and database operations.
- [ ] 13. Configure Tauri build scripts and bundle the desktop application for target OS.
- [ ] 14. Test desktop app functionality, verify local web server access, and validate alert mechanisms.
- [ ] 15. Implement history cleanup job to archive or delete old records based on retention policy.
- [ ] 16. Write README with setup instructions, usage guide, and plugin integration architecture note.
