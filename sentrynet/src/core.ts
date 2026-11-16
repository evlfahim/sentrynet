/**
 * SentryNet - Core scanner service bindings.
 *
 * Orchestrates the full scan pipeline:
 * 1. ARP discovery → active hosts with MAC/vendor
 * 2. TCP port scanning on discovered hosts
 * 3. Latency measurement (ICMP + HTTP HEAD)
 * 4. Database persistence (devices, ports, history, alerts)
 * 5. Alert generation for new devices and port changes
 */

import { invoke } from '@tauri-apps/api/core';
import { PortResult, HostScanResult, WELL_KNOWN_SERVICES, DEFAULT_PORTS } from './port_scan';
import { LatencySample, HostLatencyResult } from './latency';
import { ArpEntry } from './arp';

// ──────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────

/** A device discovered during a full scan, enriched with port and latency data. */
export interface ScannedDevice {
  /** IP address. */
  ip: string;
  /** MAC address. */
  mac: string;
  /** Vendor name from OUI lookup. */
  vendor: string | null;
  /** Interface name. */
  interface: string | null;
  /** Open ports found on this device. */
  openPorts: PortResult[];
  /** Latency results for this device. */
  latency: HostLatencyResult | null;
  /** Whether this device was seen before (false = new). */
  isNew: boolean;
}

/** Configuration for a full network scan. */
export interface FullScanOptions {
  /** Subnet CIDR for ARP discovery (e.g. "192.168.1.0/24"). Defaults to local /24. */
  cidr?: string;
  /** ARP settle time in milliseconds (default 1500). */
  arpSettleMs?: number;
  /** TCP scan timeout per port in milliseconds (default 1000). */
  portScanTimeoutMs?: number;
  /** TCP scan concurrency (default 64). */
  portScanConcurrency?: number;
  /** Whether to attempt banner-based service detection (default true). */
  portServiceDetection?: boolean;
  /** Number of ICMP ping probes per host (default 4). */
  pingCount?: number;
  /** ICMP ping timeout per probe in milliseconds (default 3000). */
  pingTimeoutMs?: number;
  /** HTTP HEAD port (default 80). */
  httpPort?: number;
  /** HTTP HEAD path (default "/"). */
  httpPath?: string;
  /** HTTP HEAD timeout in milliseconds (default 3000). */
  httpTimeoutMs?: number;
  /** Whether to check latency for discovered devices (default true). */
  checkLatency?: boolean;
}

/** Result of a full network scan. */
export interface FullScanResult {
  /** Total time taken for the scan in milliseconds. */
  elapsedMs: number;
  /** Number of devices discovered. */
  deviceCount: number;
  /** Number of new devices (not seen before). */
  newDeviceCount: number;
  /** Total open ports across all devices. */
  totalOpenPorts: number;
  /** Number of alerts generated. */
  alertCount: number;
  /** Discovered devices with their scan data. */
  devices: ScannedDevice[];
  /** Alerts generated during this scan. */
  alerts: Alert[];
  /** History records created during this scan. */
  history: HistoryRecord[];
}

/** An alert triggered by the system. */
export interface Alert {
  id: number | null;
  deviceIp: string;
  alertType: 'new_device' | 'new_port' | 'device_offline' | 'port_closed';
  message: string;
  acknowledged: boolean;
  createdAt: string;
}

/** A history record capturing a device state change. */
export interface HistoryRecord {
  id: number | null;
  deviceIp: string;
  eventType:
    | 'discovered'
    | 'disconnected'
    | 'port_added'
    | 'port_removed'
    | 'port_state_changed'
    | 'seen';
  details: string | null;
  timestamp: string;
}

/** Options for scanning a single host. */
export interface SingleHostScanOptions {
  /** TCP scan timeout per port in milliseconds (default 1000). */
  portScanTimeoutMs?: number;
  /** TCP scan concurrency (default 64). */
  portScanConcurrency?: number;
  /** Whether to attempt banner-based service detection (default true). */
  portServiceDetection?: boolean;
  /** Number of ICMP ping probes (default 4). */
  pingCount?: number;
  /** ICMP ping timeout per probe in milliseconds (default 3000). */
  pingTimeoutMs?: number;
  /** HTTP HEAD port (default 80). */
  httpPort?: number;
  /** HTTP HEAD path (default "/"). */
  httpPath?: string;
  /** HTTP HEAD timeout in milliseconds (default 3000). */
  httpTimeoutMs?: number;
  /** Whether to check latency (default true). */
  checkLatency?: boolean;
}

// ──────────────────────────────────────────────
// Default options
// ──────────────────────────────────────────────

/** Default full scan options. */
export const DEFAULT_SCAN_OPTIONS: FullScanOptions = {
  arpSettleMs: 1500,
  portScanTimeoutMs: 1000,
  portScanConcurrency: 64,
  portServiceDetection: true,
  pingCount: 4,
  pingTimeoutMs: 3000,
  httpPort: 80,
  httpPath: '/',
  httpTimeoutMs: 3000,
  checkLatency: true,
};

// ──────────────────────────────────────────────
// API functions
// ──────────────────────────────────────────────

/**
 * Run a full network scan: ARP discovery, port scanning, latency check,
 * database persistence, and alert generation.
 *
 * @param dbPath - Path to the SQLite database file.
 * @param options - Scan configuration options.
 * @returns The full scan result with devices, alerts, and history.
 */
export async function fullScan(
  dbPath: string,
  options: FullScanOptions = {},
): Promise<FullScanResult> {
  const merged = { ...DEFAULT_SCAN_OPTIONS, ...options };
  return invoke<FullScanResult>('full_scan', {
    dbPath,
    cidr: merged.cidr ?? null,
    arpSettleMs: merged.arpSettleMs ?? null,
    portScanTimeoutMs: merged.portScanTimeoutMs ?? null,
    portScanConcurrency: merged.portScanConcurrency ?? null,
    portServiceDetection: merged.portServiceDetection ?? null,
    pingCount: merged.pingCount ?? null,
    pingTimeoutMs: merged.pingTimeoutMs ?? null,
    httpPort: merged.httpPort ?? null,
    httpPath: merged.httpPath ?? null,
    httpTimeoutMs: merged.httpTimeoutMs ?? null,
    checkLatency: merged.checkLatency ?? null,
  });
}

/**
 * Scan a single host by IP: port scan + latency check, without ARP.
 * Useful for targeted scans and testing.
 *
 * @param dbPath - Path to the SQLite database file.
 * @param host - IP address or hostname to scan.
 * @param options - Scan configuration options.
 * @returns The scanned device with port and latency data.
 */
export async function scanSingleHost(
  dbPath: string,
  host: string,
  options: SingleHostScanOptions = {},
): Promise<ScannedDevice> {
  const merged = { ...DEFAULT_SCAN_OPTIONS, ...options };
  return invoke<ScannedDevice>('scan_single_host', {
    dbPath,
    host,
    portScanTimeoutMs: merged.portScanTimeoutMs ?? null,
    portScanConcurrency: merged.portScanConcurrency ?? null,
    portServiceDetection: merged.portServiceDetection ?? null,
    pingCount: merged.pingCount ?? null,
    pingTimeoutMs: merged.pingTimeoutMs ?? null,
    httpPort: merged.httpPort ?? null,
    httpPath: merged.httpPath ?? null,
    httpTimeoutMs: merged.httpTimeoutMs ?? null,
    checkLatency: merged.checkLatency ?? null,
  });
}
