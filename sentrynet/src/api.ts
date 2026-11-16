/**
 * SentryNet - REST API bindings.
 *
 * Two ways to reach the same backend handlers (src-tauri/src/api.rs):
 * - `invoke`-based functions for the desktop window (Tauri commands `api_*`).
 * - `RestClient` for the local HTTP server (src-tauri/src/rest_server.rs),
 *   used by the web dashboard.
 *
 * Both return the unwrapped `data` of the `{ success, data, error }` envelope
 * and throw `ApiError` on failure.
 *
 * Field names below match the JSON the Rust backend actually sends (snake_case).
 */

import { invoke } from '@tauri-apps/api/core';

// ──────────────────────────────────────────────
// Wire types
// ──────────────────────────────────────────────

/** Envelope returned by every endpoint. */
export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  error: string | null;
}

export interface Device {
  ip: string;
  mac: string;
  name: string | null;
  vendor: string | null;
  last_seen: string;
  first_seen: string;
}

export interface Port {
  device_ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  service: string | null;
}

export interface HistoryRecord {
  id: number | null;
  device_ip: string;
  event_type: string;
  details: string | null;
  timestamp: string;
}

export interface Alert {
  id: number | null;
  device_ip: string;
  alert_type: string;
  message: string;
  acknowledged: boolean;
  created_at: string;
}

export interface AppConfig {
  default_cidr: string | null;
  arp_settle_ms: number;
  port_scan_timeout_ms: number;
  port_scan_concurrency: number;
  port_service_detection: boolean;
  ping_count: number;
  ping_timeout_ms: number;
  http_port: number;
  http_path: string;
  http_timeout_ms: number;
  check_latency: boolean;
  history_retention_days: number;
  enable_notifications: boolean;
}

export interface ScanStats {
  device_count: number;
  port_count: number;
  alert_count: number;
  history_count: number;
  unacknowledged_alerts: number;
}

export interface CleanupResult {
  history_deleted: number;
  alerts_deleted: number;
}

export interface ApiServerInfo {
  /** Database file used by the app; pass it as `dbPath` to the invoke functions. */
  db_path: string;
  /** Base URL of the local REST server, or null if it failed to start. */
  rest_url: string | null;
  rest_error: string | null;
}

export interface WirePortResult {
  port: number;
  protocol: string;
  state: string;
  latency_ms: number | null;
  service: string | null;
}

export interface WireHostScanResult {
  ip: string;
  open_ports: WirePortResult[];
  total_scanned: number;
  elapsed_ms: number;
}

export interface WireLatencySample {
  host: string;
  method: 'icmp' | 'http';
  latency_ms: number | null;
  success: boolean;
  details: string | null;
  timestamp: string;
}

export interface WireHostLatencyResult {
  host: string;
  samples: WireLatencySample[];
  avg_latency_ms: number | null;
  min_latency_ms: number | null;
  max_latency_ms: number | null;
  packet_loss: number;
  elapsed_ms: number;
}

export interface WireScannedDevice {
  ip: string;
  mac: string;
  vendor: string | null;
  interface: string | null;
  open_ports: WirePortResult[];
  latency: WireHostLatencyResult | null;
  is_new: boolean;
}

export interface WireFullScanResult {
  elapsed_ms: number;
  device_count: number;
  new_device_count: number;
  total_open_ports: number;
  alert_count: number;
  devices: WireScannedDevice[];
  alerts: Alert[];
  history: HistoryRecord[];
}

/** Scan overrides; unset fields fall back to the stored config. */
export interface ScanRequest {
  cidr?: string;
  arp_settle_ms?: number;
  port_scan_timeout_ms?: number;
  port_scan_concurrency?: number;
  port_service_detection?: boolean;
  ping_count?: number;
  ping_timeout_ms?: number;
  http_port?: number;
  http_path?: string;
  http_timeout_ms?: number;
  check_latency?: boolean;
}

export interface PortScanRequest {
  hosts: string[];
  ports?: number[];
  timeout_ms?: number;
  concurrency?: number;
  service_detection?: boolean;
}

export interface LatencyRequest {
  hosts: string[];
  ping_count?: number;
  ping_timeout_ms?: number;
  http_port?: number;
  http_path?: string;
  http_timeout_ms?: number;
}

export interface HistoryQuery {
  limit?: number;
  eventType?: string;
}

export interface AlertQuery {
  acknowledged?: boolean;
  limit?: number;
}

/** Default REST server address (see `DEFAULT_BIND_ADDR` in rest_server.rs). */
export const DEFAULT_REST_URL = 'http://127.0.0.1:7357';

// ──────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────

export class ApiError extends Error {
  /** HTTP status when the error came from the REST server. */
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** Return `data` from an envelope, or throw `ApiError`. */
export function unwrap<T>(response: ApiResponse<T>, status?: number): T {
  if (!response || typeof response !== 'object' || typeof response.success !== 'boolean') {
    throw new ApiError('malformed API response', status);
  }
  if (!response.success) {
    throw new ApiError(response.error ?? 'unknown API error', status);
  }
  return response.data as T;
}

// ──────────────────────────────────────────────
// Tauri invoke bindings (desktop)
// ──────────────────────────────────────────────

async function call<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  return unwrap(await invoke<ApiResponse<T>>(command, args));
}

/** Map snake_case scan overrides to the camelCase argument names Tauri expects. */
function scanArgs(req: ScanRequest): Record<string, unknown> {
  return {
    portScanTimeoutMs: req.port_scan_timeout_ms ?? null,
    portScanConcurrency: req.port_scan_concurrency ?? null,
    portServiceDetection: req.port_service_detection ?? null,
    pingCount: req.ping_count ?? null,
    pingTimeoutMs: req.ping_timeout_ms ?? null,
    httpPort: req.http_port ?? null,
    httpPath: req.http_path ?? null,
    httpTimeoutMs: req.http_timeout_ms ?? null,
    checkLatency: req.check_latency ?? null,
  };
}

/** Database path and REST URL of the running app. */
export async function getServerInfo(): Promise<ApiServerInfo> {
  return invoke<ApiServerInfo>('api_server_info');
}

export function apiScan(dbPath: string, req: ScanRequest = {}): Promise<WireFullScanResult> {
  return call('api_scan', {
    dbPath,
    cidr: req.cidr ?? null,
    arpSettleMs: req.arp_settle_ms ?? null,
    ...scanArgs(req),
  });
}

export function apiScanHost(
  dbPath: string,
  host: string,
  req: ScanRequest = {},
): Promise<WireScannedDevice> {
  return call('api_scan_host', { dbPath, host, ...scanArgs(req) });
}

export function apiScanPorts(req: PortScanRequest): Promise<WireHostScanResult[]> {
  return call('api_scan_ports', {
    hosts: req.hosts,
    ports: req.ports ?? null,
    timeoutMs: req.timeout_ms ?? null,
    concurrency: req.concurrency ?? null,
    serviceDetection: req.service_detection ?? null,
  });
}

export function apiScanLatency(req: LatencyRequest): Promise<WireHostLatencyResult[]> {
  return call('api_scan_latency', {
    hosts: req.hosts,
    pingCount: req.ping_count ?? null,
    pingTimeoutMs: req.ping_timeout_ms ?? null,
    httpPort: req.http_port ?? null,
    httpPath: req.http_path ?? null,
    httpTimeoutMs: req.http_timeout_ms ?? null,
  });
}

export function apiGetDevices(dbPath: string): Promise<Device[]> {
  return call('api_get_devices', { dbPath });
}

export function apiGetDevice(dbPath: string, ip: string): Promise<Device> {
  return call('api_get_device', { dbPath, ip });
}

export function apiGetDevicePorts(dbPath: string, ip: string): Promise<Port[]> {
  return call('api_get_device_ports', { dbPath, ip });
}

export function apiGetPorts(dbPath: string): Promise<Port[]> {
  return call('api_get_ports', { dbPath });
}

export function apiGetDeviceHistory(dbPath: string, ip: string, limit?: number): Promise<HistoryRecord[]> {
  return call('api_get_device_history', { dbPath, ip, limit: limit ?? null });
}

export function apiGetHistory(dbPath: string, query: HistoryQuery = {}): Promise<HistoryRecord[]> {
  return call('api_get_history', {
    dbPath,
    limit: query.limit ?? null,
    eventType: query.eventType ?? null,
  });
}

export function apiGetAlerts(dbPath: string, query: AlertQuery = {}): Promise<Alert[]> {
  return call('api_get_alerts', {
    dbPath,
    acknowledged: query.acknowledged ?? null,
    limit: query.limit ?? null,
  });
}

export function apiGetDeviceAlerts(dbPath: string, ip: string): Promise<Alert[]> {
  return call('api_get_device_alerts', { dbPath, ip });
}

export async function apiAcknowledgeAlert(dbPath: string, id: number): Promise<void> {
  await call<null>('api_acknowledge_alert', { dbPath, id });
}

export function apiGetConfig(dbPath: string): Promise<AppConfig> {
  return call('api_get_config', { dbPath });
}

/** Replace the whole config (missing fields reset to defaults). */
export function apiUpdateConfig(dbPath: string, config: AppConfig): Promise<AppConfig> {
  return call('api_update_config', { dbPath, config });
}

export function apiGetStats(dbPath: string): Promise<ScanStats> {
  return call('api_get_stats', { dbPath });
}

export function apiExportDevices(dbPath: string): Promise<string> {
  return call('api_export_devices', { dbPath });
}

export function apiExportHistory(dbPath: string, limit?: number): Promise<string> {
  return call('api_export_history', { dbPath, limit: limit ?? null });
}

export function apiExportPorts(dbPath: string): Promise<string> {
  return call('api_export_ports', { dbPath });
}

export function apiCleanup(dbPath: string): Promise<CleanupResult> {
  return call('api_cleanup', { dbPath });
}

// ──────────────────────────────────────────────
// HTTP client (web dashboard)
// ──────────────────────────────────────────────

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

function queryString(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : '';
}

export class RestClient {
  readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(baseUrl: string = DEFAULT_REST_URL, fetchImpl?: FetchLike) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.fetchImpl = fetchImpl ?? ((input, init) => fetch(input, init));
  }

  private async send(method: string, path: string, body?: unknown): Promise<Response> {
    const init: RequestInit = { method };
    if (body !== undefined) {
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify(body);
    }
    try {
      return await this.fetchImpl(`${this.baseUrl}${path}`, init);
    } catch (err) {
      throw new ApiError(`cannot reach SentryNet API at ${this.baseUrl}: ${(err as Error).message}`);
    }
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.send(method, path, body);
    let payload: ApiResponse<T>;
    try {
      payload = (await res.json()) as ApiResponse<T>;
    } catch {
      throw new ApiError(`HTTP ${res.status}: response was not JSON`, res.status);
    }
    return unwrap(payload, res.status);
  }

  /** Export endpoints return the raw JSON document (no envelope) on success. */
  private async requestRaw<T>(path: string): Promise<T> {
    const res = await this.send('GET', path);
    let payload: unknown;
    try {
      payload = await res.json();
    } catch {
      throw new ApiError(`HTTP ${res.status}: response was not JSON`, res.status);
    }
    if (!res.ok) {
      return unwrap(payload as ApiResponse<T>, res.status);
    }
    return payload as T;
  }

  health(): Promise<{ status: string; version: string }> {
    return this.request('GET', '/api/health');
  }

  scan(req: ScanRequest = {}): Promise<WireFullScanResult> {
    return this.request('POST', '/api/scan', req);
  }

  scanHost(host: string, req: ScanRequest = {}): Promise<WireScannedDevice> {
    return this.request('POST', '/api/scan/host', { ...req, host });
  }

  scanPorts(req: PortScanRequest): Promise<WireHostScanResult[]> {
    return this.request('POST', '/api/scan/ports', req);
  }

  scanLatency(req: LatencyRequest): Promise<WireHostLatencyResult[]> {
    return this.request('POST', '/api/scan/latency', req);
  }

  devices(): Promise<Device[]> {
    return this.request('GET', '/api/devices');
  }

  device(ip: string): Promise<Device> {
    return this.request('GET', `/api/devices/${encodeURIComponent(ip)}`);
  }

  devicePorts(ip: string): Promise<Port[]> {
    return this.request('GET', `/api/devices/${encodeURIComponent(ip)}/ports`);
  }

  deviceHistory(ip: string, limit?: number): Promise<HistoryRecord[]> {
    return this.request('GET', `/api/devices/${encodeURIComponent(ip)}/history${queryString({ limit })}`);
  }

  deviceAlerts(ip: string): Promise<Alert[]> {
    return this.request('GET', `/api/devices/${encodeURIComponent(ip)}/alerts`);
  }

  ports(): Promise<Port[]> {
    return this.request('GET', '/api/ports');
  }

  history(query: HistoryQuery = {}): Promise<HistoryRecord[]> {
    return this.request(
      'GET',
      `/api/history${queryString({ limit: query.limit, event_type: query.eventType })}`,
    );
  }

  alerts(query: AlertQuery = {}): Promise<Alert[]> {
    return this.request(
      'GET',
      `/api/alerts${queryString({ acknowledged: query.acknowledged, limit: query.limit })}`,
    );
  }

  async acknowledgeAlert(id: number): Promise<void> {
    await this.request<null>('POST', `/api/alerts/${encodeURIComponent(String(id))}/ack`);
  }

  config(): Promise<AppConfig> {
    return this.request('GET', '/api/config');
  }

  /** Update only the given keys. */
  updateConfig(patch: Partial<AppConfig>): Promise<AppConfig> {
    return this.request('PUT', '/api/config', patch);
  }

  stats(): Promise<ScanStats> {
    return this.request('GET', '/api/stats');
  }

  exportDevices(): Promise<Device[]> {
    return this.requestRaw('/api/export/devices');
  }

  exportHistory(limit?: number): Promise<HistoryRecord[]> {
    return this.requestRaw(`/api/export/history${queryString({ limit })}`);
  }

  exportPorts(): Promise<Port[]> {
    return this.requestRaw('/api/export/ports');
  }

  cleanup(): Promise<CleanupResult> {
    return this.request('POST', '/api/cleanup');
  }
}
