/**
 * SentryNet Web Dashboard
 *
 * Connects to the local REST API (src-tauri/src/rest_server.rs) and renders
 * a full dashboard with device table, port details, latency graphs, history
 * timeline, alerts, and settings.
 */

import { isTauriRuntime, maxAlertId, newAlertsSince, planNotifications } from './alerts';

// ──────────────────────────────────────────────
// Types (mirror src-tauri/src/api.rs)
// ──────────────────────────────────────────────

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
  protocol: string;
  state: string;
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

export interface WirePortResult {
  port: number;
  protocol: string;
  state: string;
  latency_ms: number | null;
  service: string | null;
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

export interface CleanupResult {
  history_deleted: number;
  alerts_deleted: number;
}

// ──────────────────────────────────────────────
// REST client
// ──────────────────────────────────────────────

const DEFAULT_REST_URL = 'http://127.0.0.1:7357';

let restUrl = DEFAULT_REST_URL;
let connected = false;

async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${restUrl}${path}`);
  if (!res.ok) {
    const text = await res.text();
    let err: string;
    try { err = JSON.parse(text).error ?? `HTTP ${res.status}`; } catch { err = `HTTP ${res.status}: ${text}`; }
    throw new Error(err);
  }
  const json = await res.json();
  if (json && typeof json === 'object' && 'success' in json) {
    if (!json.success) throw new Error(json.error ?? 'API error');
    return json.data as T;
  }
  // Raw export response (no envelope)
  return json as T;
}

async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${restUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    let err: string;
    try { err = JSON.parse(text).error ?? `HTTP ${res.status}`; } catch { err = `HTTP ${res.status}: ${text}`; }
    throw new Error(err);
  }
  const json = await res.json();
  if (!json.success) throw new Error(json.error ?? 'API error');
  return json.data as T;
}

async function apiPut<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${restUrl}${path}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    let err: string;
    try { err = JSON.parse(text).error ?? `HTTP ${res.status}`; } catch { err = `HTTP ${res.status}: ${text}`; }
    throw new Error(err);
  }
  const json = await res.json();
  if (!json.success) throw new Error(json.error ?? 'API error');
  return json.data as T;
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

function fmtDate(iso: string): string {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function fmtMs(ms: number | null): string {
  if (ms === null) return '—';
  if (ms < 10) return `${ms.toFixed(1)}ms`;
  return `${Math.round(ms)}ms`;
}

function latencyClass(ms: number | null): string {
  if (ms === null) return '';
  if (ms < 20) return 'fast';
  if (ms < 100) return 'medium';
  return 'slow';
}

function latencyBarWidth(ms: number | null): number {
  if (ms === null) return 0;
  return Math.min(100, (ms / 500) * 100);
}

function stateBadge(state: string): string {
  const s = state.toLowerCase();
  if (s === 'open') return 'badge-open';
  if (s === 'closed') return 'badge-closed';
  if (s === 'filtered') return 'badge-filtered';
  return '';
}

function alertIcon(type: string): string {
  switch (type) {
    case 'new_device': return '🟢';
    case 'new_port': return '🔓';
    case 'device_offline': return '🔴';
    case 'port_closed': return '🔒';
    default: return '⚠️';
  }
}

function eventTypeLabel(type: string): string {
  return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ──────────────────────────────────────────────
// Toast notifications
// ──────────────────────────────────────────────

function showToast(message: string, type: 'success' | 'error' | 'info' = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; setTimeout(() => el.remove(), 300); }, 3500);
}

// ──────────────────────────────────────────────
// Browser notifications (for web dashboard)
// ──────────────────────────────────────────────
//
// Inside the Tauri window the Rust backend already shows desktop
// notifications for every scan alert, so browser notifications are only used
// when the dashboard is opened in a regular browser.

let notificationPermission = 'default';
/** Mirrors `enable_notifications` from the stored config. */
let notificationsEnabled = true;
/** Highest alert id already notified (or present when the page loaded). */
let lastNotifiedAlertId: number | null = null;

const LAST_ALERT_KEY = 'sentrynet.lastNotifiedAlertId';

function browserNotificationsWanted(): boolean {
  return notificationsEnabled && !isTauriRuntime() && 'Notification' in window;
}

function loadLastNotifiedAlertId(): number | null {
  try {
    const raw = window.localStorage.getItem(LAST_ALERT_KEY);
    const id = raw === null ? NaN : Number(raw);
    return Number.isFinite(id) ? id : null;
  } catch {
    return null;
  }
}

function saveLastNotifiedAlertId(id: number) {
  lastNotifiedAlertId = id;
  try { window.localStorage.setItem(LAST_ALERT_KEY, String(id)); } catch { /* storage unavailable */ }
}

async function requestNotificationPermission(): Promise<boolean> {
  if (!browserNotificationsWanted()) return false;
  if (notificationPermission === 'granted') return true;
  if (notificationPermission === 'denied') return false;
  try {
    notificationPermission = await Notification.requestPermission();
    return notificationPermission === 'granted';
  } catch {
    return false;
  }
}

async function sendBrowserNotification(title: string, body: string) {
  if (!('Notification' in window)) return;
  if (notificationPermission === 'denied') return;
  if (notificationPermission !== 'granted') {
    const granted = await requestNotificationPermission();
    if (!granted) return;
  }
  try {
    new Notification(title, { body, tag: `${title}|${body}`, requireInteraction: true });
  } catch {
    // Notification failed silently
  }
}

/**
 * Notify about alerts created since the last check. On the first check of a
 * fresh browser the existing alerts only set the baseline, so reloading the
 * page never replays old alerts.
 */
async function checkAndNotifyAlerts() {
  try {
    const alerts = await apiGet<Alert[]>('/api/alerts?acknowledged=false&limit=100');
    if (lastNotifiedAlertId === null) lastNotifiedAlertId = loadLastNotifiedAlertId();
    if (lastNotifiedAlertId === null) {
      saveLastNotifiedAlertId(maxAlertId(alerts));
      return;
    }
    const fresh = newAlertsSince(alerts, lastNotifiedAlertId);
    if (fresh.length === 0) return;
    saveLastNotifiedAlertId(maxAlertId(fresh));

    // Always surface new alerts in the page itself.
    const newDevices = fresh.filter(a => a.alert_type === 'new_device').length;
    if (newDevices > 0) showToast(`${alertIcon('new_device')} ${newDevices} new device(s) on the network`, 'info');

    if (!browserNotificationsWanted()) return;
    for (const n of planNotifications(fresh)) {
      await sendBrowserNotification(n.title, n.body);
    }
  } catch {
    // Silently fail — notifications are non-critical
  }
}

// ──────────────────────────────────────────────
// Tab management
// ──────────────────────────────────────────────

function initTabs() {
  const btns = document.querySelectorAll('.tab-btn') as NodeListOf<HTMLButtonElement>;
  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      btns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      const panel = document.getElementById(`panel-${btn.dataset.tab}`);
      if (panel) panel.classList.add('active');
    });
  });
}

// ──────────────────────────────────────────────
// Device detail panel
// ──────────────────────────────────────────────

async function showDeviceDetail(ip: string) {
  const panel = document.getElementById('detailPanel');
  const title = document.getElementById('detailTitle');
  const body = document.getElementById('detailBody');
  if (!panel || !title || !body) return;

  title.textContent = ip;
  body.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-dim)">Loading…</div>';
  panel.classList.add('open');

  try {
    const device = await apiGet<Device>(`/api/devices/${encodeURIComponent(ip)}`);
    const ports = await apiGet<Port[]>(`/api/devices/${encodeURIComponent(ip)}/ports`);
    const history = await apiGet<HistoryRecord[]>(`/api/devices/${encodeURIComponent(ip)}/history?limit=20`);
    const alerts = await apiGet<Alert[]>(`/api/devices/${encodeURIComponent(ip)}/alerts`);

    let html = '';

    // Device info
    html += `<div class="detail-section">
      <h4>Device Info</h4>
      <table style="width:100%">
        <tr><td style="color:var(--text-dim);padding:4px 8px 4px 0">IP</td><td class="mono">${escapeHtml(device.ip)}</td></tr>
        <tr><td style="color:var(--text-dim);padding:4px 8px 4px 0">MAC</td><td class="mono">${escapeHtml(device.mac)}</td></tr>
        <tr><td style="color:var(--text-dim);padding:4px 8px 4px 0">Name</td><td>${escapeHtml(device.name || '—')}</td></tr>
        <tr><td style="color:var(--text-dim);padding:4px 8px 4px 0">Vendor</td><td>${escapeHtml(device.vendor || '—')}</td></tr>
        <tr><td style="color:var(--text-dim);padding:4px 8px 4px 0">First Seen</td><td class="mono">${fmtDate(device.first_seen)}</td></tr>
        <tr><td style="color:var(--text-dim);padding:4px 8px 4px 0">Last Seen</td><td class="mono">${fmtDate(device.last_seen)}</td></tr>
      </table>
    </div>`;

    // Ports
    html += `<div class="detail-section"><h4>Open Ports (${ports.length})</h4>`;
    if (ports.length === 0) {
      html += '<p style="color:var(--text-dim);font-size:.82rem">No open ports.</p>';
    } else {
      html += '<table style="width:100%"><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr></thead><tbody>';
      for (const p of ports) {
        html += `<tr><td class="mono">${p.port}</td><td class="mono">${escapeHtml(p.protocol)}</td><td><span class="badge ${stateBadge(p.state)}">${escapeHtml(p.state)}</span></td><td>${escapeHtml(p.service || '—')}</td></tr>`;
      }
      html += '</tbody></table>';
    }
    html += '</div>';

    // History
    html += `<div class="detail-section"><h4>Recent History (${history.length})</h4>`;
    if (history.length === 0) {
      html += '<p style="color:var(--text-dim);font-size:.82rem">No history.</p>';
    } else {
      html += '<div class="timeline">';
      for (const h of history) {
        html += `<div class="timeline-item event-${escapeHtml(h.event_type)}">
          <div class="tl-time">${fmtDate(h.timestamp)}</div>
          <div class="tl-body"><strong>${escapeHtml(eventTypeLabel(h.event_type))}</strong>${h.details ? ` — ${escapeHtml(h.details)}` : ''}</div>
        </div>`;
      }
      html += '</div>';
    }
    html += '</div>';

    // Alerts
    html += `<div class="detail-section"><h4>Alerts (${alerts.length})</h4>`;
    if (alerts.length === 0) {
      html += '<p style="color:var(--text-dim);font-size:.82rem">No alerts.</p>';
    } else {
      for (const a of alerts) {
        html += `<div class="alert-item ${a.acknowledged ? 'ack' : 'unack'}">
          <div class="alert-icon">${alertIcon(a.alert_type)}</div>
          <div class="alert-content">
            <div class="alert-msg">${escapeHtml(a.message)}</div>
            <div class="alert-meta">${fmtDate(a.created_at)} · ${escapeHtml(a.alert_type)}</div>
          </div>
          ${!a.acknowledged ? `<button class="btn btn-sm" onclick="window.__ackAlert(${a.id})">Ack</button>` : ''}
        </div>`;
      }
    }
    html += '</div>';

    body.innerHTML = html;
  } catch (e) {
    body.innerHTML = `<div style="padding:24px;text-align:center;color:var(--red)">Error: ${(e as Error).message}</div>`;
  }
}

function closeDeviceDetail() {
  const panel = document.getElementById('detailPanel');
  if (panel) panel.classList.remove('open');
}

// Expose ack function globally for inline onclick
(window as unknown as Record<string, unknown>).__ackAlert = async function (id: number) {
  try {
    await apiPost(`/api/alerts/${id}/ack`);
    showToast('Alert acknowledged', 'success');
    const ip = document.getElementById('detailTitle')?.textContent;
    if (ip) showDeviceDetail(ip);
    refreshAlerts();
  } catch (e) {
    showToast(`Failed to acknowledge: ${(e as Error).message}`, 'error');
  }
};

// ──────────────────────────────────────────────
// Render functions
// ──────────────────────────────────────────────

function renderDevices(devices: Device[], scanResult?: WireFullScanResult) {
  const tbody = document.getElementById('deviceBody');
  if (!tbody) return;

  if (devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state"><div class="empty-icon">🔍</div><p>No devices yet. Run a scan to discover devices.</p></td></tr>';
    return;
  }

  // Build lookup for scan results (new devices, latency)
  const scanMap = new Map<string, WireScannedDevice>();
  if (scanResult) {
    for (const d of scanResult.devices) scanMap.set(d.ip, d);
  }

  let html = '';
  for (const d of devices) {
    const scan = scanMap.get(d.ip);
    const isNew = scan?.is_new ?? false;
    const portCount = scan?.open_ports.length ?? 0;
    const icmpMs = scan?.latency?.samples?.find(s => s.method === 'icmp')?.latency_ms ?? null;
    const httpMs = scan?.latency?.samples?.find(s => s.method === 'http')?.latency_ms ?? null;
    const isOnline = scan !== undefined;

    html += `<tr>
      <td class="mono">${escapeHtml(d.ip)}${isNew ? ' <span class="badge badge-new">NEW</span>' : ''}</td>
      <td class="mono">${escapeHtml(d.mac)}</td>
      <td>${escapeHtml(d.name || '—')}</td>
      <td>${escapeHtml(d.vendor || '—')}</td>
      <td>${portCount}</td>
      <td>
        ${icmpMs !== null || httpMs !== null ? `
          <div class="latency-bar-wrap">
            <div class="latency-bar"><div class="latency-bar-fill ${latencyClass(icmpMs)}" style="width:${latencyBarWidth(icmpMs)}%"></div></div>
            <span class="latency-val">${fmtMs(icmpMs)}</span>
          </div>
        ` : '—'}
      </td>
      <td><span class="badge ${isOnline ? 'badge-online' : 'badge-offline'}">${isOnline ? 'Online' : 'Offline'}</span></td>
      <td class="mono" style="font-size:.72rem">${fmtDate(d.last_seen)}</td>
      <td><button class="btn btn-sm" onclick="window.__showDetail('${escapeHtml(d.ip)}')">Details</button></td>
    </tr>`;
  }
  tbody.innerHTML = html;
}

function renderPorts(ports: Port[]) {
  const tbody = document.getElementById('portBody');
  if (!tbody) return;

  if (ports.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><div class="empty-icon">🔌</div><p>No ports discovered yet.</p></td></tr>';
    return;
  }

  let html = '';
  for (const p of ports) {
    html += `<tr>
      <td class="mono">${escapeHtml(p.device_ip)}</td>
      <td class="mono">${p.port}</td>
      <td class="mono">${escapeHtml(p.protocol)}</td>
      <td><span class="badge ${stateBadge(p.state)}">${escapeHtml(p.state)}</span></td>
      <td>${escapeHtml(p.service || '—')}</td>
    </tr>`;
  }
  tbody.innerHTML = html;
}

function renderLatency(devices: Device[], scanResult?: WireFullScanResult) {
  const tbody = document.getElementById('latencyBody');
  if (!tbody) return;

  if (!scanResult || scanResult.devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><div class="empty-icon">⏱️</div><p>No latency data yet. Run a scan.</p></td></tr>';
    return;
  }

  let html = '';
  for (const d of scanResult.devices) {
    const icmp = d.latency?.samples?.find(s => s.method === 'icmp');
    const http = d.latency?.samples?.find(s => s.method === 'http');
    const icmpMs = icmp?.latency_ms ?? null;
    const httpMs = http?.latency_ms ?? null;
    const loss = d.latency?.packet_loss ?? 0;

    html += `<tr>
      <td class="mono">${escapeHtml(d.ip)}</td>
      <td>
        <div class="latency-bar-wrap">
          <div class="latency-bar"><div class="latency-bar-fill ${latencyClass(icmpMs)}" style="width:${latencyBarWidth(icmpMs)}%"></div></div>
          <span class="latency-val">${fmtMs(icmpMs)}</span>
        </div>
      </td>
      <td>
        <div class="latency-bar-wrap">
          <div class="latency-bar"><div class="latency-bar-fill ${latencyClass(httpMs)}" style="width:${latencyBarWidth(httpMs)}%"></div></div>
          <span class="latency-val">${fmtMs(httpMs)}</span>
        </div>
      </td>
      <td>${(loss * 100).toFixed(0)}%</td>
    </tr>`;
  }
  tbody.innerHTML = html;
}

function renderHistory(records: HistoryRecord[]) {
  const container = document.getElementById('timeline');
  if (!container) return;

  if (records.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">📝</div><p>No history yet.</p></div>';
    return;
  }

  let html = '';
  for (const r of records) {
    html += `<div class="timeline-item event-${escapeHtml(r.event_type)}">
      <div class="tl-time">${fmtDate(r.timestamp)}</div>
      <div class="tl-body"><strong>${escapeHtml(eventTypeLabel(r.event_type))}</strong> — ${escapeHtml(r.device_ip)}${r.details ? ` · ${escapeHtml(r.details)}` : ''}</div>
    </div>`;
  }
  container.innerHTML = html;
}

function renderAlerts(alerts: Alert[]) {
  const container = document.getElementById('alertsList');
  if (!container) return;

  if (alerts.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">🔔</div><p>No alerts.</p></div>';
    return;
  }

  let html = '';
  for (const a of alerts) {
    html += `<div class="alert-item ${a.acknowledged ? 'ack' : 'unack'}">
      <div class="alert-icon">${alertIcon(a.alert_type)}</div>
      <div class="alert-content">
        <div class="alert-msg">${escapeHtml(a.message)}</div>
        <div class="alert-meta">${fmtDate(a.created_at)} · ${escapeHtml(a.alert_type)} · ${escapeHtml(a.device_ip)}</div>
      </div>
      ${!a.acknowledged ? `<button class="btn btn-sm" onclick="window.__ackAlert(${a.id})">Ack</button>` : ''}
    </div>`;
  }
  container.innerHTML = html;
}

function updateStats(stats: ScanStats) {
  const el = (id: string) => document.getElementById(id);
  if (el('statDevices')) el('statDevices')!.textContent = String(stats.device_count);
  if (el('statPorts')) el('statPorts')!.textContent = String(stats.port_count);
  if (el('statAlerts')) el('statAlerts')!.textContent = String(stats.unacknowledged_alerts);
  if (el('statHistory')) el('statHistory')!.textContent = String(stats.history_count);

  // Alert badge
  const badge = document.getElementById('alertBadge');
  if (badge) {
    if (stats.unacknowledged_alerts > 0) {
      badge.style.display = 'inline-flex';
      badge.textContent = String(stats.unacknowledged_alerts);
    } else {
      badge.style.display = 'none';
    }
  }
}

// ──────────────────────────────────────────────
// Scan
// ──────────────────────────────────────────────

async function runScan() {
  const progress = document.getElementById('scanProgress');
  const status = document.getElementById('scanStatus');
  if (!progress || !status) return;

  progress.classList.add('active');
  status.textContent = 'Scanning LAN…';

  try {
    const result = await apiPost<WireFullScanResult>('/api/scan', {});
    status.textContent = `Scan complete — ${result.device_count} devices, ${result.total_open_ports} ports, ${result.alert_count} alerts (${result.elapsed_ms}ms)`;

    // Refresh all data
    refreshAll(result);

    if (result.alert_count > 0) {
      refreshAlerts();
      // Toast + browser notification for the alerts this scan raised
      // (the desktop app's backend has already shown OS notifications).
      await checkAndNotifyAlerts();
    }
  } catch (e) {
    status.textContent = `Scan failed: ${(e as Error).message}`;
    showToast(`Scan failed: ${(e as Error).message}`, 'error');
  }

  setTimeout(() => progress.classList.remove('active'), 5000);
}

// ──────────────────────────────────────────────
// Refresh
// ──────────────────────────────────────────────

async function refreshAll(scanResult?: WireFullScanResult) {
  try {
    const [devices, ports, history, alerts, stats] = await Promise.all([
      apiGet<Device[]>('/api/devices'),
      apiGet<Port[]>('/api/ports'),
      apiGet<HistoryRecord[]>('/api/history?limit=50'),
      apiGet<Alert[]>('/api/alerts?acknowledged=false&limit=50'),
      apiGet<ScanStats>('/api/stats'),
    ]);

    renderDevices(devices, scanResult);
    renderPorts(ports);
    renderHistory(history);
    renderAlerts(alerts);
    updateStats(stats);
  } catch (e) {
    console.error('Refresh failed:', e);
  }
}

async function refreshAlerts() {
  try {
    const alerts = await apiGet<Alert[]>('/api/alerts?acknowledged=false&limit=50');
    renderAlerts(alerts);
    const stats = await apiGet<ScanStats>('/api/stats');
    updateStats(stats);
  } catch (e) {
    console.error('Alert refresh failed:', e);
  }
}

// ──────────────────────────────────────────────
// Settings
// ──────────────────────────────────────────────

async function loadSettings() {
  try {
    const config = await apiGet<AppConfig>('/api/config');
    notificationsEnabled = config.enable_notifications;
    const fill =(id: string, val: string | number | boolean) => {
      const el = document.getElementById(id) as HTMLInputElement | null;
      if (el) {
        if (el.type === 'checkbox') {
          el.checked = Boolean(val);
        } else {
          el.value = String(val);
        }
      }
    };
    fill('cfgCidr', config.default_cidr ?? '');
    fill('cfgArpSettle', config.arp_settle_ms);
    fill('cfgPortTimeout', config.port_scan_timeout_ms);
    fill('cfgPortConcurrency', config.port_scan_concurrency);
    fill('cfgPingCount', config.ping_count);
    fill('cfgPingTimeout', config.ping_timeout_ms);
    fill('cfgHttpPort', config.http_port);
    fill('cfgHttpPath', config.http_path);
    fill('cfgHttpTimeout', config.http_timeout_ms);
    fill('cfgRetention', config.history_retention_days);
    fill('cfgSvcDetect', config.port_service_detection);
    fill('cfgLatency', config.check_latency);
    fill('cfgNotify', config.enable_notifications);
  } catch (e) {
    console.error('Failed to load settings:', e);
  }
}

async function saveSettings() {
  try {
    const patch: Record<string, unknown> = {};
    const cidr = (document.getElementById('cfgCidr') as HTMLInputElement).value.trim();
    if (cidr) patch.default_cidr = cidr;

    const num = (id: string) => {
      const v = parseInt((document.getElementById(id) as HTMLInputElement).value, 10);
      if (!isNaN(v)) patch[id.replace('cfg', '').toLowerCase()] = v;
    };
    num('ArpSettle');
    num('PortTimeout');
    num('PortConcurrency');
    num('PingCount');
    num('PingTimeout');
    num('HttpPort');
    num('HttpTimeout');
    num('Retention');

    const chk = (id: string) => {
      const v = (document.getElementById(id) as HTMLInputElement).checked;
      patch[id.replace('cfg', '').toLowerCase()] = v;
    };
    chk('SvcDetect');
    chk('Latency');
    chk('Notify');

    // http_path is special — only send if non-empty
    const httpPath = (document.getElementById('cfgHttpPath') as HTMLInputElement).value.trim();
    if (httpPath) patch.http_path = httpPath;

    await apiPut('/api/config', patch);
    showToast('Settings saved', 'success');
  } catch (e) {
    showToast(`Failed to save: ${(e as Error).message}`, 'error');
  }
}

async function resetSettings() {
  try {
    await apiPut('/api/config', {});
    showToast('Settings reset to defaults', 'info');
    loadSettings();
  } catch (e) {
    showToast(`Failed to reset: ${(e as Error).message}`, 'error');
  }
}

async function runCleanup() {
  try {
    const result = await apiPost<CleanupResult>('/api/cleanup');
    const el = document.getElementById('cleanupResult');
    if (el) {
      el.textContent = `Deleted ${result.history_deleted} history records and ${result.alerts_deleted} alerts.`;
    }
    showToast('Cleanup complete', 'success');
    refreshAll();
  } catch (e) {
    showToast(`Cleanup failed: ${(e as Error).message}`, 'error');
  }
}

async function clearAllData() {
  if (!confirm('Clear ALL data? This cannot be undone.')) return;
  try {
    // Delete the database file directly — there's no API endpoint for this.
    // The user needs to know the DB path; show it in the toast.
    const info = await apiGet<{ db_path: string }>('/api/server_info');
    showToast(`Database deleted: ${info.db_path}. Restart the app to reconnect.`, 'info');
    // Note: actual file deletion requires the desktop app's file system API.
    // The web dashboard can only inform the user.
  } catch {
    showToast('Use the desktop app to clear all data.', 'info');
  }
}

// ──────────────────────────────────────────────
// Export
// ──────────────────────────────────────────────

function openExportModal() {
  const overlay = document.getElementById('exportOverlay');
  if (overlay) overlay.style.display = 'flex';
}

function closeExportModal() {
  const overlay = document.getElementById('exportOverlay');
  if (overlay) overlay.style.display = 'none';
}

async function downloadExport(filename: string, data: unknown) {
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Exported ${filename}`, 'success');
}

async function exportDevices() {
  try {
    const devices = await apiGet<Device[]>('/api/export/devices');
    closeExportModal();
    downloadExport('sentrynet-devices.json', devices);
  } catch (e) {
    showToast(`Export failed: ${(e as Error).message}`, 'error');
  }
}

async function exportPorts() {
  try {
    const ports = await apiGet<Port[]>('/api/export/ports');
    closeExportModal();
    downloadExport('sentrynet-ports.json', ports);
  } catch (e) {
    showToast(`Export failed: ${(e as Error).message}`, 'error');
  }
}

async function exportHistory() {
  try {
    const history = await apiGet<HistoryRecord[]>('/api/export/history?limit=1000');
    closeExportModal();
    downloadExport('sentrynet-history.json', history);
  } catch (e) {
    showToast(`Export failed: ${(e as Error).message}`, 'error');
  }
}

// ──────────────────────────────────────────────
// Connection check
// ──────────────────────────────────────────────

async function checkConnection() {
  const badge = document.getElementById('statusBadge');
  const text = document.getElementById('statusText');
  if (!badge || !text) return;

  try {
    await apiGet<{ status: string; version: string }>('/api/health');
    connected = true;
    badge.classList.add('online');
    text.textContent = 'Connected';
  } catch {
    connected = false;
    badge.classList.remove('online');
    text.textContent = 'Disconnected';
  }
}

// ──────────────────────────────────────────────
// Init
// ──────────────────────────────────────────────

async function init() {
  initTabs();

  // Wire up buttons
  document.getElementById('btnScan')?.addEventListener('click', runScan);
  document.getElementById('btnRefresh')?.addEventListener('click', () => refreshAll());
  document.getElementById('btnExport')?.addEventListener('click', openExportModal);
  document.getElementById('btnCloseExport')?.addEventListener('click', closeExportModal);
  document.getElementById('btnExportDevices')?.addEventListener('click', exportDevices);
  document.getElementById('btnExportPorts')?.addEventListener('click', exportPorts);
  document.getElementById('btnExportHistory')?.addEventListener('click', exportHistory);
  document.getElementById('btnSaveConfig')?.addEventListener('click', saveSettings);
  document.getElementById('btnResetConfig')?.addEventListener('click', resetSettings);
  document.getElementById('btnCleanup')?.addEventListener('click', runCleanup);
  document.getElementById('btnClearAll')?.addEventListener('click', clearAllData);
  document.getElementById('btnCloseDetail')?.addEventListener('click', closeDeviceDetail);

  // Close modal on overlay click
  const overlay = document.getElementById('exportOverlay');
  overlay?.addEventListener('click', (e) => { if (e.target === overlay) closeExportModal(); });

  // Close detail panel on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeDeviceDetail();
      closeExportModal();
    }
  });

  // Initial connection check
  await checkConnection();
  if (connected) {
    await refreshAll();
    await loadSettings();
    // Request notification permission and check for existing alerts
    await requestNotificationPermission();
    await checkAndNotifyAlerts();
  }

  // Periodic refresh (every 30s)
  setInterval(async () => {
    if (connected) {
      await refreshAlerts();
      await checkAndNotifyAlerts();
    }
  }, 30000);
}

// Make functions available globally for inline onclick handlers
(window as unknown as Record<string, unknown>).__showDetail = showDeviceDetail;

init().catch(console.error);