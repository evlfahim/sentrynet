/**
 * SentryNet alert helpers for the dashboard.
 *
 * Desktop notifications for scan alerts are sent by the Rust backend
 * (`src-tauri/src/alerts.rs`) through the Tauri notification plugin, for scans
 * started from the desktop window and from the REST API alike. These helpers
 * let the web dashboard, when opened in a normal browser, show browser
 * notifications for alerts it has not shown yet — without repeating old ones
 * and without doubling up inside the Tauri window.
 *
 * Grouping mirrors `plan_notifications` in the Rust module.
 */

/** Minimal alert shape shared by the REST payloads. */
export interface AlertLike {
  id: number | null;
  device_ip: string;
  alert_type: string;
  message: string;
  acknowledged: boolean;
}

export interface PlannedNotification {
  title: string;
  body: string;
}

/** Up to this many alerts of one type get their own notification. */
export const MAX_INDIVIDUAL_NOTIFICATIONS = 3;

const TYPE_ORDER = ['new_device', 'new_port', 'device_offline', 'port_closed'];

/** True inside the Tauri desktop window (the backend shows notifications there). */
export function isTauriRuntime(scope: object = globalThis): boolean {
  return '__TAURI_INTERNALS__' in scope || '__TAURI__' in scope;
}

export function alertTitle(type: string): string {
  switch (type) {
    case 'new_device': return 'New device discovered';
    case 'new_port': return 'New port opened';
    case 'device_offline': return 'Device offline';
    case 'port_closed': return 'Port closed';
    default: return 'SentryNet alert';
  }
}

function summaryTitle(type: string, count: number): string {
  switch (type) {
    case 'new_device': return `${count} new devices discovered`;
    case 'new_port': return `${count} new open ports`;
    case 'device_offline': return `${count} devices went offline`;
    case 'port_closed': return `${count} ports closed`;
    default: return `${count} SentryNet alerts`;
  }
}

function summaryBody(alerts: AlertLike[]): string {
  const ips = [...new Set(alerts.map(a => a.device_ip))];
  const shown = ips.slice(0, MAX_INDIVIDUAL_NOTIFICATIONS);
  let body = shown.join(', ');
  if (ips.length > shown.length) body += ` and ${ips.length - shown.length} more`;
  return `${body}. Open SentryNet to review.`;
}

/** Highest alert id in the list (0 when empty). */
export function maxAlertId(alerts: AlertLike[]): number {
  return alerts.reduce((max, a) => (a.id !== null && a.id > max ? a.id : max), 0);
}

/** Unacknowledged alerts with an id above `lastSeenId`, oldest first. */
export function newAlertsSince<T extends AlertLike>(alerts: T[], lastSeenId: number): T[] {
  return alerts
    .filter(a => !a.acknowledged && a.id !== null && a.id > lastSeenId)
    .sort((a, b) => (a.id ?? 0) - (b.id ?? 0));
}

/**
 * Group alerts into notifications: one per alert for small groups, a single
 * summary for groups larger than `max`. New devices come first.
 */
export function planNotifications(
  alerts: AlertLike[],
  max: number = MAX_INDIVIDUAL_NOTIFICATIONS,
): PlannedNotification[] {
  const pending = alerts.filter(a => !a.acknowledged);
  const types = [...TYPE_ORDER];
  for (const a of pending) {
    if (!types.includes(a.alert_type)) types.push(a.alert_type);
  }

  const out: PlannedNotification[] = [];
  for (const type of types) {
    const group = pending.filter(a => a.alert_type === type);
    if (group.length === 0) continue;
    if (group.length <= max) {
      for (const a of group) out.push({ title: alertTitle(a.alert_type), body: a.message });
    } else {
      out.push({ title: summaryTitle(type, group.length), body: summaryBody(group) });
    }
  }
  return out;
}
