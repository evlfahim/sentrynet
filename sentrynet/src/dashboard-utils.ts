/**
 * SentryNet - Dashboard pure utility functions.
 *
 * These helpers have no DOM or browser dependencies and can be tested in any
 * environment (Node, jsdom, etc.).  The main dashboard.ts imports them and
 * adds browser-specific code (window, fetch, Notification API).
 */

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

export function fmtDate(iso: string): string {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

export function fmtMs(ms: number | null): string {
  if (ms === null) return '—';
  if (ms < 10) return `${ms.toFixed(1)}ms`;
  return `${Math.round(ms)}ms`;
}

export function latencyClass(ms: number | null): string {
  if (ms === null) return '';
  if (ms < 20) return 'fast';
  if (ms < 100) return 'medium';
  return 'slow';
}

export function latencyBarWidth(ms: number | null): number {
  if (ms === null) return 0;
  return Math.min(100, (ms / 500) * 100);
}

export function stateBadge(state: string): string {
  const s = state.toLowerCase();
  if (s === 'open') return 'badge-open';
  if (s === 'closed') return 'badge-closed';
  if (s === 'filtered') return 'badge-filtered';
  return '';
}

export function alertIcon(type: string): string {
  switch (type) {
    case 'new_device': return '🟢';
    case 'new_port': return '🔓';
    case 'device_offline': return '🔴';
    case 'port_closed': return '🔒';
    default: return '⚠️';
  }
}

export function eventTypeLabel(type: string): string {
  return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
