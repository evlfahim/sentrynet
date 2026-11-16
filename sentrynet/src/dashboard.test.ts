/**
 * SentryNet - Dashboard utility tests.
 * Covers the pure helper functions used by the web dashboard.
 */

import { describe, it, expect } from 'vitest';
import {
  fmtDate,
  fmtMs,
  latencyClass,
  latencyBarWidth,
  stateBadge,
  alertIcon,
  eventTypeLabel,
  escapeHtml,
} from './dashboard-utils';

// ── fmtDate ──

describe('fmtDate', () => {
  it('formats a valid ISO string', () => {
    const result = fmtDate('2026-11-16T12:30:00Z');
    expect(result).toBeDefined();
    expect(typeof result).toBe('string');
  });

  it('returns "Invalid Date" for invalid input (Date doesn\'t throw)', () => {
    // new Date('not-a-date') returns Invalid Date but doesn't throw,
    // so toLocaleString() returns "Invalid Date"
    const result = fmtDate('not-a-date');
    expect(result).toBe('Invalid Date');
  });

  it('handles epoch', () => {
    const result = fmtDate('1970-01-01T00:00:00.000Z');
    expect(result).toBeDefined();
  });
});

// ── fmtMs ──

describe('fmtMs', () => {
  it('returns em-dash for null', () => {
    expect(fmtMs(null)).toBe('—');
  });

  it('formats sub-10ms with one decimal', () => {
    expect(fmtMs(1.5)).toBe('1.5ms');
    expect(fmtMs(9.9)).toBe('9.9ms');
  });

  it('rounds 10ms and above', () => {
    expect(fmtMs(10)).toBe('10ms');
    expect(fmtMs(99)).toBe('99ms');
    expect(fmtMs(100)).toBe('100ms');
    expect(fmtMs(1234)).toBe('1234ms');
  });
});

// ── latencyClass ──

describe('latencyClass', () => {
  it('returns empty for null', () => {
    expect(latencyClass(null)).toBe('');
  });

  it('returns fast for < 20ms', () => {
    expect(latencyClass(0)).toBe('fast');
    expect(latencyClass(19)).toBe('fast');
  });

  it('returns medium for 20-99ms', () => {
    expect(latencyClass(20)).toBe('medium');
    expect(latencyClass(99)).toBe('medium');
  });

  it('returns slow for >= 100ms', () => {
    expect(latencyClass(100)).toBe('slow');
    expect(latencyClass(5000)).toBe('slow');
  });
});

// ── latencyBarWidth ──

describe('latencyBarWidth', () => {
  it('returns 0 for null', () => {
    expect(latencyBarWidth(null)).toBe(0);
  });

  it('scales linearly up to 500ms', () => {
    expect(latencyBarWidth(250)).toBe(50);
    expect(latencyBarWidth(100)).toBe(20);
  });

  it('caps at 100 for values >= 500ms', () => {
    expect(latencyBarWidth(500)).toBe(100);
    expect(latencyBarWidth(1000)).toBe(100);
  });
});

// ── stateBadge ──

describe('stateBadge', () => {
  it('maps open', () => {
    expect(stateBadge('open')).toBe('badge-open');
  });

  it('maps closed', () => {
    expect(stateBadge('closed')).toBe('badge-closed');
  });

  it('maps filtered', () => {
    expect(stateBadge('filtered')).toBe('badge-filtered');
  });

  it('is case-insensitive', () => {
    expect(stateBadge('OPEN')).toBe('badge-open');
    expect(stateBadge('Open')).toBe('badge-open');
  });

  it('returns empty for unknown states', () => {
    expect(stateBadge('unknown')).toBe('');
  });
});

// ── alertIcon ──

describe('alertIcon', () => {
  it('maps known alert types', () => {
    expect(alertIcon('new_device')).toBe('🟢');
    expect(alertIcon('new_port')).toBe('🔓');
    expect(alertIcon('device_offline')).toBe('🔴');
    expect(alertIcon('port_closed')).toBe('🔒');
  });

  it('returns warning for unknown types', () => {
    expect(alertIcon('custom')).toBe('⚠️');
  });
});

// ── eventTypeLabel ──

describe('eventTypeLabel', () => {
  it('converts snake_case to Title Case', () => {
    expect(eventTypeLabel('new_device')).toBe('New Device');
    expect(eventTypeLabel('port_added')).toBe('Port Added');
    expect(eventTypeLabel('device_offline')).toBe('Device Offline');
  });

  it('handles single-word types', () => {
    expect(eventTypeLabel('discovered')).toBe('Discovered');
  });

  it('handles already-camelCase', () => {
    // The regex capitalizes the first letter of every word boundary
    expect(eventTypeLabel('newDevice')).toBe('NewDevice');
  });
});

// ── escapeHtml ──

describe('escapeHtml', () => {
  it('escapes special characters', () => {
    expect(escapeHtml('<script>alert("xss")</script>')).toBe(
      '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
    );
  });

  it('leaves safe strings unchanged', () => {
    expect(escapeHtml('Hello, world!')).toBe('Hello, world!');
  });

  it('handles empty string', () => {
    expect(escapeHtml('')).toBe('');
  });

  it('escapes ampersand', () => {
    expect(escapeHtml('Tom & Jerry')).toBe('Tom &amp; Jerry');
  });
});
