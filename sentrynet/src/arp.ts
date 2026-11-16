/**
 * SentryNet - ARP discovery bindings.
 * Thin wrapper around the Rust `arp_scan` Tauri command.
 */

import { invoke } from '@tauri-apps/api/core';

/** A host discovered in the ARP cache (mirrors Rust `arp::ArpEntry`). */
export interface ArpEntry {
  ip: string;
  /** Uppercase, colon separated: `AA:BB:CC:DD:EE:FF`. */
  mac: string;
  vendor: string | null;
  interface: string | null;
}

export interface ArpScanOptions {
  /** Subnet in CIDR notation, e.g. `192.168.1.0/24`. Defaults to the local /24. */
  cidr?: string;
  /** Milliseconds to wait for ARP replies after probing (default 1500). */
  settleMs?: number;
}

/** Run an ARP scan of the LAN via the Tauri backend. */
export async function arpScan(options: ArpScanOptions = {}): Promise<ArpEntry[]> {
  return invoke<ArpEntry[]>('arp_scan', {
    cidr: options.cidr ?? null,
    settleMs: options.settleMs ?? null,
  });
}

/**
 * Normalize a MAC in any common notation to `AA:BB:CC:DD:EE:FF`.
 * Returns null for invalid input. Mirrors Rust `arp::normalize_mac`.
 */
export function normalizeMac(raw: string): string | null {
  const s = raw.trim();
  if (!s || !/^[0-9a-fA-F:.-]+$/.test(s)) return null;
  const groups = s.split(/[:.-]/);
  let hex: string;
  if (groups.length === 6) {
    if (groups.some((g) => g.length < 1 || g.length > 2)) return null;
    hex = groups.map((g) => g.padStart(2, '0')).join('');
  } else if (groups.length === 3) {
    if (groups.some((g) => g.length !== 4)) return null;
    hex = groups.join('');
  } else if (groups.length === 1 && groups[0].length === 12) {
    hex = groups[0];
  } else {
    return null;
  }
  return hex.toUpperCase().match(/.{2}/g)!.join(':');
}

/** True for locally administered (usually randomized/private) MACs. */
export function isRandomizedMac(mac: string): boolean {
  const normalized = normalizeMac(mac);
  if (!normalized) return false;
  return (parseInt(normalized.slice(0, 2), 16) & 0x02) !== 0;
}
