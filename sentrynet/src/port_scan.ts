/**
 * SentryNet - TCP port scanner bindings.
 * Thin wrapper around the Rust `tcp_scan` Tauri command.
 */

import { invoke } from '@tauri-apps/api/core';

/** Result of scanning a single TCP port. */
export interface PortResult {
  port: number;
  protocol: 'tcp';
  state: 'open' | 'closed' | 'filtered';
  latencyMs: number | null;
  service: string | null;
}

/** A single host's scan results. */
export interface HostScanResult {
  ip: string;
  openPorts: PortResult[];
  totalScanned: number;
  elapsedMs: number;
}

/** Options for the TCP port scan. */
export interface TcpScanOptions {
  /** Target IP addresses. */
  hosts: string[];
  /** Port numbers to scan. Empty = default well-known ports. */
  ports?: number[];
  /** Timeout per port in milliseconds (default 1000). */
  timeoutMs?: number;
  /** Maximum concurrent connections (default 64). */
  concurrency?: number;
  /** Attempt banner-based service detection (default true). */
  serviceDetection?: boolean;
}

/**
 * Scan TCP ports on one or more hosts.
 *
 * Returns an array of `HostScanResult`, one per host.
 */
export async function tcpScan(options: TcpScanOptions): Promise<HostScanResult[]> {
  return invoke<HostScanResult[]>('tcp_scan', {
    hosts: options.hosts,
    ports: options.ports ?? null,
    timeoutMs: options.timeoutMs ?? null,
    concurrency: options.concurrency ?? null,
    serviceDetection: options.serviceDetection ?? null,
  });
}

/**
 * Scan TCP ports on a single host.
 * Convenience wrapper around `tcpScan`.
 */
export async function tcpScanHost(
  host: string,
  options: Omit<TcpScanOptions, 'hosts'> = {},
): Promise<HostScanResult> {
  const results = await tcpScan({ hosts: [host], ...options });
  if (results.length === 0) {
    throw new Error('No scan results returned');
  }
  return results[0];
}

/**
 * Well-known service names for common ports.
 * Mirrors the Rust `WELL_KNOWN_SERVICES` table.
 */
export const WELL_KNOWN_SERVICES: Record<number, string> = {
  20: 'ftp-data',
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  67: 'dhcp',
  68: 'dhcp',
  69: 'tftp',
  80: 'http',
  110: 'pop3',
  111: 'rpcbind',
  119: 'nntp',
  123: 'ntp',
  135: 'msrpc',
  137: 'netbios-ns',
  138: 'netbios-dgm',
  139: 'netbios-ssn',
  143: 'imap',
  161: 'snmp',
  162: 'snmptrap',
  179: 'bgp',
  389: 'ldap',
  443: 'https',
  445: 'microsoft-ds',
  465: 'smtps',
  514: 'syslog',
  515: 'printer',
  520: 'rip',
  523: 'ibm-db2',
  554: 'rtsp',
  587: 'submission',
  631: 'ipp',
  636: 'ldaps',
  993: 'imaps',
  995: 'pop3s',
  1080: 'socks',
  1433: 'mssql',
  1521: 'oracle',
  1723: 'pptp',
  1900: 'upnp',
  2049: 'nfs',
  3306: 'mysql',
  3389: 'rdp',
  5060: 'sip',
  5432: 'postgresql',
  5900: 'vnc',
  6379: 'redis',
  8080: 'http-proxy',
  8443: 'https-alt',
  9200: 'elasticsearch',
  11211: 'memcached',
  27017: 'mongodb',
};

/** Default well-known ports to scan. */
export const DEFAULT_PORTS: number[] = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 554, 587, 631,
  993, 995, 1723, 2049, 3306, 3389, 5060, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
];
