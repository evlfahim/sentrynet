/**
 * SentryNet - Latency checker bindings.
 * Thin wrapper around the Rust `check_latency` Tauri command.
 *
 * Measures network latency to hosts using:
 * - ICMP ping (via system `ping` command)
 * - HTTP HEAD requests (pure TCP, no external HTTP library)
 */

import { invoke } from '@tauri-apps/api/core';

/** A single latency sample from one measurement method. */
export interface LatencySample {
  /** Target host (IP or hostname). */
  host: string;
  /** Measurement method: "icmp" or "http". */
  method: 'icmp' | 'http';
  /** Response time in milliseconds. Null if the probe failed. */
  latencyMs: number | null;
  /** Whether the probe succeeded. */
  success: boolean;
  /** Extra details (e.g. HTTP status code, ICMP TTL). */
  details: string | null;
  /** Timestamp of the measurement (ISO 8601 UTC). */
  timestamp: string;
}

/** Result of a full latency check on a single host. */
export interface HostLatencyResult {
  /** Target host. */
  host: string;
  /** All samples collected. */
  samples: LatencySample[];
  /** Average latency across successful samples (ms), or null if all failed. */
  avgLatencyMs: number | null;
  /** Minimum latency across successful samples (ms), or null. */
  minLatencyMs: number | null;
  /** Maximum latency across successful samples (ms), or null. */
  maxLatencyMs: number | null;
  /** Packet loss percentage (0.0–100.0). */
  packetLoss: number;
  /** Total time spent measuring (ms). */
  elapsedMs: number;
}

/** Options for the latency checker. */
export interface LatencyCheckOptions {
  /** Target IP addresses or hostnames. */
  hosts: string[];
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
}

/**
 * Check latency to one or more hosts using ICMP ping and HTTP HEAD.
 *
 * Returns an array of `HostLatencyResult`, one per host.
 */
export async function checkLatency(options: LatencyCheckOptions): Promise<HostLatencyResult[]> {
  return invoke<HostLatencyResult[]>('check_latency', {
    hosts: options.hosts,
    pingCount: options.pingCount ?? null,
    pingTimeoutMs: options.pingTimeoutMs ?? null,
    httpPort: options.httpPort ?? null,
    httpPath: options.httpPath ?? null,
    httpTimeoutMs: options.httpTimeoutMs ?? null,
  });
}

/**
 * Check latency to a single host.
 * Convenience wrapper around `checkLatency`.
 */
export async function checkLatencyHost(
  host: string,
  options: Omit<LatencyCheckOptions, 'hosts'> = {},
): Promise<HostLatencyResult> {
  const results = await checkLatency({ hosts: [host], ...options });
  if (results.length === 0) {
    throw new Error('No latency results returned');
  }
  return results[0];
}

/**
 * Quick ICMP ping to a single host (default options).
 * Returns an array of `LatencySample`, one per probe.
 */
export async function pingHost(
  host: string,
  count: number = 4,
  timeoutMs: number = 3000,
): Promise<LatencySample[]> {
  const result = await checkLatencyHost(host, { pingCount: count, pingTimeoutMs: timeoutMs });
  return result.samples.filter((s) => s.method === 'icmp');
}

/**
 * Quick HTTP HEAD check to a single host (default options).
 * Returns the `LatencySample` for the HTTP probe.
 */
export async function httpCheck(
  host: string,
  port: number = 80,
  path: string = '/',
  timeoutMs: number = 3000,
): Promise<LatencySample> {
  const result = await checkLatencyHost(host, {
    httpPort: port,
    httpPath: path,
    httpTimeoutMs: timeoutMs,
  });
  const httpSample = result.samples.find((s) => s.method === 'http');
  if (!httpSample) {
    throw new Error('No HTTP sample returned');
  }
  return httpSample;
}
