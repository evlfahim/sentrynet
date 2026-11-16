/**
 * SentryNet - Port scanner binding tests.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
import { tcpScan, tcpScanHost, WELL_KNOWN_SERVICES, DEFAULT_PORTS } from './port_scan';

const mockedInvoke = vi.mocked(invoke);

describe('WELL_KNOWN_SERVICES', () => {
  it('maps common ports to service names', () => {
    expect(WELL_KNOWN_SERVICES[22]).toBe('ssh');
    expect(WELL_KNOWN_SERVICES[80]).toBe('http');
    expect(WELL_KNOWN_SERVICES[443]).toBe('https');
    expect(WELL_KNOWN_SERVICES[3306]).toBe('mysql');
    expect(WELL_KNOWN_SERVICES[5432]).toBe('postgresql');
    expect(WELL_KNOWN_SERVICES[8080]).toBe('http-proxy');
    expect(WELL_KNOWN_SERVICES[27017]).toBe('mongodb');
  });

  it('has entries for all DEFAULT_PORTS', () => {
    for (const port of DEFAULT_PORTS) {
      expect(WELL_KNOWN_SERVICES[port]).toBeDefined();
    }
  });
});

describe('DEFAULT_PORTS', () => {
  it('is sorted', () => {
    const sorted = [...DEFAULT_PORTS].sort((a, b) => a - b);
    expect(DEFAULT_PORTS).toEqual(sorted);
  });

  it('has a reasonable number of ports', () => {
    expect(DEFAULT_PORTS.length).toBeGreaterThanOrEqual(20);
    expect(DEFAULT_PORTS.length).toBeLessThanOrEqual(100);
  });
});

describe('tcpScan', () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it('invokes the tcp_scan command with defaults', async () => {
    const result = {
      ip: '192.168.1.1',
      openPorts: [{ port: 80, protocol: 'tcp', state: 'open', latencyMs: 1.5, service: 'http' }],
      totalScanned: 35,
      elapsedMs: 450.5,
    };
    mockedInvoke.mockResolvedValue([result]);
    await expect(tcpScan({ hosts: ['192.168.1.1'] })).resolves.toEqual([result]);
    expect(mockedInvoke).toHaveBeenCalledWith('tcp_scan', {
      hosts: ['192.168.1.1'],
      ports: null,
      timeoutMs: null,
      concurrency: null,
      serviceDetection: null,
    });
  });

  it('passes custom options through', async () => {
    mockedInvoke.mockResolvedValue([]);
    await tcpScan({
      hosts: ['192.168.1.1', '192.168.1.2'],
      ports: [22, 80, 443],
      timeoutMs: 500,
      concurrency: 32,
      serviceDetection: false,
    });
    expect(mockedInvoke).toHaveBeenCalledWith('tcp_scan', {
      hosts: ['192.168.1.1', '192.168.1.2'],
      ports: [22, 80, 443],
      timeoutMs: 500,
      concurrency: 32,
      serviceDetection: false,
    });
  });

  it('propagates backend errors', async () => {
    mockedInvoke.mockRejectedValue('no hosts specified');
    await expect(tcpScan({ hosts: [] })).rejects.toBe('no hosts specified');
  });
});

describe('tcpScanHost', () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it('wraps tcpScan for a single host', async () => {
    const result = {
      ip: '192.168.1.1',
      openPorts: [{ port: 22, protocol: 'tcp', state: 'open', latencyMs: 2.0, service: 'ssh' }],
      totalScanned: 35,
      elapsedMs: 300.0,
    };
    mockedInvoke.mockResolvedValue([result]);
    const res = await tcpScanHost('192.168.1.1', { ports: [22] });
    expect(res).toEqual(result);
    expect(mockedInvoke).toHaveBeenCalledWith('tcp_scan', {
      hosts: ['192.168.1.1'],
      ports: [22],
      timeoutMs: null,
      concurrency: null,
      serviceDetection: null,
    });
  });

  it('throws when no results returned', async () => {
    mockedInvoke.mockResolvedValue([]);
    await expect(tcpScanHost('192.168.1.1')).rejects.toThrow('No scan results returned');
  });
});
