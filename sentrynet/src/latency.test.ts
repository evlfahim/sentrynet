/**
 * SentryNet - Latency checker binding tests.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
import {
  checkLatency,
  checkLatencyHost,
  pingHost,
  httpCheck,
  type LatencySample,
  type HostLatencyResult,
} from './latency';

const mockedInvoke = vi.mocked(invoke);

describe('LatencySample', () => {
  it('has the correct shape', () => {
    const sample: LatencySample = {
      host: '192.168.1.1',
      method: 'icmp',
      latencyMs: 1.5,
      success: true,
      details: 'ttl=64',
      timestamp: '2024-01-01T00:00:00+00:00',
    };
    expect(sample.host).toBe('192.168.1.1');
    expect(sample.method).toBe('icmp');
    expect(sample.latencyMs).toBe(1.5);
    expect(sample.success).toBe(true);
    expect(sample.details).toBe('ttl=64');
  });

  it('handles failed samples', () => {
    const sample: LatencySample = {
      host: '192.168.1.1',
      method: 'http',
      latencyMs: null,
      success: false,
      details: 'connection refused',
      timestamp: '2024-01-01T00:00:00+00:00',
    };
    expect(sample.latencyMs).toBeNull();
    expect(sample.success).toBe(false);
  });
});

describe('HostLatencyResult', () => {
  it('has the correct shape', () => {
    const result: HostLatencyResult = {
      host: '192.168.1.1',
      samples: [],
      avgLatencyMs: 2.5,
      minLatencyMs: 1.0,
      maxLatencyMs: 4.0,
      packetLoss: 0.0,
      elapsedMs: 100.0,
    };
    expect(result.host).toBe('192.168.1.1');
    expect(result.avgLatencyMs).toBe(2.5);
    expect(result.minLatencyMs).toBe(1.0);
    expect(result.maxLatencyMs).toBe(4.0);
    expect(result.packetLoss).toBe(0.0);
  });

  it('handles all-failed results', () => {
    const result: HostLatencyResult = {
      host: '192.168.1.1',
      samples: [],
      avgLatencyMs: null,
      minLatencyMs: null,
      maxLatencyMs: null,
      packetLoss: 100.0,
      elapsedMs: 50.0,
    };
    expect(result.avgLatencyMs).toBeNull();
    expect(result.packetLoss).toBe(100.0);
  });
});

describe('checkLatency', () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it('invokes the check_latency command with defaults', async () => {
    const result: HostLatencyResult = {
      host: '192.168.1.1',
      samples: [
        {
          host: '192.168.1.1',
          method: 'icmp',
          latencyMs: 1.5,
          success: true,
          details: 'ttl=64',
          timestamp: '2024-01-01T00:00:00+00:00',
        },
      ],
      avgLatencyMs: 1.5,
      minLatencyMs: 1.5,
      maxLatencyMs: 1.5,
      packetLoss: 0.0,
      elapsedMs: 50.0,
    };
    mockedInvoke.mockResolvedValue([result]);
    await expect(checkLatency({ hosts: ['192.168.1.1'] })).resolves.toEqual([result]);
    expect(mockedInvoke).toHaveBeenCalledWith('check_latency', {
      hosts: ['192.168.1.1'],
      pingCount: null,
      pingTimeoutMs: null,
      httpPort: null,
      httpPath: null,
      httpTimeoutMs: null,
    });
  });

  it('passes custom options through', async () => {
    mockedInvoke.mockResolvedValue([]);
    await checkLatency({
      hosts: ['192.168.1.1', '192.168.1.2'],
      pingCount: 6,
      pingTimeoutMs: 5000,
      httpPort: 8080,
      httpPath: '/health',
      httpTimeoutMs: 2000,
    });
    expect(mockedInvoke).toHaveBeenCalledWith('check_latency', {
      hosts: ['192.168.1.1', '192.168.1.2'],
      pingCount: 6,
      pingTimeoutMs: 5000,
      httpPort: 8080,
      httpPath: '/health',
      httpTimeoutMs: 2000,
    });
  });

  it('propagates backend errors', async () => {
    mockedInvoke.mockRejectedValue('no hosts specified');
    await expect(checkLatency({ hosts: [] })).rejects.toBe('no hosts specified');
  });
});

describe('checkLatencyHost', () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it('wraps checkLatency for a single host', async () => {
    const result: HostLatencyResult = {
      host: '192.168.1.1',
      samples: [
        {
          host: '192.168.1.1',
          method: 'icmp',
          latencyMs: 1.5,
          success: true,
          details: 'ttl=64',
          timestamp: '2024-01-01T00:00:00+00:00',
        },
      ],
      avgLatencyMs: 1.5,
      minLatencyMs: 1.5,
      maxLatencyMs: 1.5,
      packetLoss: 0.0,
      elapsedMs: 50.0,
    };
    mockedInvoke.mockResolvedValue([result]);
    const res = await checkLatencyHost('192.168.1.1', { pingCount: 2 });
    expect(res).toEqual(result);
    expect(mockedInvoke).toHaveBeenCalledWith('check_latency', {
      hosts: ['192.168.1.1'],
      pingCount: 2,
      pingTimeoutMs: null,
      httpPort: null,
      httpPath: null,
      httpTimeoutMs: null,
    });
  });

  it('throws when no results returned', async () => {
    mockedInvoke.mockResolvedValue([]);
    await expect(checkLatencyHost('192.168.1.1')).rejects.toThrow('No latency results returned');
  });
});

describe('pingHost', () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it('filters ICMP samples from the result', async () => {
    const icmpSample: LatencySample = {
      host: '192.168.1.1',
      method: 'icmp',
      latencyMs: 1.5,
      success: true,
      details: 'ttl=64',
      timestamp: '2024-01-01T00:00:00+00:00',
    };
    const httpSample: LatencySample = {
      host: '192.168.1.1',
      method: 'http',
      latencyMs: 5.0,
      success: true,
      details: 'HTTP 200',
      timestamp: '2024-01-01T00:00:00+00:00',
    };
    const result: HostLatencyResult = {
      host: '192.168.1.1',
      samples: [icmpSample, httpSample],
      avgLatencyMs: 3.25,
      minLatencyMs: 1.5,
      maxLatencyMs: 5.0,
      packetLoss: 0.0,
      elapsedMs: 100.0,
    };
    mockedInvoke.mockResolvedValue([result]);
    const samples = await pingHost('192.168.1.1', 4, 3000);
    expect(samples).toEqual([icmpSample]);
    expect(mockedInvoke).toHaveBeenCalledWith('check_latency', {
      hosts: ['192.168.1.1'],
      pingCount: 4,
      pingTimeoutMs: 3000,
      httpPort: null,
      httpPath: null,
      httpTimeoutMs: null,
    });
  });
});

describe('httpCheck', () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it('returns the HTTP sample from the result', async () => {
    const icmpSample: LatencySample = {
      host: '192.168.1.1',
      method: 'icmp',
      latencyMs: 1.5,
      success: true,
      details: 'ttl=64',
      timestamp: '2024-01-01T00:00:00+00:00',
    };
    const httpSample: LatencySample = {
      host: '192.168.1.1',
      method: 'http',
      latencyMs: 5.0,
      success: true,
      details: 'HTTP 200',
      timestamp: '2024-01-01T00:00:00+00:00',
    };
    const result: HostLatencyResult = {
      host: '192.168.1.1',
      samples: [icmpSample, httpSample],
      avgLatencyMs: 3.25,
      minLatencyMs: 1.5,
      maxLatencyMs: 5.0,
      packetLoss: 0.0,
      elapsedMs: 100.0,
    };
    mockedInvoke.mockResolvedValue([result]);
    const sample = await httpCheck('192.168.1.1', 80, '/', 3000);
    expect(sample).toEqual(httpSample);
    expect(mockedInvoke).toHaveBeenCalledWith('check_latency', {
      hosts: ['192.168.1.1'],
      pingCount: null,
      pingTimeoutMs: null,
      httpPort: 80,
      httpPath: '/',
      httpTimeoutMs: 3000,
    });
  });

  it('throws when no HTTP sample is returned', async () => {
    const result: HostLatencyResult = {
      host: '192.168.1.1',
      samples: [
        {
          host: '192.168.1.1',
          method: 'icmp',
          latencyMs: 1.5,
          success: true,
          details: 'ttl=64',
          timestamp: '2024-01-01T00:00:00+00:00',
        },
      ],
      avgLatencyMs: 1.5,
      minLatencyMs: 1.5,
      maxLatencyMs: 1.5,
      packetLoss: 0.0,
      elapsedMs: 50.0,
    };
    mockedInvoke.mockResolvedValue([result]);
    await expect(httpCheck('192.168.1.1')).rejects.toThrow('No HTTP sample returned');
  });
});
