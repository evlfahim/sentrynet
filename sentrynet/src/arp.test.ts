/**
 * SentryNet - ARP binding tests.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
import { arpScan, normalizeMac, isRandomizedMac, type ArpEntry } from './arp';

const mockedInvoke = vi.mocked(invoke);

describe('normalizeMac', () => {
  it('accepts common notations', () => {
    expect(normalizeMac('00:1a:2b:3c:4d:5e')).toBe('00:1A:2B:3C:4D:5E');
    expect(normalizeMac('00-1A-2B-3C-4D-5E')).toBe('00:1A:2B:3C:4D:5E');
    expect(normalizeMac('0:1a:2b:3c:4d:5e')).toBe('00:1A:2B:3C:4D:5E');
    expect(normalizeMac('001a.2b3c.4d5e')).toBe('00:1A:2B:3C:4D:5E');
    expect(normalizeMac('001A2B3C4D5E')).toBe('00:1A:2B:3C:4D:5E');
  });

  it('rejects invalid input', () => {
    expect(normalizeMac('')).toBeNull();
    expect(normalizeMac('00:1a:2b:3c:4d')).toBeNull();
    expect(normalizeMac('gg:hh:ii:jj:kk:ll')).toBeNull();
    expect(normalizeMac('192.168.1.1')).toBeNull();
    expect(normalizeMac('(incomplete)')).toBeNull();
  });
});

describe('isRandomizedMac', () => {
  it('detects locally administered MACs', () => {
    expect(isRandomizedMac('da:a1:19:00:00:01')).toBe(true);
    expect(isRandomizedMac('b8:27:eb:12:34:56')).toBe(false);
    expect(isRandomizedMac('not-a-mac')).toBe(false);
  });
});

describe('arpScan', () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it('invokes the arp_scan command with defaults', async () => {
    const entries: ArpEntry[] = [
      { ip: '192.168.1.1', mac: 'B8:27:EB:12:34:56', vendor: 'Raspberry Pi', interface: 'eth0' },
    ];
    mockedInvoke.mockResolvedValue(entries);
    await expect(arpScan()).resolves.toEqual(entries);
    expect(mockedInvoke).toHaveBeenCalledWith('arp_scan', { cidr: null, settleMs: null });
  });

  it('passes subnet and settle time through', async () => {
    mockedInvoke.mockResolvedValue([]);
    await arpScan({ cidr: '10.0.0.0/24', settleMs: 500 });
    expect(mockedInvoke).toHaveBeenCalledWith('arp_scan', { cidr: '10.0.0.0/24', settleMs: 500 });
  });

  it('propagates backend errors', async () => {
    mockedInvoke.mockRejectedValue('invalid CIDR subnet: nope');
    await expect(arpScan({ cidr: 'nope' })).rejects.toBe('invalid CIDR subnet: nope');
  });
});
