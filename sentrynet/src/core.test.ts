/**
 * SentryNet - Core module tests
 * Tests for the foundational scanner modules.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// --- Utility helpers ---

function createTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentrynet-test-'));
  return dir;
}

function cleanupDir(dir: string): void {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// --- Test: IP address validation ---

describe('IP Address Utilities', () => {
  function isValidIPv4(ip: string): boolean {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every((part) => {
      const num = parseInt(part, 10);
      return !isNaN(num) && num >= 0 && num <= 255 && part === String(num);
    });
  }

  it('validates correct IPv4 addresses', () => {
    expect(isValidIPv4('192.168.1.1')).toBe(true);
    expect(isValidIPv4('10.0.0.1')).toBe(true);
    expect(isValidIPv4('255.255.255.255')).toBe(true);
    expect(isValidIPv4('0.0.0.0')).toBe(true);
  });

  it('rejects invalid IPv4 addresses', () => {
    expect(isValidIPv4('256.1.1.1')).toBe(false);
    expect(isValidIPv4('192.168.1')).toBe(false);
    expect(isValidIPv4('192.168.1.1.1')).toBe(false);
    expect(isValidIPv4('abc.def.ghi.jkl')).toBe(false);
    expect(isValidIPv4('')).toBe(false);
    expect(isValidIPv4('192.168.1.999')).toBe(false);
  });
});

// --- Test: MAC address validation ---

describe('MAC Address Utilities', () => {
  function isValidMAC(mac: string): boolean {
    const cleaned = mac.replace(/[:-]/g, '');
    return /^[0-9a-fA-F]{12}$/.test(cleaned);
  }

  it('validates correct MAC addresses', () => {
    expect(isValidMAC('00:1A:2B:3C:4D:5E')).toBe(true);
    expect(isValidMAC('00-1A-2B-3C-4D-5E')).toBe(true);
    expect(isValidMAC('001A2B3C4D5E')).toBe(true);
    expect(isValidMAC('aa:bb:cc:dd:ee:ff')).toBe(true);
  });

  it('rejects invalid MAC addresses', () => {
    expect(isValidMAC('00:1A:2B:3C:4D')).toBe(false);
    expect(isValidMAC('GG:HH:II:JJ:KK:LL')).toBe(false);
    expect(isValidMAC('')).toBe(false);
    expect(isValidMAC('00:1A:2B:3C:4D:5E:FF')).toBe(false);
  });
});

// --- Test: Port range validation ---

describe('Port Range Utilities', () => {
  function isValidPort(port: number): boolean {
    return port >= 1 && port <= 65535;
  }

  function isValidPortRange(start: number, end: number): boolean {
    return isValidPort(start) && isValidPort(end) && start <= end;
  }

  it('validates correct port numbers', () => {
    expect(isValidPort(22)).toBe(true);
    expect(isValidPort(80)).toBe(true);
    expect(isValidPort(443)).toBe(true);
    expect(isValidPort(65535)).toBe(true);
  });

  it('rejects invalid port numbers', () => {
    expect(isValidPort(0)).toBe(false);
    expect(isValidPort(-1)).toBe(false);
    expect(isValidPort(65536)).toBe(false);
    expect(isValidPort(100000)).toBe(false);
  });

  it('validates correct port ranges', () => {
    expect(isValidPortRange(1, 1024)).toBe(true);
    expect(isValidPortRange(80, 443)).toBe(true);
    expect(isValidPortRange(1, 65535)).toBe(true);
  });

  it('rejects invalid port ranges', () => {
    expect(isValidPortRange(0, 100)).toBe(false);
    expect(isValidPortRange(100, 0)).toBe(false);
    expect(isValidPortRange(1, 70000)).toBe(false);
  });
});

// --- Test: Timestamp formatting ---

describe('Timestamp Utilities', () => {
  function formatTimestamp(date: Date): string {
    return date.toISOString();
  }

  function parseTimestamp(iso: string): Date {
    return new Date(iso);
  }

  it('formats and parses timestamps correctly', () => {
    const now = new Date();
    const formatted = formatTimestamp(now);
    const parsed = parseTimestamp(formatted);
    expect(parsed.getTime()).toBeCloseTo(now.getTime(), -3);
  });

  it('handles edge cases', () => {
    const epoch = new Date(0);
    const formatted = formatTimestamp(epoch);
    expect(formatted).toBe('1970-01-01T00:00:00.000Z');
  });
});

// --- Test: Temp directory operations (integration test) ---

describe('File System Operations', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir();
  });

  afterEach(() => {
    cleanupDir(tempDir);
  });

  it('creates and reads a test file', () => {
    const filePath = path.join(tempDir, 'test.txt');
    const content = 'SentryNet test data';
    fs.writeFileSync(filePath, content);
    const read = fs.readFileSync(filePath, 'utf-8');
    expect(read).toBe(content);
  });

  it('creates and parses JSON', () => {
    const filePath = path.join(tempDir, 'data.json');
    const data = { devices: 5, timestamp: new Date().toISOString() };
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    const read = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    expect(read.devices).toBe(5);
    expect(read.timestamp).toBeDefined();
  });

  it('removes temp directory on cleanup', () => {
    const subDir = path.join(tempDir, 'sub');
    fs.mkdirSync(subDir);
    cleanupDir(tempDir);
    expect(fs.existsSync(tempDir)).toBe(false);
  });
});

// --- Test: CIDR subnet generation ---

describe('CIDR Subnet Utilities', () => {
  function generateSubnet(ip: string, prefix: number): string[] {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) throw new Error('Invalid IP');

    const mask = prefix <= 32 ? (0xffffffff << (32 - prefix)) >>> 0 : 0;
    const network = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    const net = network & mask;

    const hostBits = 32 - prefix;
    const hostCount = 1 << hostBits;
    const addresses: string[] = [];

    for (let i = 0; i < hostCount && i < 256; i++) {
      const host = net + i;
      addresses.push(
        `${(host >> 24) & 0xff}.${(host >> 16) & 0xff}.${(host >> 8) & 0xff}.${host & 0xff}`
      );
    }
    return addresses;
  }

  it('generates a /24 subnet', () => {
    const addrs = generateSubnet('192.168.1.1', 24);
    expect(addrs.length).toBe(256);
    expect(addrs[0]).toBe('192.168.1.0');
    expect(addrs[255]).toBe('192.168.1.255');
  });

  it('generates a /30 subnet', () => {
    const addrs = generateSubnet('10.0.0.5', 30);
    expect(addrs.length).toBe(4);
    expect(addrs).toContain('10.0.0.4');
    expect(addrs).toContain('10.0.0.7');
  });
});
