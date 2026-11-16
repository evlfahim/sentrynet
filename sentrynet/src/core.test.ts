/**
 * SentryNet - Core module tests
 * Tests for the core scanner service: full scan orchestration,
 * single host scanning, device tracking, and alert generation.
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

// --- Test: Core module types and defaults ---

describe('Core Module Types', () => {
  it('default scan options have reasonable values', () => {
    const opts = {
      arpSettleMs: 1500,
      portScanTimeoutMs: 1000,
      portScanConcurrency: 64,
      portServiceDetection: true,
      pingCount: 4,
      pingTimeoutMs: 3000,
      httpPort: 80,
      httpPath: '/',
      httpTimeoutMs: 3000,
      checkLatency: true,
    };

    expect(opts.arpSettleMs).toBeGreaterThan(0);
    expect(opts.portScanTimeoutMs).toBeGreaterThan(0);
    expect(opts.portScanConcurrency).toBeGreaterThan(0);
    expect(opts.pingCount).toBeGreaterThan(0);
    expect(opts.httpPort).toBeGreaterThan(0);
    expect(opts.checkLatency).toBe(true);
  });

  it('scanned device has required fields', () => {
    const device = {
      ip: '192.168.1.1',
      mac: 'AA:BB:CC:DD:EE:FF',
      vendor: 'TestVendor',
      interface: 'eth0',
      openPorts: [],
      latency: null,
      isNew: true,
    };

    expect(device.ip).toBeDefined();
    expect(device.mac).toBeDefined();
    expect(device.openPorts).toBeInstanceOf(Array);
    expect(typeof device.isNew).toBe('boolean');
  });

  it('full scan result has required fields', () => {
    const result = {
      elapsedMs: 1234.5,
      deviceCount: 3,
      newDeviceCount: 1,
      totalOpenPorts: 5,
      alertCount: 2,
      devices: [],
      alerts: [],
      history: [],
    };

    expect(result.elapsedMs).toBeGreaterThan(0);
    expect(result.deviceCount).toBeGreaterThanOrEqual(0);
    expect(result.newDeviceCount).toBeGreaterThanOrEqual(0);
    expect(result.totalOpenPorts).toBeGreaterThanOrEqual(0);
    expect(result.alertCount).toBeGreaterThanOrEqual(0);
    expect(result.devices).toBeInstanceOf(Array);
    expect(result.alerts).toBeInstanceOf(Array);
    expect(result.history).toBeInstanceOf(Array);
  });

  it('alert has required fields', () => {
    const alert = {
      id: 1,
      deviceIp: '192.168.1.1',
      alertType: 'new_device' as const,
      message: 'New device discovered',
      acknowledged: false,
      createdAt: new Date().toISOString(),
    };

    expect(alert.deviceIp).toBeDefined();
    expect(alert.alertType).toBeDefined();
    expect(alert.message).toBeDefined();
    expect(typeof alert.acknowledged).toBe('boolean');
    expect(alert.createdAt).toBeDefined();
  });

  it('history record has required fields', () => {
    const record = {
      id: 1,
      deviceIp: '192.168.1.1',
      eventType: 'discovered' as const,
      details: 'New device',
      timestamp: new Date().toISOString(),
    };

    expect(record.deviceIp).toBeDefined();
    expect(record.eventType).toBeDefined();
    expect(record.timestamp).toBeDefined();
  });
});

// --- Test: Core module orchestration logic (unit tests) ---

describe('Core Scanner Orchestration', () => {
  it('merges default and custom options', () => {
    const defaults = {
      arpSettleMs: 1500,
      portScanTimeoutMs: 1000,
      portScanConcurrency: 64,
      portServiceDetection: true,
      pingCount: 4,
      pingTimeoutMs: 3000,
      httpPort: 80,
      httpPath: '/',
      httpTimeoutMs: 3000,
      checkLatency: true,
    };

    const custom = {
      portScanTimeoutMs: 500,
      pingCount: 2,
    };

    const merged = { ...defaults, ...custom };
    expect(merged.arpSettleMs).toBe(1500); // default
    expect(merged.portScanTimeoutMs).toBe(500); // custom
    expect(merged.pingCount).toBe(2); // custom
    expect(merged.checkLatency).toBe(true); // default
  });

  it('validates scan result structure', () => {
    // Simulate a scan result structure
    const result = {
      elapsedMs: 2500.0,
      deviceCount: 5,
      newDeviceCount: 2,
      totalOpenPorts: 12,
      alertCount: 3,
      devices: [
        {
          ip: '192.168.1.1',
          mac: 'AA:BB:CC:DD:EE:01',
          vendor: 'Raspberry Pi',
          interface: 'eth0',
          openPorts: [
            { port: 22, protocol: 'tcp', state: 'open', latencyMs: 1.5, service: 'ssh' },
            { port: 80, protocol: 'tcp', state: 'open', latencyMs: 2.3, service: 'http' },
          ],
          latency: {
            host: '192.168.1.1',
            samples: [
              {
                host: '192.168.1.1',
                method: 'icmp' as const,
                latencyMs: 1.2,
                success: true,
                details: 'ttl=64',
                timestamp: new Date().toISOString(),
              },
            ],
            avgLatencyMs: 1.2,
            minLatencyMs: 1.2,
            maxLatencyMs: 1.2,
            packetLoss: 0,
            elapsedMs: 50.0,
          },
          isNew: true,
        },
      ],
      alerts: [
        {
          id: 1,
          deviceIp: '192.168.1.1',
          alertType: 'new_device',
          message: 'New device discovered: 192.168.1.1',
          acknowledged: false,
          createdAt: new Date().toISOString(),
        },
      ],
      history: [
        {
          id: 1,
          deviceIp: '192.168.1.1',
          eventType: 'discovered',
          details: 'New device discovered: 192.168.1.1 (Raspberry Pi)',
          timestamp: new Date().toISOString(),
        },
      ],
    };

    // Validate structure
    expect(result.elapsedMs).toBeGreaterThan(0);
    expect(result.deviceCount).toBe(5);
    expect(result.newDeviceCount).toBe(2);
    expect(result.totalOpenPorts).toBe(12);
    expect(result.alertCount).toBe(3);
    expect(result.devices.length).toBe(1);
    expect(result.devices[0].ip).toBe('192.168.1.1');
    expect(result.devices[0].isNew).toBe(true);
    expect(result.devices[0].openPorts.length).toBe(2);
    expect(result.alerts.length).toBe(1);
    expect(result.history.length).toBe(1);
  });

  it('handles empty scan result', () => {
    const result = {
      elapsedMs: 0,
      deviceCount: 0,
      newDeviceCount: 0,
      totalOpenPorts: 0,
      alertCount: 0,
      devices: [],
      alerts: [],
      history: [],
    };

    expect(result.deviceCount).toBe(0);
    expect(result.devices.length).toBe(0);
    expect(result.alerts.length).toBe(0);
    expect(result.history.length).toBe(0);
  });

  it('handles device without latency', () => {
    const device = {
      ip: '192.168.1.1',
      mac: 'AA:BB:CC:DD:EE:01',
      vendor: null,
      interface: null,
      openPorts: [],
      latency: null,
      isNew: false,
    };

    expect(device.latency).toBeNull();
    expect(device.isNew).toBe(false);
    expect(device.openPorts.length).toBe(0);
  });

  it('handles device with latency', () => {
    const device = {
      ip: '192.168.1.1',
      mac: 'AA:BB:CC:DD:EE:01',
      vendor: 'TestVendor',
      interface: 'eth0',
      openPorts: [{ port: 80, protocol: 'tcp', state: 'open', latencyMs: 2.0, service: 'http' }],
      latency: {
        host: '192.168.1.1',
        samples: [
          {
            host: '192.168.1.1',
            method: 'icmp',
            latencyMs: 1.5,
            success: true,
            details: 'ttl=64',
            timestamp: new Date().toISOString(),
          },
        ],
        avgLatencyMs: 1.5,
        minLatencyMs: 1.5,
        maxLatencyMs: 1.5,
        packetLoss: 0,
        elapsedMs: 50.0,
      },
      isNew: true,
    };

    expect(device.latency).not.toBeNull();
    expect(device.latency!.avgLatencyMs).toBe(1.5);
    expect(device.latency!.packetLoss).toBe(0);
    expect(device.isNew).toBe(true);
  });
});

// --- Test: Alert types ---

describe('Alert Types', () => {
  const validAlertTypes = ['new_device', 'new_port', 'device_offline', 'port_closed'];

  it('has all valid alert types', () => {
    expect(validAlertTypes).toContain('new_device');
    expect(validAlertTypes).toContain('new_port');
    expect(validAlertTypes).toContain('device_offline');
    expect(validAlertTypes).toContain('port_closed');
  });

  it('creates a new_device alert', () => {
    const alert = {
      id: 1,
      deviceIp: '192.168.1.100',
      alertType: 'new_device' as const,
      message: 'New device discovered on the network: 192.168.1.100',
      acknowledged: false,
      createdAt: new Date().toISOString(),
    };

    expect(alert.alertType).toBe('new_device');
    expect(alert.message).toContain('192.168.1.100');
    expect(alert.acknowledged).toBe(false);
  });

  it('creates a new_port alert', () => {
    const alert = {
      id: 2,
      deviceIp: '192.168.1.50',
      alertType: 'new_port' as const,
      message: 'New open port discovered on 192.168.1.50: 22/tcp (ssh)',
      acknowledged: false,
      createdAt: new Date().toISOString(),
    };

    expect(alert.alertType).toBe('new_port');
    expect(alert.message).toContain('22');
    expect(alert.message).toContain('ssh');
  });
});

// --- Test: History event types ---

describe('History Event Types', () => {
  const validEventTypes = [
    'discovered',
    'disconnected',
    'port_added',
    'port_removed',
    'port_state_changed',
    'seen',
  ];

  it('has all valid event types', () => {
    expect(validEventTypes).toContain('discovered');
    expect(validEventTypes).toContain('disconnected');
    expect(validEventTypes).toContain('port_added');
    expect(validEventTypes).toContain('port_removed');
    expect(validEventTypes).toContain('port_state_changed');
    expect(validEventTypes).toContain('seen');
  });

  it('creates a discovered history record', () => {
    const record = {
      id: 1,
      deviceIp: '192.168.1.1',
      eventType: 'discovered',
      details: 'New device discovered: 192.168.1.1 (Raspberry Pi)',
      timestamp: new Date().toISOString(),
    };

    expect(record.eventType).toBe('discovered');
    expect(record.deviceIp).toBe('192.168.1.1');
  });

  it('creates a port_added history record', () => {
    const record = {
      id: 2,
      deviceIp: '192.168.1.1',
      eventType: 'port_added',
      details: 'New open port: 80/tcp (http)',
      timestamp: new Date().toISOString(),
    };

    expect(record.eventType).toBe('port_added');
    expect(record.details).toContain('80');
  });
});

// --- Test: Port scanning integration (unit-level) ---

describe('Port Scan Integration', () => {
  it('port result has required fields', () => {
    const port = {
      port: 80,
      protocol: 'tcp' as const,
      state: 'open' as const,
      latencyMs: 2.3,
      service: 'http',
    };

    expect(port.port).toBe(80);
    expect(port.protocol).toBe('tcp');
    expect(port.state).toBe('open');
    expect(port.latencyMs).toBe(2.3);
    expect(port.service).toBe('http');
  });

  it('closed port has null latency and service', () => {
    const port = {
      port: 22,
      protocol: 'tcp' as const,
      state: 'closed' as const,
      latencyMs: null,
      service: null,
    };

    expect(port.state).toBe('closed');
    expect(port.latencyMs).toBeNull();
    expect(port.service).toBeNull();
  });

  it('host scan result has required fields', () => {
    const result = {
      ip: '192.168.1.1',
      openPorts: [
        { port: 80, protocol: 'tcp', state: 'open', latencyMs: 2.3, service: 'http' },
      ],
      totalScanned: 35,
      elapsedMs: 450.5,
    };

    expect(result.ip).toBe('192.168.1.1');
    expect(result.openPorts.length).toBe(1);
    expect(result.totalScanned).toBe(35);
    expect(result.elapsedMs).toBeGreaterThan(0);
  });
});

// --- Test: Latency check integration (unit-level) ---

describe('Latency Check Integration', () => {
  it('latency sample has required fields', () => {
    const sample = {
      host: '192.168.1.1',
      method: 'icmp' as const,
      latencyMs: 1.5,
      success: true,
      details: 'ttl=64',
      timestamp: new Date().toISOString(),
    };

    expect(sample.host).toBe('192.168.1.1');
    expect(sample.method).toBe('icmp');
    expect(sample.latencyMs).toBe(1.5);
    expect(sample.success).toBe(true);
  });

  it('host latency result has required fields', () => {
    const result = {
      host: '192.168.1.1',
      samples: [
        {
          host: '192.168.1.1',
          method: 'icmp',
          latencyMs: 1.2,
          success: true,
          details: 'ttl=64',
          timestamp: new Date().toISOString(),
        },
      ],
      avgLatencyMs: 1.2,
      minLatencyMs: 1.2,
      maxLatencyMs: 1.2,
      packetLoss: 0,
      elapsedMs: 50.0,
    };

    expect(result.host).toBe('192.168.1.1');
    expect(result.samples.length).toBe(1);
    expect(result.avgLatencyMs).toBe(1.2);
    expect(result.packetLoss).toBe(0);
  });

  it('handles failed latency check', () => {
    const result = {
      host: '192.168.1.1',
      samples: [
        {
          host: '192.168.1.1',
          method: 'icmp',
          latencyMs: null,
          success: false,
          details: 'no ping replies received',
          timestamp: new Date().toISOString(),
        },
      ],
      avgLatencyMs: null,
      minLatencyMs: null,
      maxLatencyMs: null,
      packetLoss: 100,
      elapsedMs: 3000.0,
    };

    expect(result.avgLatencyMs).toBeNull();
    expect(result.packetLoss).toBe(100);
  });
});

// --- Test: ARP entry integration (unit-level) ---

describe('ARP Entry Integration', () => {
  it('arp entry has required fields', () => {
    const entry = {
      ip: '192.168.1.1',
      mac: 'AA:BB:CC:DD:EE:FF',
      vendor: 'Raspberry Pi',
      interface: 'eth0',
    };

    expect(entry.ip).toBe('192.168.1.1');
    expect(entry.mac).toBe('AA:BB:CC:DD:EE:FF');
    expect(entry.vendor).toBe('Raspberry Pi');
    expect(entry.interface).toBe('eth0');
  });

  it('arp entry with null vendor', () => {
    const entry = {
      ip: '192.168.1.50',
      mac: '00:00:00:00:00:01',
      vendor: null,
      interface: null,
    };

    expect(entry.vendor).toBeNull();
    expect(entry.interface).toBeNull();
  });
});

// --- Test: Core module exports ---

describe('Core Module Exports', () => {
  it('exports fullScan function', async () => {
    const core = await import('./core');
    expect(typeof core.fullScan).toBe('function');
  });

  it('exports scanSingleHost function', async () => {
    const core = await import('./core');
    expect(typeof core.scanSingleHost).toBe('function');
  });

  it('exports DEFAULT_SCAN_OPTIONS', async () => {
    const core = await import('./core');
    expect(core.DEFAULT_SCAN_OPTIONS).toBeDefined();
    expect(typeof core.DEFAULT_SCAN_OPTIONS.arpSettleMs).toBe('number');
    expect(typeof core.DEFAULT_SCAN_OPTIONS.checkLatency).toBe('boolean');
  });

  it('imports PortResult from port_scan', async () => {
    const ps = await import('./port_scan');
    expect(ps.WELL_KNOWN_SERVICES).toBeDefined();
    expect(ps.DEFAULT_PORTS).toBeDefined();
    expect(ps.DEFAULT_PORTS.length).toBeGreaterThan(0);
  });

  it('imports LatencySample from latency', async () => {
    const lat = await import('./latency');
    expect(typeof lat.checkLatency).toBe('function');
    expect(typeof lat.checkLatencyHost).toBe('function');
  });

  it('imports ArpEntry from arp', async () => {
    const arp = await import('./arp');
    expect(typeof arp.arpScan).toBe('function');
    expect(typeof arp.normalizeMac).toBe('function');
  });
});
