/**
 * SentryNet - REST API binding tests.
 * Covers the envelope unwrapping, the Tauri invoke wrappers and the HTTP client.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
import {
  ApiError,
  DEFAULT_REST_URL,
  RestClient,
  apiAcknowledgeAlert,
  apiGetAlerts,
  apiGetDevices,
  apiGetHistory,
  apiScan,
  apiScanHost,
  apiScanPorts,
  apiUpdateConfig,
  getServerInfo,
  unwrap,
  type AppConfig,
  type Device,
  type FetchLike,
} from './api';

const mockedInvoke = vi.mocked(invoke);

const DEVICE: Device = {
  ip: '192.168.1.10',
  mac: 'AA:BB:CC:DD:EE:10',
  name: null,
  vendor: 'Acme',
  last_seen: '2026-11-16T00:00:00Z',
  first_seen: '2026-11-16T00:00:00Z',
};

const CONFIG: AppConfig = {
  default_cidr: null,
  arp_settle_ms: 1500,
  port_scan_timeout_ms: 1000,
  port_scan_concurrency: 64,
  port_scan_ports: '',
  port_service_detection: true,
  ping_count: 4,
  ping_timeout_ms: 3000,
  http_port: 80,
  http_path: '/',
  http_timeout_ms: 3000,
  check_latency: true,
  history_retention_days: 90,
  enable_notifications: true,
  auto_scan_interval_seconds: 0,
  alert_rules_new_device: true,
  alert_rules_new_port: true,
  alert_rules_device_offline: true,
  alert_rules_port_closed: true,
};

function ok<T>(data: T) {
  return { success: true, data, error: null };
}

function fail(error: string) {
  return { success: false, data: null, error };
}

beforeEach(() => {
  mockedInvoke.mockReset();
});

describe('unwrap', () => {
  it('returns data on success', () => {
    expect(unwrap(ok([1, 2]))).toEqual([1, 2]);
  });

  it('throws ApiError with the server message on failure', () => {
    expect(() => unwrap(fail('device not found'), 404)).toThrow(ApiError);
    try {
      unwrap(fail('device not found'), 404);
    } catch (err) {
      expect((err as ApiError).message).toBe('device not found');
      expect((err as ApiError).status).toBe(404);
    }
  });

  it('rejects malformed envelopes', () => {
    expect(() => unwrap({} as never)).toThrow('malformed API response');
  });
});

describe('invoke bindings', () => {
  it('getServerInfo calls api_server_info', async () => {
    mockedInvoke.mockResolvedValueOnce({ db_path: '/tmp/x.sqlite', rest_url: DEFAULT_REST_URL, rest_error: null });
    const info = await getServerInfo();
    expect(mockedInvoke).toHaveBeenCalledWith('api_server_info');
    expect(info.rest_url).toBe(DEFAULT_REST_URL);
  });

  it('apiGetDevices passes dbPath and unwraps data', async () => {
    mockedInvoke.mockResolvedValueOnce(ok([DEVICE]));
    const devices = await apiGetDevices('/tmp/db.sqlite');
    expect(mockedInvoke).toHaveBeenCalledWith('api_get_devices', { dbPath: '/tmp/db.sqlite' });
    expect(devices).toEqual([DEVICE]);
  });

  it('throws ApiError when the command reports failure', async () => {
    mockedInvoke.mockResolvedValueOnce(fail('cannot open database'));
    await expect(apiGetDevices('/bad')).rejects.toThrow('cannot open database');
  });

  it('apiScan maps snake_case options to camelCase args with nulls for unset', async () => {
    mockedInvoke.mockResolvedValueOnce(ok({ device_count: 0 }));
    await apiScan('/db', { cidr: '192.168.1.0/24', ping_count: 2, check_latency: false });
    expect(mockedInvoke).toHaveBeenCalledWith('api_scan', {
      dbPath: '/db',
      cidr: '192.168.1.0/24',
      arpSettleMs: null,
      portScanTimeoutMs: null,
      portScanConcurrency: null,
      portScanPorts: null,
      portServiceDetection: null,
      pingCount: 2,
      pingTimeoutMs: null,
      httpPort: null,
      httpPath: null,
      httpTimeoutMs: null,
      checkLatency: false,
    });
  });

  it('apiScanHost sends host and no cidr', async () => {
    mockedInvoke.mockResolvedValueOnce(ok({ ip: '10.0.0.2' }));
    await apiScanHost('/db', '10.0.0.2', { http_port: 8080 });
    const [command, args] = mockedInvoke.mock.calls[0];
    expect(command).toBe('api_scan_host');
    expect(args).toMatchObject({ dbPath: '/db', host: '10.0.0.2', httpPort: 8080 });
    expect(args).not.toHaveProperty('cidr');
  });

  it('apiScanPorts forwards ports and timeouts', async () => {
    mockedInvoke.mockResolvedValueOnce(ok([]));
    await apiScanPorts({ hosts: ['10.0.0.1'], ports: [22, 80], timeout_ms: 500 });
    expect(mockedInvoke).toHaveBeenCalledWith('api_scan_ports', {
      hosts: ['10.0.0.1'],
      ports: [22, 80],
      timeoutMs: 500,
      concurrency: null,
      serviceDetection: null,
    });
  });

  it('apiGetHistory and apiGetAlerts pass filters', async () => {
    mockedInvoke.mockResolvedValue(ok([]));
    await apiGetHistory('/db', { limit: 10, eventType: 'discovered' });
    expect(mockedInvoke).toHaveBeenCalledWith('api_get_history', {
      dbPath: '/db',
      limit: 10,
      eventType: 'discovered',
    });
    await apiGetAlerts('/db', { acknowledged: false });
    expect(mockedInvoke).toHaveBeenCalledWith('api_get_alerts', {
      dbPath: '/db',
      acknowledged: false,
      limit: null,
    });
  });

  it('apiAcknowledgeAlert and apiUpdateConfig use the right commands', async () => {
    mockedInvoke.mockResolvedValueOnce(ok(null));
    await expect(apiAcknowledgeAlert('/db', 7)).resolves.toBeUndefined();
    expect(mockedInvoke).toHaveBeenCalledWith('api_acknowledge_alert', { dbPath: '/db', id: 7 });

    mockedInvoke.mockResolvedValueOnce(ok(CONFIG));
    const saved = await apiUpdateConfig('/db', CONFIG);
    expect(mockedInvoke).toHaveBeenLastCalledWith('api_update_config', { dbPath: '/db', config: CONFIG });
    expect(saved).toEqual(CONFIG);
  });
});

describe('RestClient', () => {
  function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  function client(responder: (url: string, init?: RequestInit) => Response) {
    const fetchMock = vi.fn<FetchLike>(async (url, init) => responder(url, init));
    return { rest: new RestClient('http://127.0.0.1:7357/', fetchMock), fetchMock };
  }

  it('strips trailing slashes from the base URL', () => {
    expect(new RestClient('http://localhost:7357///').baseUrl).toBe('http://localhost:7357');
    expect(new RestClient().baseUrl).toBe(DEFAULT_REST_URL);
  });

  it('GETs devices and unwraps the envelope', async () => {
    const { rest, fetchMock } = client(() => jsonResponse(ok([DEVICE])));
    await expect(rest.devices()).resolves.toEqual([DEVICE]);
    expect(fetchMock).toHaveBeenCalledWith('http://127.0.0.1:7357/api/devices', { method: 'GET' });
  });

  it('encodes path parameters', async () => {
    const { rest, fetchMock } = client(() => jsonResponse(ok([])));
    await rest.deviceHistory('fe80::1', 5);
    expect(fetchMock.mock.calls[0][0]).toBe('http://127.0.0.1:7357/api/devices/fe80%3A%3A1/history?limit=5');
  });

  it('builds history and alert query strings, skipping undefined values', async () => {
    const { rest, fetchMock } = client(() => jsonResponse(ok([])));
    await rest.history({ eventType: 'port_added' });
    await rest.alerts({ acknowledged: false, limit: 20 });
    await rest.alerts();
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual([
      'http://127.0.0.1:7357/api/history?event_type=port_added',
      'http://127.0.0.1:7357/api/alerts?acknowledged=false&limit=20',
      'http://127.0.0.1:7357/api/alerts',
    ]);
  });

  it('POSTs scan requests as JSON', async () => {
    const { rest, fetchMock } = client(() => jsonResponse(ok({ ip: '10.0.0.5' })));
    await rest.scanHost('10.0.0.5', { ping_count: 1 });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('http://127.0.0.1:7357/api/scan/host');
    expect(init?.method).toBe('POST');
    expect(init?.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(JSON.parse(String(init?.body))).toEqual({ ping_count: 1, host: '10.0.0.5' });
  });

  it('PUTs partial config updates', async () => {
    const { rest, fetchMock } = client(() => jsonResponse(ok({ ...CONFIG, ping_count: 2 })));
    const saved = await rest.updateConfig({ ping_count: 2 });
    expect(saved.ping_count).toBe(2);
    const [, init] = fetchMock.mock.calls[0];
    expect(init?.method).toBe('PUT');
    expect(JSON.parse(String(init?.body))).toEqual({ ping_count: 2 });
  });

  it('acknowledgeAlert POSTs to the ack route', async () => {
    const { rest, fetchMock } = client(() => jsonResponse(ok(null)));
    await expect(rest.acknowledgeAlert(42)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith('http://127.0.0.1:7357/api/alerts/42/ack', { method: 'POST' });
  });

  it('throws ApiError carrying the HTTP status on error envelopes', async () => {
    const { rest } = client(() => jsonResponse(fail('device not found: 10.0.0.9'), 404));
    const err = await rest.device('10.0.0.9').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(404);
    expect((err as ApiError).message).toBe('device not found: 10.0.0.9');
  });

  it('throws ApiError for non-JSON responses', async () => {
    const { rest } = client(() => new Response('oops', { status: 502 }));
    await expect(rest.stats()).rejects.toThrow('HTTP 502');
  });

  it('wraps network failures in ApiError', async () => {
    const rest = new RestClient(DEFAULT_REST_URL, async () => {
      throw new Error('ECONNREFUSED');
    });
    await expect(rest.health()).rejects.toThrow(/cannot reach SentryNet API.*ECONNREFUSED/);
  });

  it('export endpoints return the raw document', async () => {
    const { rest } = client(() => jsonResponse([DEVICE]));
    await expect(rest.exportDevices()).resolves.toEqual([DEVICE]);
  });

  it('export endpoints still surface error envelopes', async () => {
    const { rest } = client(() => jsonResponse(fail('database error'), 500));
    await expect(rest.exportPorts()).rejects.toThrow('database error');
  });
});
