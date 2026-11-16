import { describe, it, expect } from 'vitest';
import {
  alertTitle,
  isTauriRuntime,
  maxAlertId,
  newAlertsSince,
  planNotifications,
  type AlertLike,
} from './alerts';

function alert(id: number | null, ip: string, type: string, acknowledged = false): AlertLike {
  return { id, device_ip: ip, alert_type: type, message: `${type} on ${ip}`, acknowledged };
}

describe('alertTitle', () => {
  it('maps known alert types', () => {
    expect(alertTitle('new_device')).toBe('New device discovered');
    expect(alertTitle('new_port')).toBe('New port opened');
    expect(alertTitle('device_offline')).toBe('Device offline');
    expect(alertTitle('port_closed')).toBe('Port closed');
    expect(alertTitle('whatever')).toBe('SentryNet alert');
  });
});

describe('isTauriRuntime', () => {
  it('detects the Tauri globals', () => {
    expect(isTauriRuntime({})).toBe(false);
    expect(isTauriRuntime({ __TAURI_INTERNALS__: {} })).toBe(true);
    expect(isTauriRuntime({ __TAURI__: {} })).toBe(true);
  });
});

describe('maxAlertId / newAlertsSince', () => {
  const alerts = [
    alert(5, '192.168.1.5', 'new_device'),
    alert(3, '192.168.1.3', 'new_device'),
    alert(7, '192.168.1.7', 'new_port', true),
    alert(null, '192.168.1.9', 'new_device'),
  ];

  it('finds the highest id', () => {
    expect(maxAlertId(alerts)).toBe(7);
    expect(maxAlertId([])).toBe(0);
  });

  it('returns only unseen, unacknowledged alerts, oldest first', () => {
    expect(newAlertsSince(alerts, 0).map(a => a.id)).toEqual([3, 5]);
    expect(newAlertsSince(alerts, 3).map(a => a.id)).toEqual([5]);
    expect(newAlertsSince(alerts, 7)).toEqual([]);
  });
});

describe('planNotifications', () => {
  it('returns nothing for no alerts', () => {
    expect(planNotifications([])).toEqual([]);
  });

  it('skips acknowledged alerts', () => {
    expect(planNotifications([alert(1, '10.0.0.1', 'new_device', true)])).toEqual([]);
  });

  it('notifies each alert in small groups, new devices first', () => {
    const planned = planNotifications([
      alert(1, '10.0.0.1', 'new_port'),
      alert(2, '10.0.0.2', 'new_device'),
    ]);
    expect(planned).toEqual([
      { title: 'New device discovered', body: 'new_device on 10.0.0.2' },
      { title: 'New port opened', body: 'new_port on 10.0.0.1' },
    ]);
  });

  it('collapses large groups into one summary', () => {
    const alerts = Array.from({ length: 10 }, (_, i) => alert(i + 1, `10.0.0.${i + 1}`, 'new_device'));
    const planned = planNotifications(alerts);
    expect(planned).toHaveLength(1);
    expect(planned[0].title).toBe('10 new devices discovered');
    expect(planned[0].body).toBe('10.0.0.1, 10.0.0.2, 10.0.0.3 and 7 more. Open SentryNet to review.');
  });

  it('keeps unknown alert types', () => {
    const planned = planNotifications([alert(1, '10.0.0.1', 'custom')]);
    expect(planned).toEqual([{ title: 'SentryNet alert', body: 'custom on 10.0.0.1' }]);
  });
});
