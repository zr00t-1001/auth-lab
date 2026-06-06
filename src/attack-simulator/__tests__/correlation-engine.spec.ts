import { CorrelationEngine } from '../engine/correlation-engine';
import { networkEvent } from './test-helpers';

describe('CorrelationEngine', () => {
  it('produces one alert per distinct IP', () => {
    const alerts = new CorrelationEngine([
      networkEvent({ scenario: 'X', classification: 'ALLOW', ip: '1.1.1.1' }),
      networkEvent({ scenario: 'X', classification: 'ALLOW', ip: '2.2.2.2' }),
    ]).build();
    expect(alerts.map((a) => a.ip).sort()).toEqual(['1.1.1.1', '2.2.2.2']);
  });

  it('escalates severity as an IP accumulates rejections', () => {
    // 5 AUTH_REJECT = score 10 -> MEDIUM; add RATE_LIMITED to push past HIGH.
    const ip = '9.9.9.9';
    const evs = [
      ...Array.from({ length: 5 }, () =>
        networkEvent({ scenario: 'X', classification: 'AUTH_REJECT', ip }),
      ),
      networkEvent({ scenario: 'X', classification: 'RATE_LIMITED', ip }),
    ];
    const [alert] = new CorrelationEngine(evs).build();
    expect(alert.severity).toBe('HIGH');
    expect(alert.confidence).toBeGreaterThan(0);
    expect(alert.confidence).toBeLessThanOrEqual(1);
    expect(alert.sequence).toHaveLength(6);
  });

  it('keeps a benign single-event IP at LOW severity', () => {
    const [alert] = new CorrelationEngine([
      networkEvent({ scenario: 'X', classification: 'ALLOW', ip: '8.8.8.8' }),
    ]).build();
    expect(alert.severity).toBe('LOW');
  });
});
