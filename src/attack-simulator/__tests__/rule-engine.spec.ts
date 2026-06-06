import { RuleEngine } from '../engine/rule-engine';
import { networkEvent, systemEvent } from './test-helpers';

describe('RuleEngine', () => {
  it('raises no alerts for benign traffic', () => {
    const alerts = new RuleEngine([
      networkEvent({ scenario: 'X', classification: 'ALLOW', ip: '1.1.1.1' }),
    ]).run();
    expect(alerts).toHaveLength(0);
  });

  it('fires RATE_LIMIT_BURST once 5+ rate-limited events occur', () => {
    const evs = Array.from({ length: 6 }, () =>
      systemEvent({ scenario: 'X', classification: 'RATE_LIMITED' }),
    );
    const alerts = new RuleEngine(evs).run();
    const burst = alerts.find((a) => a.rule === 'RATE_LIMIT_BURST');
    expect(burst).toBeDefined();
    expect(burst?.severity).toBe('MEDIUM');
    expect(burst?.confidence).toBeLessThanOrEqual(0.9);
  });

  it('does not fire RATE_LIMIT_BURST below the threshold', () => {
    const evs = Array.from({ length: 4 }, () =>
      systemEvent({ scenario: 'X', classification: 'RATE_LIMITED' }),
    );
    const alerts = new RuleEngine(evs).run();
    expect(alerts.find((a) => a.rule === 'RATE_LIMIT_BURST')).toBeUndefined();
  });

  it('fires MULTI_IP_CAMPAIGN with enough IP diversity and pressure', () => {
    const ips = ['1.1.1.1', '2.2.2.2', '3.3.3.3'];
    const evs = ips.flatMap((ip) =>
      Array.from({ length: 2 }, () =>
        networkEvent({ scenario: 'X', classification: 'AUTH_REJECT', ip }),
      ),
    );
    const alerts = new RuleEngine(evs).run();
    const campaign = alerts.find((a) => a.rule === 'MULTI_IP_CAMPAIGN');
    expect(campaign).toBeDefined();
    expect(campaign?.severity).toBe('HIGH');
  });

  it('does not fire MULTI_IP_CAMPAIGN from a single IP', () => {
    const evs = Array.from({ length: 6 }, () =>
      networkEvent({ scenario: 'X', classification: 'AUTH_REJECT', ip: '1.1.1.1' }),
    );
    const alerts = new RuleEngine(evs).run();
    expect(alerts.find((a) => a.rule === 'MULTI_IP_CAMPAIGN')).toBeUndefined();
  });
});
