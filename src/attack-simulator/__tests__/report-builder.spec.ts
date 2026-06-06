import { buildReport } from '../engine/report-builder';
import { ScenarioReportSchema } from '../schemas';
import { type ScenarioExpectation } from '../expectations';
import { networkEvent } from './test-helpers';

const target = 'http://localhost:3000';

describe('buildReport', () => {
  it('emits a schema-valid report even with no events', () => {
    const report = buildReport([], { target, scenarios: [] });
    expect(() => ScenarioReportSchema.parse(report)).not.toThrow();
    expect(report.summary.status).toBe('CLEAN');
    expect(report.verdict.passed).toBe(true);
  });

  it('marks an ACTIVE_THREAT when a HIGH-severity rule fires', () => {
    const ips = ['1.1.1.1', '2.2.2.2', '3.3.3.3'];
    const evs = ips.flatMap((ip) =>
      Array.from({ length: 2 }, () =>
        networkEvent({ scenario: 'SESSION_HIJACK', classification: 'AUTH_REJECT', ip }),
      ),
    );
    const report = buildReport(evs, { target, scenarios: ['session-hijack'] });
    expect(report.summary.high).toBeGreaterThan(0);
    expect(report.summary.status).toBe('ACTIVE_THREAT');
  });

  it('folds the scenario verdict into the report', () => {
    const expectation: ScenarioExpectation = {
      scenario: 'SESSION_HIJACK',
      description: 'must block spoofed requests',
      minBlocked: 1,
    };
    const passing = buildReport(
      [networkEvent({ scenario: 'SESSION_HIJACK', classification: 'BLOCKED', ip: '1.1.1.1' })],
      { target, scenarios: ['session-hijack'], expectations: [expectation] },
    );
    expect(passing.verdict.passed).toBe(true);

    const failing = buildReport(
      [networkEvent({ scenario: 'SESSION_HIJACK', classification: 'ALLOW', ip: '1.1.1.1' })],
      { target, scenarios: ['session-hijack'], expectations: [expectation] },
    );
    expect(failing.verdict.passed).toBe(false);
  });
});
