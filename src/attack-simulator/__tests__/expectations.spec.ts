import {
  evaluateExpectations,
  DEFAULT_BLOCKING,
  type ScenarioExpectation,
} from '../expectations';
import { networkEvent } from './test-helpers';

const hijackExpectation: ScenarioExpectation = {
  scenario: 'SESSION_HIJACK',
  description: 'spoofed requests must be blocked',
  minBlocked: 1,
};

describe('evaluateExpectations', () => {
  it('passes when the defense blocked at least the required number', () => {
    const verdict = evaluateExpectations(
      [
        networkEvent({ scenario: 'SESSION_HIJACK', classification: 'BLOCKED', ip: '1.1.1.1' }),
        networkEvent({ scenario: 'SESSION_HIJACK', classification: 'ALLOW', ip: '1.1.1.1' }),
      ],
      [hijackExpectation],
    );
    expect(verdict.passed).toBe(true);
    expect(verdict.scenarios[0]).toMatchObject({
      total: 2,
      blocked: 1,
      required: 1,
      passed: true,
    });
  });

  it('fails when nothing was blocked', () => {
    const verdict = evaluateExpectations(
      [networkEvent({ scenario: 'SESSION_HIJACK', classification: 'ALLOW', ip: '1.1.1.1' })],
      [hijackExpectation],
    );
    expect(verdict.passed).toBe(false);
    expect(verdict.scenarios[0].blocked).toBe(0);
  });

  it('fails a scenario that produced no events at all (target unreachable)', () => {
    const verdict = evaluateExpectations([], [hijackExpectation]);
    expect(verdict.passed).toBe(false);
    expect(verdict.scenarios[0]).toMatchObject({ total: 0, blocked: 0, passed: false });
  });

  it('only counts events belonging to the scenario under test', () => {
    const verdict = evaluateExpectations(
      [
        networkEvent({ scenario: 'TOKEN_REUSE', classification: 'BLOCKED', ip: '1.1.1.1' }),
        networkEvent({ scenario: 'SESSION_HIJACK', classification: 'BLOCKED', ip: '1.1.1.1' }),
      ],
      [hijackExpectation],
    );
    expect(verdict.scenarios[0].total).toBe(1);
    expect(verdict.scenarios[0].passed).toBe(true);
  });

  it('respects a custom blocking set', () => {
    const expectation: ScenarioExpectation = {
      scenario: 'SESSION_HIJACK',
      description: 'only a hard 403 block counts',
      blocking: ['BLOCKED'],
      minBlocked: 1,
    };
    const verdict = evaluateExpectations(
      [networkEvent({ scenario: 'SESSION_HIJACK', classification: 'AUTH_REJECT', ip: '1.1.1.1' })],
      [expectation],
    );
    // AUTH_REJECT is in DEFAULT_BLOCKING but not in the custom set.
    expect(DEFAULT_BLOCKING).toContain('AUTH_REJECT');
    expect(verdict.passed).toBe(false);
  });

  it('passes vacuously when there are no expectations', () => {
    expect(evaluateExpectations([], []).passed).toBe(true);
  });
});
