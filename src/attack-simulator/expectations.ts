import {
  type SocEvent,
  type Classification,
  type ScenarioVerdict,
  type Verdict,
} from './schemas';

/**
 * A defensive expectation for a single scenario.
 *
 * The lab exists to prove the backend's defenses fire. An expectation states,
 * for one scenario, how many of its events the backend was supposed to reject.
 * `evaluateExpectations` checks the observed events against this and produces a
 * pass/fail verdict — so a regression that silently weakens a guard shows up as
 * a failing run (and a non-zero CLI exit code) instead of going unnoticed.
 */
export type ScenarioExpectation = {
  /** Matches SocEvent.scenario, e.g. 'SESSION_HIJACK'. */
  scenario: string;
  /** Human-readable statement of what the defense must do. */
  description: string;
  /** Classifications that count as "the defense fired". */
  blocking?: Classification[];
  /** Minimum number of blocked events required for the scenario to pass. */
  minBlocked: number;
};

/** Default set of classifications that count as a defensive rejection. */
export const DEFAULT_BLOCKING: Classification[] = [
  'BLOCKED',
  'AUTH_REJECT',
  'RATE_LIMITED',
];

/**
 * Evaluate observed events against a set of scenario expectations.
 *
 * Pure and deterministic: no clock, no network, no I/O. Scenarios that produced
 * no events (e.g. the target was unreachable) are reported with total 0 and
 * fail when they required at least one block, which is the safe default — a
 * lab that could not reach the target should not report "defenses held".
 */
export function evaluateExpectations(
  events: SocEvent[],
  expectations: ScenarioExpectation[],
): Verdict {
  const scenarios: ScenarioVerdict[] = expectations.map((exp) => {
    const blocking = exp.blocking ?? DEFAULT_BLOCKING;
    const scoped = events.filter((e) => e.scenario === exp.scenario);
    const blocked = scoped.filter((e) =>
      blocking.includes(e.classification),
    ).length;

    return {
      scenario: exp.scenario,
      description: exp.description,
      total: scoped.length,
      blocked,
      required: exp.minBlocked,
      passed: blocked >= exp.minBlocked,
    };
  });

  return {
    passed: scenarios.every((s) => s.passed),
    scenarios,
  };
}
