import { EventBus } from './engine/event-bus';
import { runRefreshRace } from './scenarios/refresh-race';
import { runTokenReuse } from './scenarios/token-reuse';
import { runSessionHijack } from './scenarios/session-hijack';
import { runFingerprintSpoof } from './scenarios/fingerprint-spoof';
import { runBruteForce } from './scenarios/brute-force';
import { runJwtTamper } from './scenarios/jwt-tamper';
import { type ScenarioExpectation } from './expectations';

export type ScenarioContext = {
  bus: EventBus;
  /** Access token (for endpoints behind JwtAuthGuard). */
  accessToken: string;
  /** Refresh token (for /auth/refresh). */
  refreshToken: string;
  /** Account used for isolated simulator logins. */
  email: string;
  password: string;
  /** Decoy account used for brute-force attempts so the operator is not locked out. */
  bruteForceEmail: string;
};

export type Scenario = {
  key: string;
  label: string;
  description: string;
  /** Defensive behaviour this scenario is meant to provoke. */
  expectation: ScenarioExpectation;
  run: (ctx: ScenarioContext) => Promise<unknown>;
};

/**
 * Single source of truth for what the runner and the console can execute.
 * Each scenario is wrapped to share one calling convention.
 */
export const SCENARIOS: Scenario[] = [
  {
    key: 'refresh-race',
    label: 'Refresh race',
    description: 'Fire many concurrent refreshes to test atomic rotation.',
    expectation: {
      scenario: 'REFRESH_RACE',
      description:
        'Only one concurrent refresh may succeed; the rest must be rejected.',
      minBlocked: 1,
    },
    run: ({ bus, email, password }) => runRefreshRace(bus, { email, password }),
  },
  {
    key: 'token-reuse',
    label: 'Token reuse',
    description: 'Replay a refresh token to test anti-replay revocation.',
    expectation: {
      scenario: 'TOKEN_REUSE',
      description: 'A replayed refresh token must be rejected.',
      minBlocked: 1,
    },
    run: ({ bus, refreshToken }) => runTokenReuse(refreshToken, bus),
  },
  {
    key: 'session-hijack',
    label: 'Session hijack',
    description: 'Hit /sessions from spoofed IP/UA to test session binding.',
    expectation: {
      scenario: 'SESSION_HIJACK',
      description:
        'Requests from a fingerprint that does not match the session must be blocked.',
      minBlocked: 1,
    },
    run: ({ bus, accessToken }) => runSessionHijack(accessToken, bus),
  },
  {
    key: 'fingerprint-spoof',
    label: 'Fingerprint spoof',
    description: 'Vary device fingerprint to test the zero-trust engine.',
    expectation: {
      scenario: 'FINGERPRINT_SPOOF',
      description: 'A spoofed device fingerprint must trip the zero-trust guard.',
      minBlocked: 1,
    },
    run: ({ bus, accessToken }) => runFingerprintSpoof(accessToken, bus),
  },
  {
    key: 'brute-force',
    label: 'Brute force',
    description: 'Repeatedly guess a password to test rate limiting + lockout.',
    expectation: {
      scenario: 'BRUTE_FORCE',
      description:
        'Repeated login guesses must be rate-limited (or the account locked), not answered indefinitely.',
      // The wrong-password 401s also count as rejections, but we specifically
      // want to see the throttler/lockout engage.
      blocking: ['RATE_LIMITED', 'BLOCKED'],
      minBlocked: 1,
    },
    run: ({ bus, bruteForceEmail }) => runBruteForce(bus, { email: bruteForceEmail }),
  },
  {
    key: 'jwt-tamper',
    label: 'JWT tampering',
    description: 'Present forged/altered tokens to test signature validation.',
    expectation: {
      scenario: 'JWT_TAMPER',
      description:
        'Tampered tokens (bad signature, escalated role, alg:none) must all be rejected.',
      minBlocked: 1,
    },
    run: ({ bus, accessToken }) => runJwtTamper(accessToken, bus),
  },
];

export function findScenario(key: string): Scenario | undefined {
  return SCENARIOS.find((s) => s.key === key);
}
