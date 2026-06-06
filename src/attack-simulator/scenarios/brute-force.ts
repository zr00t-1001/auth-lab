import { request } from '../core/http';
import { EventBus } from '../engine/event-bus';
import { classify } from '../core/classify';

/**
 * Hammer /auth/login with wrong passwords for a known account and confirm the
 * backend pushes back — the per-route throttler should start returning 429
 * (RATE_LIMITED) well before the password could ever be guessed.
 */
export async function runBruteForce(
  bus: EventBus,
  opts: { email?: string; attempts?: number } = {},
) {
  const email = opts.email ?? 'test@test.com';
  const attempts = opts.attempts ?? 8;
  // Attack from a dedicated attacker IP so the brute-force throttle bucket is
  // separate from the victim/operator logins (otherwise it would starve the
  // shared rate limit and the legit victim login would 429).
  const ATTACKER_IP = '45.155.205.99';
  console.log('\n🔨 BRUTE-FORCE ATTACK START');

  for (let i = 1; i <= attempts; i++) {
    try {
      const res = await request({
        method: 'POST',
        url: '/auth/login',
        data: { email, password: `wrong-password-${i}` },
        headers: { 'X-Forwarded-For': ATTACKER_IP },
      });
      const { layer, classification } = classify(res.status);
      bus.emit({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'BRUTE_FORCE',
        type: 'LOGIN_ATTEMPT',
        status: res.status,
        layer,
        classification,
        message: res.data?.message,
      });
      console.log(`  attempt ${i}:`, res.status, classification);
    } catch (err: any) {
      const status = err?.response?.status ?? 0;
      const { layer, classification } = classify(status);
      bus.emit({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'BRUTE_FORCE',
        type: 'LOGIN_ATTEMPT',
        status,
        layer,
        classification,
        message: err?.response?.data?.message ?? err?.message,
      });
      console.log(`  attempt ${i}:`, status, classification);
    }
  }
}
