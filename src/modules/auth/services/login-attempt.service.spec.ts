import { HttpException } from '@nestjs/common';
import { LoginAttemptService } from './login-attempt.service';

// Minimal fake so we don't touch the DB.
function makeService() {
  const recorded: any[] = [];
  const events = { record: async (e: any) => void recorded.push(e) } as any;
  return { svc: new LoginAttemptService(events), recorded };
}

describe('LoginAttemptService', () => {
  const EMAIL = 'victim@test.com';

  it('does not lock before the threshold', async () => {
    const { svc } = makeService();
    for (let i = 0; i < LoginAttemptService.MAX_FAILURES - 1; i++) {
      await svc.recordFailure(EMAIL);
    }
    expect(svc.isLocked(EMAIL)).toBe(false);
    expect(() => svc.assertNotLocked(EMAIL)).not.toThrow();
  });

  it('locks the account once MAX_FAILURES is reached', async () => {
    const { svc, recorded } = makeService();
    for (let i = 0; i < LoginAttemptService.MAX_FAILURES; i++) {
      await svc.recordFailure(EMAIL);
    }
    expect(svc.isLocked(EMAIL)).toBe(true);
    expect(() => svc.assertNotLocked(EMAIL)).toThrow(HttpException);
    // A lock emits exactly one ACCOUNT_LOCKED audit event.
    expect(recorded).toHaveLength(1);
    expect(recorded[0].type).toBe('ACCOUNT_LOCKED');
    expect(recorded[0].severity).toBe('HIGH');
  });

  it('throws a 429 when locked', async () => {
    const { svc } = makeService();
    for (let i = 0; i < LoginAttemptService.MAX_FAILURES; i++) {
      await svc.recordFailure(EMAIL);
    }
    try {
      svc.assertNotLocked(EMAIL);
      fail('expected lockout to throw');
    } catch (e) {
      expect((e as HttpException).getStatus()).toBe(429);
    }
  });

  it('reset() clears failures and the lock', async () => {
    const { svc } = makeService();
    for (let i = 0; i < LoginAttemptService.MAX_FAILURES; i++) {
      await svc.recordFailure(EMAIL);
    }
    expect(svc.isLocked(EMAIL)).toBe(true);
    svc.reset(EMAIL);
    expect(svc.isLocked(EMAIL)).toBe(false);
    expect(() => svc.assertNotLocked(EMAIL)).not.toThrow();
  });

  it('is case/space-insensitive on the email key', async () => {
    const { svc } = makeService();
    for (let i = 0; i < LoginAttemptService.MAX_FAILURES; i++) {
      await svc.recordFailure('  VICTIM@TEST.com ');
    }
    expect(svc.isLocked('victim@test.com')).toBe(true);
  });
});
