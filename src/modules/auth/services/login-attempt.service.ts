import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { SecurityEventService } from '../../security/events/security-event.service';
import { SecurityEventType } from '../../security/events/security-event.entity';

/**
 * Account lockout. After MAX_FAILURES failed logins for the same email within
 * WINDOW_MS, the account is locked for LOCK_MS. This is defense-in-depth on top
 * of the per-route rate limiter: the throttler slows a burst, the lockout stops
 * a slow, sustained credential-guessing campaign and leaves an audit trail.
 *
 * State is in-memory, which is fine for a single-instance lab. A multi-instance
 * deployment would back this with Redis or a DB column.
 */
@Injectable()
export class LoginAttemptService {
  static readonly MAX_FAILURES = 5;
  static readonly WINDOW_MS = 15 * 60_000; // 15 min
  static readonly LOCK_MS = 15 * 60_000; // 15 min

  private readonly failures = new Map<string, number[]>();
  private readonly lockedUntil = new Map<string, number>();

  constructor(private readonly events: SecurityEventService) {}

  private key(email: string): string {
    return email.toLowerCase().trim();
  }

  /** Throws 429 if the account is currently locked. Call before checking creds. */
  assertNotLocked(email: string, ip?: string): void {
    const k = this.key(email);
    const until = this.lockedUntil.get(k);
    if (until && until > Date.now()) {
      const retryAfter = Math.ceil((until - Date.now()) / 1000);
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: 'Account temporarily locked due to repeated failed logins',
          retryAfter,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    if (until) this.lockedUntil.delete(k); // lock expired
  }

  /** Record a failed attempt; locks the account once the threshold is hit. */
  async recordFailure(email: string, ip?: string): Promise<void> {
    const k = this.key(email);
    const now = Date.now();
    const recent = (this.failures.get(k) ?? []).filter(
      (t) => now - t < LoginAttemptService.WINDOW_MS,
    );
    recent.push(now);
    this.failures.set(k, recent);

    if (recent.length >= LoginAttemptService.MAX_FAILURES) {
      this.lockedUntil.set(k, now + LoginAttemptService.LOCK_MS);
      this.failures.delete(k);
      await this.events.record({
        type: SecurityEventType.ACCOUNT_LOCKED,
        severity: 'HIGH',
        ip,
        detail: {
          email: k,
          failures: LoginAttemptService.MAX_FAILURES,
          lockMs: LoginAttemptService.LOCK_MS,
        },
      });
    }
  }

  /** Clear all failure state for an account (call on successful login). */
  reset(email: string): void {
    const k = this.key(email);
    this.failures.delete(k);
    this.lockedUntil.delete(k);
  }

  /** Test/inspection helper. */
  isLocked(email: string): boolean {
    const until = this.lockedUntil.get(this.key(email));
    return Boolean(until && until > Date.now());
  }
}
