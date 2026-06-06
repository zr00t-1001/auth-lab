import { Injectable } from '@nestjs/common';
import { SecurityContext } from './session-security.context';
import { RiskLevel } from './risk-level.types';

/**
 * True when a value is actually present (not null/undefined and, for strings,
 * not empty). Used so a missing field never auto-scores risk: we only compare
 * two values when both sides actually have one.
 */
function defined(v: unknown): boolean {
  return v !== undefined && v !== null && v !== '';
}

@Injectable()
export class SessionSecurityEngine {

  evaluate(current: any, target: any): SecurityContext {

    // -----------------------------
    // IDENTITY RISK (HIGHEST PRIORITY)
    // -----------------------------
    const identity = this.identityRisk(current, target);

    // -----------------------------
    // BEHAVIORAL RISK
    // -----------------------------
    const behavior = this.behaviorRisk(current, target);

    // -----------------------------
    // ENV / DRIFT RISK
    // -----------------------------
    const drift = this.driftRisk(current, target);

    const score = this.weighted(identity, behavior, drift);

    const level = this.toLevel(score);

    const action =
      identity > 80 ? 'REVOKE' :
      score > 80 ? 'REVOKE' :
      score > 55 ? 'STEP_UP' :
      'ALLOW';

    return {
      score,
      level,
      reasons: this.reasons(identity, behavior, drift),

      driftScore: drift,
      driftLevel: this.toLevel(drift),
      driftReasons: this.driftReasons(drift),

      isSuspicious: score > 50,
      requireReauth: score > 60,
      action,
    };
  }

  emptyContext(): SecurityContext {
    return {
      score: 0,
      level: 'TRUSTED',
      reasons: [],

      driftScore: 0,
      driftLevel: 'TRUSTED',
      driftReasons: [],

      isSuspicious: false,
      requireReauth: false,
      action: 'ALLOW',
    };
  }

  // -----------------------------
  // CORE SCORING
  // -----------------------------

  private identityRisk(a: any, b: any): number {
    let s = 0;

    // Identity is the USER, not the session row id. Only score a field when
    // both sides actually have a value, so a missing field never auto-scores.
    if (defined(a.userId) && defined(b.userId) && a.userId !== b.userId) s += 30;
    if (defined(a.ipAddress) && defined(b.ipAddress) && a.ipAddress !== b.ipAddress) s += 25;
    if (defined(a.userAgent) && defined(b.userAgent) && a.userAgent !== b.userAgent) s += 20;
    if (a.fingerprint && b.fingerprint && a.fingerprint !== b.fingerprint) s += 60;
    if (a.currentRefreshJti && b.currentRefreshJti && a.currentRefreshJti !== b.currentRefreshJti) s += 70;

    return Math.min(s, 100);
  }

  private behaviorRisk(a: any, b: any): number {
    let s = 0;

    if (defined(a.ipAddress) && defined(b.ipAddress) && a.ipAddress !== b.ipAddress) s += 40;
    if (defined(a.userAgent) && defined(b.userAgent) && a.userAgent !== b.userAgent) s += 30;

    return Math.min(s, 100);
  }

  private driftRisk(a: any, b: any): number {
    let s = 0;

    if (a.country && b.country && a.country !== b.country) s += 50;
    if (a.asn && b.asn && a.asn !== b.asn) s += 30;

    return Math.min(s, 100);
  }

  private weighted(i: number, b: number, d: number): number {
    return i * 0.5 + b * 0.3 + d * 0.2;
  }

  private toLevel(score: number): RiskLevel {
    if (score > 80) return 'HIGH_RISK';
    if (score > 50) return 'SUSPICIOUS';
    if (score > 20) return 'LOW_RISK';
    return 'TRUSTED';
  }

  private reasons(i: number, b: number, d: number): string[] {
    const r: string[] = [];

    if (i > 80) r.push('Identity compromise suspected');
    if (b > 50) r.push('Behavior anomaly');
    if (d > 50) r.push('Environment drift detected');

    return r;
  }

  private driftReasons(score: number): string[] {
    if (score > 80) return ['Severe network drift'];
    if (score > 50) return ['Network inconsistency'];
    return [];
  }
}