import { request } from '../core/http';
import { EventBus } from '../engine/event-bus';
import { classify } from '../core/classify';

const b64url = (s: string) => Buffer.from(s).toString('base64url');

/** Flip a character in the signature so it no longer verifies. */
function corruptSignature(token: string): string {
  const p = token.split('.');
  if (p.length !== 3 || !p[2]) return token + 'x';
  const sig = p[2];
  p[2] = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  return p.join('.');
}

/** Escalate to admin in the payload but keep the original (now-invalid) signature. */
function escalateRole(token: string): string {
  const p = token.split('.');
  if (p.length < 2) return token;
  try {
    const payload = JSON.parse(Buffer.from(p[1], 'base64url').toString('utf8'));
    payload.role = 'admin';
    p[1] = b64url(JSON.stringify(payload));
    return p.join('.');
  } catch {
    return token;
  }
}

/** Forge an unsigned (alg:none) token — a classic library-confusion attack. */
function algNone(token: string): string {
  const p = token.split('.');
  let payload: Record<string, unknown> = { sub: 'attacker', role: 'admin' };
  try {
    if (p[1]) payload = JSON.parse(Buffer.from(p[1], 'base64url').toString('utf8'));
  } catch {
    /* keep default */
  }
  payload.role = 'admin';
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(
    JSON.stringify(payload),
  )}.`;
}

/**
 * Present tampered access tokens to a protected route. Every variant must be
 * rejected (401) — signature verification should fail before any handler or
 * role check runs.
 */
export async function runJwtTamper(accessToken: string, bus: EventBus) {
  console.log('\n🪪 JWT TAMPERING ATTACK START');

  const variants: Array<[string, string]> = [
    ['corrupt-signature', corruptSignature(accessToken)],
    ['role-escalation', escalateRole(accessToken)],
    ['alg-none', algNone(accessToken)],
  ];

  for (const [label, token] of variants) {
    try {
      const res = await request({
        method: 'GET',
        url: '/sessions',
        headers: { Authorization: `Bearer ${token}` },
      });
      const { layer, classification } = classify(res.status);
      bus.emit({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'JWT_TAMPER',
        type: 'JWT_TAMPER',
        status: res.status,
        layer,
        classification,
        message: `${label}: ${res.data?.message ?? res.status}`,
      });
      console.log(`  ${label}:`, res.status, classification);
    } catch (err: any) {
      const status = err?.response?.status ?? 0;
      const { layer, classification } = classify(status);
      bus.emit({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'JWT_TAMPER',
        type: 'JWT_TAMPER',
        status,
        layer,
        classification,
        message: `${label}: ${err?.response?.data?.message ?? err?.message}`,
      });
      console.log(`  ${label}:`, status, classification);
    }
  }
}
