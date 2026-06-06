import { request } from '../core/http';
import { EventBus, type SocEventType } from '../engine/event-bus';
import { classify } from '../core/classify';

export async function runTokenReuse(token: string, bus: EventBus) {
  console.log('\n🧨 TOKEN REUSE ATTACK START');

  const call = async (label: SocEventType) => {
    try {
      const res = await request({
        method: 'POST',
        url: '/auth/refresh',
        data: { refreshToken: token },
      });

      const { layer, classification } = classify(res.status);

      bus.emit({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'TOKEN_REUSE',
        type: label,

        status: res.status,
        layer,
        classification,
        message: res.data?.message,
      });

      console.log(`✔ ${label}:`, res.status, classification);

      return { status: res.status, classification };
    } catch (err: any) {
      const status = err?.response?.status ?? 0;
      const { layer, classification } = classify(status);

      bus.emit({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'TOKEN_REUSE',
        type: label,

        status,
        layer,
        classification,
        message: err?.response?.data?.message ?? err?.message,
      });

      console.log(`❌ ${label}:`, status, classification);

      return { status, classification };
    }
  };

  const first = await call('REFRESH_FIRST');
  const reused = await call('REFRESH_REUSE');

  if (reused.classification === 'AUTH_REJECT') {
    console.log('🚨 Replay detected by backend');
  }

  if (reused.classification === 'RATE_LIMITED') {
    console.log('🛑 Attack throttled');
  }

  return { first, reused };
}