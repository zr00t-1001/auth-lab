import { client } from '../core/client';
import { EventBus } from '../engine/event-bus';
import { classify } from '../core/classify';

type Env = {
  ip: string;
  ua: string;
};

export async function runFingerprintSpoof(token: string, bus: EventBus) {
  console.log('💣 FINGERPRINT SPOOF START');

  const envs: Env[] = [
    { ip: '185.12.44.10', ua: 'Chrome Win' },
    { ip: '91.200.33.21', ua: 'iPhone Safari' },
    { ip: '77.88.11.55', ua: 'Android Chrome' },
  ];

  for (const env of envs) {
    try {
      const res = await client.get('/sessions', {
        headers: {
          Authorization: `Bearer ${token}`,
          'User-Agent': env.ua,
          'x-forwarded-for': env.ip,
        },
      });

      const { layer, classification } = classify(res.status);

      bus.emit({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'FINGERPRINT_SPOOF',
        type: 'SESSION_GET',

        ip: env.ip,
        userAgent: env.ua,

        status: res.status,
        layer,
        classification,

        message: res.data?.message,
      });

      console.log('🟢 OK:', env.ip, res.status, classification);
    } catch (e: any) {
      const status = e.response?.status ?? 0;

      const { layer, classification } = classify(status);

      bus.emit({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'FINGERPRINT_SPOOF',
        type: 'SESSION_GET',

        ip: env.ip,
        userAgent: env.ua,

        status,
        layer,
        classification,

        message: e.response?.data?.message,
      });

      console.log('🔴 BLOCKED:', env.ip, status, classification);
    }
  }
}