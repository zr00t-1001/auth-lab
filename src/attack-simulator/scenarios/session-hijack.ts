import { EventBus, type NetworkEvent } from '../engine/event-bus';
import { Timeline } from '../engine/timeline';
import { client } from '../core/client';
import { classify } from '../core/classify';

type Env = {
  ip: string;
  ua: string;
};

export async function runSessionHijack(token: string, bus: EventBus) {
  console.log('💣 SOC SESSION HIJACK START');

  const envs: Env[] = [
    { ip: '185.12.44.10', ua: 'Chrome Win' },
    { ip: '91.200.33.21', ua: 'iPhone Safari' },
    { ip: '77.88.11.55', ua: 'Android Chrome' },
    { ip: '103.44.22.99', ua: 'Mac Safari' },
  ];

  const results: NetworkEvent[] = [];

  for (let i = 0; i < envs.length; i++) {
    const env = envs[i];

    try {
      const res = await client.get('/sessions', {
        headers: {
          Authorization: `Bearer ${token}`,
          'x-forwarded-for': env.ip,
          'user-agent': env.ua,
        },
      });

      const { layer, classification } = classify(res.status);

      const event: NetworkEvent = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'SESSION_HIJACK',
        type: 'SESSION_GET',

        status: res.status,
        layer,
        classification,

        ip: env.ip,
        userAgent: env.ua,
        message: res.data?.message ?? 'OK',
      };

      bus.emit(event);
      results.push(event);

      console.log(`✔ [${i}] ${env.ip} → ${res.status}`);

    } catch (err: any) {
      const status = err?.response?.status ?? 0;
      const { layer, classification } = classify(status);

      const event: NetworkEvent = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        scenario: 'SESSION_HIJACK',
        type: 'SESSION_GET',

        status,
        layer,
        classification,

        ip: env.ip,
        userAgent: env.ua,
        message: err?.response?.data?.message ?? err?.message,
      };

      bus.emit(event);
      results.push(event);

      console.log(`❌ [${i}] ${env.ip} → ${status}`);
    }
  }

  return new Timeline(bus.all()).build();
}