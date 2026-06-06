import { login, refresh } from "../core/http";
import { classify } from "../core/classify";
import { EventBus, type SystemEvent } from "../engine/event-bus";

const sleep = (ms: number) =>
  new Promise(resolve => setTimeout(resolve, ms));

export async function runRefreshRace(
  bus: EventBus,
  opts: { email?: string; password?: string } = {},
) {
  console.log('🔥 SOC REFRESH RACE ATTACK START');

  const loginRes = await login(opts.email ?? 'test@test.com', opts.password ?? '12345678');
  const refreshToken = loginRes.refreshToken;

  const ATTACK_COUNT = 10;

  const results = await Promise.all(
    Array.from({ length: ATTACK_COUNT }).map(async (_, i) => {
      await sleep(Math.random() * 50);

      try {
        const res = await refresh(refreshToken);
        const { layer, classification } = classify(res.status);

        const event: SystemEvent = {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          scenario: 'REFRESH_RACE',
          type: 'REFRESH',

          status: res.status,
          layer,
          classification,
          message: res.data?.message,
        };

        bus.emit(event);

        return event;
      } catch (err: any) {
        const status = err?.response?.status ?? 0;
        const { layer, classification } = classify(status);

        const event: SystemEvent = {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          scenario: 'REFRESH_RACE',
          type: 'REFRESH_ERROR',

          status,
          layer,
          classification,
          message: err?.response?.data?.message,
        };

        bus.emit(event);

        return event;
      }
    })
  );

  const success = results.filter(r => r.status === 200);
  const failures = results.filter(r => r.status !== 200);

  console.log('\n🧠 SOC ANALYSIS');
  console.log('Success:', success.length);
  console.log('Failures:', failures.length);

  return { success, failures, results };
}