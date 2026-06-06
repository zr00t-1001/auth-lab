import { client } from '../core/client';
import { classify } from '../core/classify';

type HijackOptions = {
  token: string;
  sessionId: string;
};

const spoofEnvironments = [
  { ip: '185.12.44.10', ua: 'Chrome Win' },
  { ip: '91.200.33.21', ua: 'iPhone Safari' },
  { ip: '77.88.11.55', ua: 'Android Chrome' },
  { ip: '103.44.22.99', ua: 'Mac Safari' },
];

const sleep = (ms: number) =>
  new Promise<void>((r) => setTimeout(r, ms));

export async function runSessionHijack({ token }: HijackOptions) {
  console.log('💣 SESSION HIJACK SIMULATION START');

  const requests = spoofEnvironments.map(async (env, index) => {
    await sleep(index * 50);

    const headers = {
      Authorization: `Bearer ${token}`,
      'User-Agent': env.ua,
      'x-forwarded-for': env.ip,
    };

    try {
      const res = await client.get('/sessions', { headers });

      const { layer, classification } = classify(res.status);

      return {
        env,
        status: res.status,
        layer,
        classification,
        data: res.data,
      };
    } catch (err: any) {
      const status = err?.response?.status ?? 0;
      const { layer, classification } = classify(status);

      return {
        env,
        status,
        layer,
        classification,
        data: err?.response?.data,
      };
    }
  });

  const results = await Promise.all(requests);

  console.log('\n📊 SESSION HIJACK RESULTS:\n');

  results.forEach((r, i) => {
    console.log(
      `Request ${i + 1}: [${r.layer}] ${r.status} (${r.classification}) IP=${r.env.ip}`
    );
  });

  return results;
}