import axios from 'axios';

/**
 * The source IP the simulator presents to the API via X-Forwarded-For. The
 * backend reads XFF first (auth.service.extractMeta), so this becomes the
 * "attacker" IP recorded on sessions and security events — and what GeoIP
 * resolves to a country/city. Override per-launch (LaunchAttackDto.sourceIp)
 * or globally via the SIM_SOURCE_IP env var. Defaults to a real public IP so
 * the lab shows geo out of the box (loopback has no location).
 */
let sourceIp = process.env.SIM_SOURCE_IP || '8.8.8.8';
export function setSourceIp(ip?: string): void {
  if (ip && ip.trim()) sourceIp = ip.trim();
}
export function getSourceIp(): string {
  return sourceIp;
}

export const client = axios.create({
  baseURL: 'http://localhost:3000',
  timeout: 5000,
  // Resolve (don't throw) for any status so scenarios can classify 4xx/5xx.
  validateStatus: () => true,
});

// Stamp every simulated request with the attacker's source IP.
client.interceptors.request.use((config) => {
  if (sourceIp && !(config.headers as any)['X-Forwarded-For']) {
    (config.headers as any)['X-Forwarded-For'] = sourceIp;
  }
  return config;
});

export function setTarget(baseURL: string): void {
  client.defaults.baseURL = baseURL;
}

export function getTarget(): string {
  return client.defaults.baseURL ?? 'http://localhost:3000';
}

export async function request(config: any) {
  return client.request(config);
}

export async function login(email: string, password: string) {
  const res = await client.post('/auth/login', { email, password });
  return res.data;
}

/**
 * The backend's refresh strategy reads the token from the JSON body field
 * `refreshToken` (ExtractJwt.fromBodyField('refreshToken')), so send it there.
 */
export async function refresh(refreshToken: string) {
  const res = await client.post('/auth/refresh', { refreshToken });
  return res;
}
