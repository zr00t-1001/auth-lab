import { readFileSync } from 'fs';

/**
 * Vault integration, gated behind USE_VAULT=true (no-op otherwise).
 *
 *  Phase 1 — static secrets: authenticate with AppRole and read JWT signing
 *  keys (+ a fallback DB password) from a KV v2 path.
 *
 *  Phase 2 — dynamic DB credentials (USE_VAULT_DB=true): ask Vault's database
 *  secrets engine for a short-lived, per-boot PostgreSQL user, inject it as
 *  DB_USER / DB_PASS, and keep its lease alive with a background renewer.
 *
 * Everything is injected into process.env BEFORE Nest loads, so the existing
 * config reads it unchanged. No SDK — just Node's built-in fetch.
 */

function read(value?: string, file?: string): string | undefined {
  if (value && value.length) return value;
  if (file && file.length) {
    try {
      return readFileSync(file, 'utf8').trim();
    } catch {
      return undefined;
    }
  }
  return undefined;
}

async function appRoleLogin(addr: string, roleId: string, secretId: string): Promise<string> {
  const res = await fetch(`${addr}/v1/auth/approle/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
  });
  if (!res.ok) {
    throw new Error(`[vault] AppRole login failed: ${res.status} ${await res.text()}`);
  }
  const token = (await res.json())?.auth?.client_token;
  if (!token) throw new Error('[vault] AppRole login returned no client_token');
  return token;
}

let renewTimer: ReturnType<typeof setInterval> | undefined;

export async function loadVaultSecrets(): Promise<void> {
  if (process.env.USE_VAULT !== 'true') return;

  const addr = (process.env.VAULT_ADDR ?? 'http://vault:8200').replace(/\/+$/, '');
  const roleId = read(process.env.VAULT_ROLE_ID, process.env.VAULT_ROLE_ID_FILE);
  const secretId = read(process.env.VAULT_SECRET_ID, process.env.VAULT_SECRET_ID_FILE);

  if (!roleId || !secretId) {
    throw new Error(
      '[vault] USE_VAULT=true but AppRole credentials are missing — set ' +
        'VAULT_ROLE_ID(_FILE) and VAULT_SECRET_ID(_FILE).',
    );
  }

  const token = await appRoleLogin(addr, roleId, secretId);

  // --- Phase 1: static secrets from KV v2 ---
  const secretPath = process.env.VAULT_SECRET_PATH ?? 'secret/data/auth-lab';
  const kv = await fetch(`${addr}/v1/${secretPath}`, { headers: { 'X-Vault-Token': token } });
  if (!kv.ok) {
    throw new Error(`[vault] reading ${secretPath} failed: ${kv.status} ${await kv.text()}`);
  }
  const body = await kv.json();
  const data: Record<string, unknown> = body?.data?.data ?? body?.data ?? {};
  const keys = Object.keys(data);
  for (const k of keys) process.env[k] = String(data[k]);
  console.log(`[vault] loaded ${keys.length} static secret(s): ${keys.join(', ')}`);

  // --- Phase 2: dynamic database credentials ---
  if (process.env.USE_VAULT_DB === 'true') {
    const role = process.env.VAULT_DB_ROLE ?? 'auth-lab';
    const res = await fetch(`${addr}/v1/database/creds/${role}`, {
      headers: { 'X-Vault-Token': token },
    });
    if (!res.ok) {
      throw new Error(`[vault] reading database/creds/${role} failed: ${res.status} ${await res.text()}`);
    }
    const cj = await res.json();
    const username: string | undefined = cj?.data?.username;
    const password: string | undefined = cj?.data?.password;
    const leaseId: string | undefined = cj?.lease_id;
    const ttl: number = cj?.lease_duration ?? 3600;
    if (!username || !password) {
      throw new Error('[vault] database creds response missing username/password');
    }
    process.env.DB_USER = username;
    process.env.DB_PASS = password;
    console.log(
      `[vault] issued dynamic DB credentials (user=${username}, lease=${leaseId}, ttl=${ttl}s)`,
    );
    startLeaseRenewer(addr, roleId, secretId, leaseId, ttl);
  }
}

/**
 * Renew the dynamic credential's lease at half its TTL so the boot-time user
 * stays valid for the life of the process. A fresh AppRole login is used each
 * cycle (the lease is independent of the token). When the lease hits its
 * max_ttl Vault stops extending it — at that point a production app would fetch
 * a new credential and recreate its DB pool; that rotation/reconnect step is
 * intentionally left out of the lab (it needs a live environment to get right).
 */
function startLeaseRenewer(
  addr: string,
  roleId: string,
  secretId: string,
  leaseId: string | undefined,
  ttl: number,
): void {
  if (!leaseId) return;
  const everyMs = Math.max(Math.floor((ttl || 3600) / 2), 60) * 1000;
  renewTimer = setInterval(async () => {
    try {
      const token = await appRoleLogin(addr, roleId, secretId);
      const r = await fetch(`${addr}/v1/sys/leases/renew`, {
        method: 'POST',
        headers: { 'X-Vault-Token': token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ lease_id: leaseId, increment: ttl }),
      });
      if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
      console.log('[vault] renewed DB credential lease');
    } catch (e) {
      console.error('[vault] DB lease renewal failed:', (e as Error).message);
    }
  }, everyMs);
  // Don't let the renewer alone keep the process alive.
  (renewTimer as any).unref?.();
}

/** Stop the background lease renewer (used in tests / graceful shutdown). */
export function stopLeaseRenewer(): void {
  if (renewTimer) {
    clearInterval(renewTimer);
    renewTimer = undefined;
  }
}
