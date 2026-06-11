import { readFileSync } from 'fs';

/**
 * Phase 1 Vault integration: at boot, authenticate to Vault with AppRole and
 * pull the app's secrets (JWT signing keys, DB password) from a KV v2 path,
 * injecting them into process.env so the rest of the app reads config exactly
 * as before. Entirely gated behind USE_VAULT=true — when it's not set, this is
 * a no-op and the app falls back to plain environment variables.
 *
 * No SDK: the Vault HTTP API is a couple of REST calls, done with Node's
 * built-in fetch, so this adds zero dependencies.
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

export async function loadVaultSecrets(): Promise<void> {
  if (process.env.USE_VAULT !== 'true') return;

  const addr = (process.env.VAULT_ADDR ?? 'http://vault:8200').replace(/\/+$/, '');
  const roleId = read(process.env.VAULT_ROLE_ID, process.env.VAULT_ROLE_ID_FILE);
  const secretId = read(process.env.VAULT_SECRET_ID, process.env.VAULT_SECRET_ID_FILE);
  const secretPath = process.env.VAULT_SECRET_PATH ?? 'secret/data/auth-lab';

  if (!roleId || !secretId) {
    throw new Error(
      '[vault] USE_VAULT=true but AppRole credentials are missing — set ' +
        'VAULT_ROLE_ID(_FILE) and VAULT_SECRET_ID(_FILE).',
    );
  }

  // 1) AppRole login -> short-lived client token
  const login = await fetch(`${addr}/v1/auth/approle/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
  });
  if (!login.ok) {
    throw new Error(`[vault] AppRole login failed: ${login.status} ${await login.text()}`);
  }
  const token = (await login.json())?.auth?.client_token;
  if (!token) throw new Error('[vault] AppRole login returned no client_token');

  // 2) read the secret (KV v2 nests the payload under data.data)
  const res = await fetch(`${addr}/v1/${secretPath}`, {
    headers: { 'X-Vault-Token': token },
  });
  if (!res.ok) {
    throw new Error(`[vault] reading ${secretPath} failed: ${res.status} ${await res.text()}`);
  }
  const body = await res.json();
  const data: Record<string, unknown> = body?.data?.data ?? body?.data ?? {};

  // 3) inject into the environment before Nest reads it
  const keys = Object.keys(data);
  for (const k of keys) process.env[k] = String(data[k]);
  console.log(`[vault] loaded ${keys.length} secret(s) from ${secretPath}: ${keys.join(', ')}`);
}
