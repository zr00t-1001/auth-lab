#!/bin/sh
# One-shot Vault bootstrap (dev mode). Configures AppRole + a least-privilege
# policy, stores the app's secrets, and exports the AppRole credentials to a
# shared volume that the api reads at boot.
set -e

echo "[vault-init] waiting for Vault to be ready..."
until vault status >/dev/null 2>&1; do sleep 1; done

# AppRole auth (idempotent across restarts)
vault auth enable approle 2>/dev/null || true

# Policy: the app may ONLY read its own secret — nothing else.
vault policy write auth-lab - <<'POLICY'
path "secret/data/auth-lab" {
  capabilities = ["read"]
}
POLICY

# Strong JWT signing keys generated here and never exposed outside Vault.
# DB_PASS comes from the environment so it matches the Postgres container.
JWT_ACCESS_SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
JWT_REFRESH_SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

vault kv put secret/auth-lab \
  JWT_ACCESS_SECRET="$JWT_ACCESS_SECRET" \
  JWT_REFRESH_SECRET="$JWT_REFRESH_SECRET" \
  DB_PASS="${DB_PASS:-1234}"

# AppRole role bound to that policy (short-lived tokens).
vault write auth/approle/role/auth-lab \
  token_policies=auth-lab \
  token_ttl=1h token_max_ttl=4h \
  secret_id_num_uses=0 secret_id_ttl=0

# Hand the api a role_id + a fresh secret_id via the shared volume.
mkdir -p /vault/creds
vault read  -field=role_id   auth/approle/role/auth-lab/role-id   > /vault/creds/role_id
vault write -f -field=secret_id auth/approle/role/auth-lab/secret-id > /vault/creds/secret_id

echo "[vault-init] done — secrets stored in Vault, AppRole credentials exported."
