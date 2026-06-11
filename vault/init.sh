#!/bin/sh
# One-shot Vault bootstrap (dev mode).
#  Phase 1: AppRole + least-privilege policy + static secrets (JWT keys) in KV.
#  Phase 2: PostgreSQL database secrets engine issuing short-lived DB users.
set -e

echo "[vault-init] waiting for Vault to be ready..."
until vault status >/dev/null 2>&1; do sleep 1; done

# AppRole auth (idempotent across restarts)
vault auth enable approle 2>/dev/null || true

# Policy: read the KV secret, request dynamic DB creds, and renew leases.
vault policy write auth-lab - <<'POLICY'
path "secret/data/auth-lab" {
  capabilities = ["read"]
}
path "database/creds/auth-lab" {
  capabilities = ["read"]
}
path "sys/leases/renew" {
  capabilities = ["update"]
}
POLICY

# --- Phase 1: static secrets (JWT keys live only in Vault) ---
JWT_ACCESS_SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
JWT_REFRESH_SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
vault kv put secret/auth-lab \
  JWT_ACCESS_SECRET="$JWT_ACCESS_SECRET" \
  JWT_REFRESH_SECRET="$JWT_REFRESH_SECRET" \
  DB_PASS="${DB_PASS:-1234}"

# --- Phase 2: PostgreSQL database secrets engine ---
vault secrets enable database 2>/dev/null || true

# Vault manages roles using the Postgres superuser. {{username}}/{{password}}
# are templated from the username/password fields below.
vault write database/config/auth-lab-pg \
  plugin_name=postgresql-database-plugin \
  allowed_roles="auth-lab" \
  connection_url="postgresql://{{username}}:{{password}}@db:5432/auth_sys?sslmode=disable" \
  username="postgres" \
  password="${DB_PASS:-1234}"

# Each request mints a fresh login role. It gets CREATE on the public schema so
# TypeORM's synchronize can build the tables (which the role then owns), plus
# full privileges on the database. Short default TTL; renewable up to max_ttl.
vault write database/roles/auth-lab \
  db_name=auth-lab-pg \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT ALL PRIVILEGES ON DATABASE auth_sys TO \"{{name}}\"; GRANT ALL ON SCHEMA public TO \"{{name}}\";" \
  revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"

# AppRole role bound to the policy; export role_id + a fresh secret_id.
vault write auth/approle/role/auth-lab \
  token_policies=auth-lab \
  token_ttl=1h token_max_ttl=4h \
  secret_id_num_uses=0 secret_id_ttl=0

mkdir -p /vault/creds
vault read  -field=role_id     auth/approle/role/auth-lab/role-id   > /vault/creds/role_id
vault write -f -field=secret_id auth/approle/role/auth-lab/secret-id > /vault/creds/secret_id

echo "[vault-init] done — KV secrets, DB secrets engine, and AppRole creds ready."
