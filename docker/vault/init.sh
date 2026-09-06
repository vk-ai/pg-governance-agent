#!/bin/sh
# Initialize Vault KV v2 with demo DB credentials (dev only)
set -eu

echo "[vault-init] waiting for vault..."
i=0
until vault status >/dev/null 2>&1 || [ "$i" -ge 30 ]; do
  i=$((i + 1))
  sleep 1
done

# Enable KV v2 at secret/ if not already
vault secrets enable -path=secret kv-v2 2>/dev/null || true

# Map roles to demo passwords (must match 01-schema.sql)
vault kv put secret/pgguard/db \
  host=postgres \
  port=5432 \
  database=corpdb \
  sslmode=disable \
  reader_user=app_reader \
  reader_password=reader_demo_pass \
  writer_user=app_writer \
  writer_password=writer_demo_pass \
  migrator_user=app_migrator \
  migrator_password=migrator_demo_pass \
  user=app_reader \
  password=reader_demo_pass

echo "[vault-init] wrote secret/pgguard/db"
vault kv get secret/pgguard/db >/dev/null
echo "[vault-init] done"
