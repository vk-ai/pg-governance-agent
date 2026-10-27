# Local test guide (Rancher Desktop)

Assumes Rancher Desktop with dockerd (moby) so docker compose works.
Need Node 20+, free ports 5432 and 8200.

## 1. Install and unit test

From the project root: copy .env.example to .env, install packages,
run the test script and policy:check. Both should pass without Docker.

## 2. Validate Compose

Run docker compose config and confirm it prints a valid merged config.

## 3. Start stack

Run docker compose up -d. Wait until postgres and vault are healthy.
The vault-init one-shot container should exit successfully after writing KV demo secrets.

## 4. Smoke-test Postgres

Exec into postgres and query corp.employees / corp.orgs as postgres or app_reader.
Reader demo password matches .env.example (local demo only).

## 5. Build and run the agent

Build TypeScript, then start the MCP server with PGGUARD_ROLE=reader.
The process waits on stdio (normal for MCP). Wire it in Cursor per README.

Suggested tool checks:
1. whoami -> reader
2. db_health -> version string
3. list_tables with schema corp
4. run_select on corp.orgs
5. run_dml without confirm -> denied; as writer with confirm -> allowed
6. run_ddl as reader -> denied; as migrator with dry_run -> validated; with confirm -> executes
7. get_audit_tail -> events in data/audit/events.jsonl

## 6. Vault-backed credentials

Set PGGUARD_SECRETS_PROVIDER=vault, VAULT_ADDR=http://127.0.0.1:8200,
VAULT_TOKEN from .env.example, VAULT_KV_PATH=secret/data/pgguard/db.

Note: vault-init writes host=postgres for in-network clients.
For a host-side agent, update the KV host to 127.0.0.1 or use the env provider.

## 6a. Out-of-band approvals (phase 4)

Real (non-dry-run) `run_dml` / `run_ddl` calls need a human-signed, single-use token bound to the exact SQL.

```bash
# 1. Approver generates an Ed25519 keypair (keep approver.key OFF the server host)
mkdir -p ~/.pgguard && npm run approvals -- keygen ~/.pgguard
# 2. Server gets only the public key (add to .env), then restart the MCP server
echo "PGGUARD_APPROVAL_PUBLIC_KEY_FILE=$HOME/.pgguard/approver.pub" >> .env
```

3. In Cursor (role `writer`), call `request_approval` with `tool: "run_dml"`, the exact SQL and a `reason`. It returns an `approval_id` and the SQL sha256 (DML includes a dry-run row count).
4. Approver reviews and signs:

```bash
npm run approvals -- list
npm run approvals -- show <approval_id>
npm run approvals -- approve <approval_id> --approver alice --key ~/.pgguard/approver.key --ttl 600
# or: npm run approvals -- deny <approval_id> --approver alice --note "too broad"
```

5. Call `run_dml` with the same SQL, `confirm: true` and `approval_id`. Expected: it runs once. Retrying the same id, changing any byte of SQL, or waiting past the TTL is refused. Self-approval (approver == JWT `sub`) is refused.

Queue/ledger live in `data/approvals/` (override with `PGGUARD_APPROVALS_DIR`); for a shared ledger apply `docker/postgres/optional/approval-ledger.sql` and set `approvals.ledger: postgres` in `config/policy.yaml`.

## 6b. Network allowlist, DNS pinning, verify-full TLS (phase 5)

Allowed hosts live in `config/policy.yaml` → `network.allowed_db_hosts` (defaults: `localhost`, `127.0.0.1`, `::1`).

- Negative test: set `PGHOST=10.0.0.5` (or any unlisted host) in `.env`, restart, call `db_health` → refused before connecting.
- Loopback with `PGSSLMODE=disable` works only because `plaintext_loopback_ok: true` (demo only).
- Remote DB: add the host (or `*.suffix` / CIDR) to the allowlist, set `PGSSLMODE=verify-full` and `PGSSLROOTCERT=/path/ca.pem`. Any other sslmode is refused for non-loopback hosts.
- Link-local / metadata addresses (169.254.0.0/16, fe80::/10, 0.0.0.0/8) are always refused.
- Run `npm run policy:check` after editing the policy.

## 6c. Hash-chained audit verification (phase 5)

Every line of `data/audit/events.jsonl` carries `seq`, `prev`, `hash`.

```bash
# optional: HMAC the chain (hex, >= 32 bytes); set it in .env for the server too
export PGGUARD_AUDIT_HMAC_KEY=$(openssl rand -hex 32)
npm run audit:verify                       # exit 0 = ok; prints head {seq, hash}
npm run audit:verify -- --expect-head <seq>:<hash>   # also detects tail truncation
```

Tamper test: edit one character in an earlier line of `events.jsonl`, rerun `npm run audit:verify` → exit 1 with the first bad line. With `audit.verify_on_start: true` the MCP server refuses to start on a broken log. (Back up the file first; restore it afterwards.)

## 6d. Schema allowlist and result caps (phase 3)

Policy: `defaults.allowed_schemas: [corp]`, `max_rows`, `max_result_bytes`, `max_cell_bytes` (roles can override).

- `list_schemas` / `list_tables` show only `corp`.
- `run_select` with `SELECT * FROM pg_catalog.pg_authid` or `information_schema.tables` → denied by the schema guard (DB grants remain the real boundary).
- `run_select` with `SELECT * FROM corp.employees` as `reader` (max_rows 100) → at most 100 rows; lower `max_rows` to 2 in the policy to see `truncated: true`. Rows come through a server-side cursor, so `LIMIT` in a subquery does not bypass the cap.
- `SELECT repeat('x', 100000)` → cell truncated at `max_cell_bytes`.

## 7. Tear down

docker compose down. Add -v to wipe the Postgres volume.

Upgrading from the old `postgres:16` Compose image to `postgres:17`: the data volume is not compatible, so run `docker compose down -v` once (demo data is re-seeded on start).

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Port 5432 busy | Stop local Postgres or remap Compose ports |
| vault-init failed | Check vault logs; ensure Vault healthy first |
| MCP silent on stdout | Expected; logs go to stderr as JSON lines |
| Role denied | Check PGGUARD_ROLE and config/policy.yaml |
| Rancher DNS quirks | Prefer 127.0.0.1 over localhost |

Compose Vault dev mode and demo passwords are local-only. Never commit .env.
