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

## 7. Tear down

docker compose down. Add -v to wipe the Postgres volume.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Port 5432 busy | Stop local Postgres or remap Compose ports |
| vault-init failed | Check vault logs; ensure Vault healthy first |
| MCP silent on stdout | Expected; logs go to stderr as JSON lines |
| Role denied | Check PGGUARD_ROLE and config/policy.yaml |
| Rancher DNS quirks | Prefer 127.0.0.1 over localhost |

Compose Vault dev mode and demo passwords are local-only. Never commit .env.
