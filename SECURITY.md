# PgGuard Agent — Security

## Secrets

- **Preferred:** HashiCorp Vault KV v2 at `secret/data/pgguard/db` (see `src/secrets/vault.ts`).
  - Auth: `VAULT_TOKEN` or AppRole (`VAULT_ROLE_ID` + `VAULT_SECRET_ID`).
  - Compose starts Vault in **dev mode** for local demos only — not for production.
- **Fallback:** `src/secrets/env.ts` + `.env` (never commit). Use `.env.example` as a template.
- Role-specific DB passwords are mapped (`reader_*`, `writer_*`, `migrator_*`) so the agent connects as the least-privilege DB user for `PGGUARD_ROLE`.

## Least privilege

| Agent role | DB user | Capabilities |
|------------|---------|--------------|
| reader | `app_reader` | SELECT + introspect |
| writer | `app_writer` | SELECT + DML (confirm) |
| migrator | `app_migrator` | SELECT + DML + DDL (confirm, dual-control) |
| admin | `app_migrator` | Same as migrator; break-glass, still audited |

Postgres grants in `docker/postgres/init/01-schema.sql` mirror this.

## TLS notes

- Set `PGSSLMODE` / Vault `sslmode` to `require` or `verify-full` in non-local environments.
- Pool config enables TLS when `sslmode !== disable` (`src/db/pool.ts`).
- Local Compose uses `disable` for simplicity on localhost.

## SQL injection defenses

1. **Introspection tools** use parameterized queries (`$1`, `$2`).
2. **User-supplied SQL** is never string-concatenated with untrusted identifiers from the model beyond the statement itself; instead:
   - Single-statement enforcement
   - Statement-class allowlist (SELECT / DML / DDL / EXPLAIN)
   - Blocklist: `COPY`, `INTO OUTFILE`, `SET ROLE`, `GRANT`/`REVOKE`, user/role DDL, dangerous functions (`pg_read_file`, etc.)
3. `run_select` appends `LIMIT` when missing (`PGGUARD_MAX_ROWS` / policy `max_rows`).
4. Prefer connecting as `app_reader` for read paths so DB privileges backstop the agent.

> Defense in depth: agent policy is necessary but not sufficient — always use least-privilege DB roles.

## Audit

- Append-only JSONL: `data/audit/events.jsonl` (gitignored).
- Each tool invocation logs role, tool name, success/failure, SQL preview (truncated), timestamps.
- Structured operational logs → **stderr** as JSON lines (stdout reserved for MCP).

## Production checklist

- [ ] Vault (or cloud secret manager) — no long-lived passwords in env on shared hosts
- [ ] TLS to Postgres and Vault
- [ ] Ship audit to immutable / SIEM store
- [ ] Restrict who can set `PGGUARD_ROLE=admin|migrator`
- [ ] Network isolation: agent host → DB/Vault only
