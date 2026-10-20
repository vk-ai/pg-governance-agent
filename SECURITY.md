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

### DB-native role controls (phase 2)

`docker/postgres/init/04-agent-roles.sql` (and `scripts/provision-roles.sql` for existing DBs) harden the login roles:

| Control | `app_reader` | `app_writer` / `app_migrator` |
|---------|--------------|-------------------------------|
| `NOSUPERUSER` / `NOBYPASSRLS` | yes | yes |
| `default_transaction_read_only` | `on` | `off` |
| `statement_timeout` | 15s | 15s / 60s |
| `lock_timeout` / `idle_in_transaction_session_timeout` | yes | yes |
| `search_path` | `corp` | `corp` |
| `CONNECTION LIMIT` | 10 | 5 / 3 |
| `REVOKE CREATE, USAGE ON SCHEMA public FROM PUBLIC` | yes (database-wide) | same |
| `FORCE ROW LEVEL SECURITY` on `corp.*` tables | yes | yes |

**What this does and does not guarantee**

- **Does:** role-level timeouts cancel long work even when the app forgets `SET LOCAL`; reader sessions start read-only; superuser/BYPASSRLS are refused at startup by `src/db/preflight.ts`; `dblink` / `postgres_fdw` presence fails preflight.
- **Does not:** a non-superuser can still `SET default_transaction_read_only TO off` for their session. **SELECT-only grants** (and the gateway's `BEGIN READ ONLY`) remain the hard write backstop for readers. Preflight runs once at process start against the configured DB user.

### Result caps and schema allowlist: limits (phase 3)

- Byte caps limit what the agent receives. A single large cell still crosses the wire in full before it is cut, bounded by `statement_timeout` and Postgres's 1 GB field limit. Plans that sort, hash or aggregate do their full work before the first row.
- The guard does not cover: string-to-OID casts (`'hr.t'::regclass`, `to_regclass`) and catalog-metadata functions that reveal whether an object exists; temp tables (`pg_temp` is searched before the path). DB grants cover both.
- Still pending: DB host allowlist, tamper-evident audit and CI against Postgres (phase 5).

### Out-of-band approvals (phase 4)

- Real `run_dml` / `run_ddl` calls need an Ed25519-signed token from `npm run approvals -- approve`. The server holds only the public key and refuses to start if `PGGUARD_APPROVAL_PRIVATE_KEY*` is in its environment.
- Tokens are bound to the exact SQL text (sha256), tool, role, DB user, database and JWT `sub`; they expire (`max_ttl_seconds`, no grace) and are single use (`jti` in a file ledger or `pgguard.approval_ledger`).
- Fail closed: approvals required + no public key → real runs refused.
- Limits: `approver` is self-declared by the key holder (no per-approver keys or revocation yet); the file ledger is per host (use `ledger: postgres` with more than one server); DDL and the file ledger spend the approval before the statement runs, so a failed statement needs a new approval.

## TLS notes

- Set `PGSSLMODE` / Vault `sslmode` to `require` or `verify-full` in non-local environments.
- Pool config enables TLS when `sslmode !== disable` (`src/db/pool.ts`).
- Local Compose uses `disable` for simplicity on localhost.

## SQL injection defenses

1. **Introspection tools** use parameterized queries (`$1`, `$2`).
2. **User-supplied SQL** is never string-concatenated with untrusted identifiers from the model beyond the statement itself; instead:
   - Single-statement enforcement
   - Statement-class allowlist (SELECT / DML / DDL / EXPLAIN)
   - Blocklist: `COPY`, `INTO OUTFILE`, `SET ROLE`, `GRANT`/`REVOKE`, user/role DDL, and dangerous functions found by walking the SQL AST plus a quote-aware lexer (`set_config`, `dblink*`, `*fdw*`, `pg_terminate_backend`, `pg_cancel_backend`, `pg_advisory*`, `pg_sleep*`, `pg_read_file`, `lo_*`, …). Quoted and schema-qualified names are caught. This is a denylist and a second layer only.
3. `run_select` caps rows at `min(max_rows argument, policy max_rows)` (phase 1) and, since phase 3, reads them through a server-side cursor (`DECLARE … CURSOR FOR <sql>`, then `FETCH` up to `max_rows + 1`). The SQL text is not rewritten. A subquery `LIMIT` or a huge `max_rows` cannot raise the cap. A byte budget (`max_result_bytes`) and a per-cell cap (`max_cell_bytes`) also apply. Responses say `truncated: true` and give `truncated_by`.
8. **Schema allowlist (phase 3).** `allowed_schemas` per role. `src/policy/schemaGuard.ts` walks the AST and refuses non-allowed schema-qualified relations, functions, types and DDL targets, plus unqualified `pg_*` relations (which resolve to `pg_catalog`), SQL-in-a-string built-ins (`query_to_xml`, `table_to_xml`, `ts_stat`, `crosstab`, …) and SQL it cannot parse. `search_path` is set per transaction to the allowlist. Introspection tools are filtered. This is an early deny with a clear message: **GRANTs are the guarantee.** The live tests show a grant-less schema is refused by Postgres with the guard turned off. Keep `allowed_schemas` and GRANTs in sync, because nothing generates one from the other yet.
4. Prefer connecting as `app_reader` for read paths so DB privileges backstop the agent.
5. Read tools run in `BEGIN READ ONLY` with transaction-local `statement_timeout` / `lock_timeout` / `idle_in_transaction_session_timeout` from policy, and agent SQL uses the extended query protocol, so Postgres rejects writes and multi-statement strings even if the classifier misses them.
6. DDL (`withClient`) now applies the same policy timeouts (session `SET` on the autocommit path, `SET LOCAL` when a principal transaction is open).
7. Role-level `ALTER ROLE … SET` timeouts and `default_transaction_read_only` (see above) backstop the app when `SET LOCAL` is missing.

> Defense in depth: agent policy is necessary but not sufficient — always use least-privilege DB roles and apply `scripts/provision-roles.sql`.

## Principal propagation (JWT → RLS)

Agents often connect as a shared DB role (`app_reader` / `app_writer`). For **row-level security**, PgGuard can propagate an end-user JWT into transaction-local session GUCs:

1. Pass `bearer_token` on MCP tools (or set `PGGUARD_BEARER_TOKEN`).
2. Tokens are verified as **HS256** with `PGGUARD_JWT_SECRET` (Node `crypto` only — no new deps). With no secret, tokens are **refused** (fail closed). `require_jwt: true` is the default. `PGGUARD_DEV_INSECURE_JWT=1` allows decode-only tokens and token-less calls for local dev only.
3. Inside the same transaction as the tool's query, PgGuard runs `set_config('app.user_id', …, true)` (and optional email) — **never** `SET ROLE` / `SET SESSION AUTHORIZATION` from user SQL (still blocked). Read tools use `BEGIN READ ONLY … ROLLBACK`; DML/DDL with a principal use `BEGIN … COMMIT`. (`is_local = true` only lasts until the end of the current transaction, so it must not be applied as a standalone statement.)
4. Audit events include `principal` (JWT `sub`) when present.

Configure claim→GUC mapping under `principal_propagation` in `config/policy.yaml`. Keep `require_jwt: true` in production.

**Do not let RLS trust `current_setting('app.user_id')` directly.** Any role can call `set_config` on a custom GUC, so agent SQL could switch tenants. Install `docker/postgres/optional/rls-principal-verify.sql`, load the key with `pgguard.set_rls_key(...)`, give PgGuard the same hex key in `PGGUARD_RLS_HMAC_KEY`, and write policies against `pgguard.current_user_id()`, which returns the id only when PgGuard's HMAC in `app.user_id_mac` verifies.

Example RLS policy:

```sql
-- Fails closed: unset or '' → NULL → no rows. Avoid "OR setting IS NULL" escape hatches.
-- pgguard.current_user_id() returns NULL unless the HMAC verifies.
CREATE POLICY tenant_isolation ON orders
  USING (user_id::text = pgguard.current_user_id());
```

## Audit

- Append-only JSONL: `data/audit/events.jsonl` (gitignored).
- Each tool invocation logs role, tool name, success/failure, SQL preview (truncated), timestamps.
- Structured operational logs → **stderr** as JSON lines (stdout reserved for MCP).

## Production checklist

- [ ] Vault (or cloud secret manager) — no long-lived passwords in env on shared hosts
- [ ] TLS to Postgres and Vault
- [ ] Apply `scripts/provision-roles.sql` (or equivalent) so agent roles are non-superuser, NOBYPASSRLS, timed, and reader is default read-only
- [ ] Set `allowed_schemas` per role to match the schemas you GRANT (USAGE/SELECT); grant nothing else
- [ ] Tune `max_rows` / `max_result_bytes` / `max_cell_bytes` to what an agent should ever see in one call
- [ ] Do not install `dblink` / `postgres_fdw` / untrusted PLs on agent databases (preflight refuses them)
- [ ] Ship audit to immutable / SIEM store
- [ ] Restrict who can set `PGGUARD_ROLE=admin|migrator`
- [ ] Network isolation: agent host → DB/Vault only
