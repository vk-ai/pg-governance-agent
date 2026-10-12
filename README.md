# PgGuard Agent

Corporate-grade **Postgres governance MCP server** for Cursor and other MCP clients.

PgGuard sits between an AI assistant and your PostgreSQL database. It enforces role-based access (RBAC), statement classification, confirmation gates for DML/DDL, optional HashiCorp Vault secrets, and append-only audit logging — so agents can query and change data without bypassing corporate controls.

**Repo:** [github.com/vk-ai/pg-governance-agent](https://github.com/vk-ai/pg-governance-agent) · **License:** MIT

---

## Docs

| Doc | What it is for |
|-----|----------------|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Components, data flow, MCP surface |
| [SECURITY.md](./SECURITY.md) | Threat model, secrets, confirm gates |
| [GOVERNANCE.md](./GOVERNANCE.md) | Roles, policy.yaml, audit expectations |
| [LOCAL_TEST.md](./LOCAL_TEST.md) | Rancher Desktop / Compose local walkthrough |

---

## What you get

**MCP tools**

| Tool | Purpose |
|------|---------|
| `db_health` | Ping + Postgres version |
| `list_schemas` / `list_tables` / `describe_table` | Safe introspection |
| `run_select` | `SELECT` only, row-capped |
| `run_dml` | Data changes — requires `confirm: true`; `dry_run: true` previews the affected row count; capped by `max_affected_rows` |
| `run_ddl` | Schema changes — requires `confirm`; optional `dry_run` |
| `explain_query` | `EXPLAIN` (`ANALYZE` gated by policy) |
| `get_audit_tail` | Recent audit events |
| `whoami` | Effective role + policy (+ optional JWT principal) |

**Principal propagation** — HS256 JWT, verified and required by default, (`bearer_token` / `PGGUARD_BEARER_TOKEN`) maps to Postgres session GUCs (`app.user_id`, …) for RLS. See [SECURITY.md](./SECURITY.md).

**Roles** (`PGGUARD_ROLE`) — see [`config/policy.yaml`](./config/policy.yaml)

| Role | Typical use | DB user (default policy) |
|------|-------------|---------------------------|
| `reader` | Analyst / read-only agent | `app_reader` |
| `writer` | App DML with confirmation | `app_writer` |
| `migrator` | Schema changes with confirmation | `app_migrator` |
| `admin` | Break-glass (still audited) | per policy |

---

## Requirements

- **Node.js 20+**
- A reachable **PostgreSQL** instance (existing corporate DB *or* the demo Compose stack)
- Optional: **HashiCorp Vault** KV v2 for credentials (`PGGUARD_SECRETS_PROVIDER=vault`)

---

## Onboard with an existing Postgres DB

Use this path when you already have Postgres (local, RDS, Cloud SQL, on-prem, etc.). You do **not** need Docker Compose.

### 1. Clone and install

```bash
git clone https://github.com/vk-ai/pg-governance-agent.git
cd pg-governance-agent
cp .env.example .env
npm install
npm test
npm run policy:check
npm run build
```

### 2. Create least-privilege DB users (recommended)

Map users to roles in `config/policy.yaml` (`db_user` per role). Example grants (adjust schema names):

```sql
-- Read-only
CREATE ROLE app_reader LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE your_db TO app_reader;
GRANT USAGE ON SCHEMA public TO app_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO app_reader;

-- Writer (DML)
CREATE ROLE app_writer LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE your_db TO app_writer;
GRANT USAGE ON SCHEMA public TO app_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_writer;

-- Migrator (DDL) — tighten to your change process
CREATE ROLE app_migrator LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE your_db TO app_migrator;
GRANT ALL ON SCHEMA public TO app_migrator;
```

You can point a single role at an existing service account by editing `db_user` in `config/policy.yaml` — prefer dedicated agent roles over shared superusers.

### 3. Point `.env` at your database

Set at least:

```bash
PGGUARD_ROLE=reader
PGGUARD_SECRETS_PROVIDER=env
PGGUARD_POLICY_PATH=./config/policy.yaml
PGGUARD_AUDIT_DIR=./data/audit

PGHOST=your-db-host.example.com   # prefer 127.0.0.1 for local sockets/quirks
PGPORT=5432
PGDATABASE=your_db
PGUSER=app_reader
PGPASSWORD=...                    # never commit .env
PGSSLMODE=require                 # use require/verify-full in production
```

**Vault instead of env passwords:** set `PGGUARD_SECRETS_PROVIDER=vault`, `VAULT_ADDR`, `VAULT_TOKEN` (or AppRole), and `VAULT_KV_PATH`. Store keys such as `host`, `port`, `database`, `user`, `password`, `sslmode` (and optional `reader_user` / `writer_user` / …) under that path. Details in [SECURITY.md](./SECURITY.md).

### 4. Wire Cursor MCP

1. Copy [`config/cursor-mcp.example.json`](./config/cursor-mcp.example.json).
2. Replace `REPLACE_WITH_ABS_PATH` with the absolute path to this repo.
3. Set `PG*` (or Vault) env to **your** database — not the demo `corpdb` values.
4. Paste into Cursor MCP settings and reload MCP servers.

Or run stdio directly:

```bash
npm run mcp
```

### 5. Smoke-test tools

1. `whoami` → `reader` (or your chosen role)
2. `db_health` → version string
3. `list_tables` for your schema
4. `run_select` → limited rows
5. `run_dml` as `reader` → **denied**; as `writer` with `confirm: true` → allowed
6. `get_audit_tail` → events under `data/audit/`

Tune allowlists, `max_rows`, and confirm flags in [`config/policy.yaml`](./config/policy.yaml). Governance expectations: [GOVERNANCE.md](./GOVERNANCE.md).

---

## Demo stack (no existing DB)

If you want a disposable local Postgres + Vault (Rancher Desktop / Docker):

```bash
cp .env.example .env
npm install && npm test && npm run policy:check
docker compose up -d          # postgres:16 + vault + vault-init
npm run build && npm run mcp
```

Seeded demo DB: `corpdb`, schema `corp` (orgs / employees). Step-by-step: **[LOCAL_TEST.md](./LOCAL_TEST.md)**.

Demo passwords live only in `.env.example` and Compose init scripts. **Never commit `.env`.**

---

## Package scripts

| Script | What it does |
|--------|----------------|
| `npm run build` | Compile TypeScript → `dist/` |
| `npm run mcp` | Start stdio MCP server |
| `npm test` | Unit tests (+ live Postgres tests when `PGGUARD_IT_DATABASE_URL` is set) |
| `npm run policy:check` | Validate `config/policy.yaml` |

---

## Read-only transactions (let Postgres say no)

Read tools (`db_health`, `list_*`, `describe_table`, `run_select`, `explain_query`) run as:

```text
BEGIN READ ONLY
  set_config('statement_timeout' | 'lock_timeout' | 'idle_in_transaction_session_timeout', <policy>, true)
  set_config('app.user_id', <jwt sub>, true)   -- principal GUCs, same transaction
  <your SELECT>                                  -- extended protocol: one statement only
ROLLBACK
```

- The classifier is the first gate. Postgres is the second: a `SELECT` that calls a writing function, or `EXPLAIN ANALYZE` of DML, fails with `cannot execute … in a read-only transaction`.
- Timeouts come from `defaults` in `config/policy.yaml` (`statement_timeout_ms`, `lock_timeout_ms`, `idle_in_transaction_session_timeout_ms`; per-role overrides; `0` disables).
- Principal GUCs are now set **inside** the transaction that runs the query. Before, `set_config(..., true)` ran on its own, outside any transaction, so the value was gone before the query ran. `run_dml`/`run_ddl` with a principal run in `BEGIN … COMMIT` for the same reason.
- The demo RLS policy (`docker/postgres/optional/rls-orders-by-employee.sql`) fails closed: no principal means no rows.

Try it against a throwaway database (needs a superuser URL; the Compose Postgres works):

```bash
docker compose up -d postgres
PGGUARD_IT_DATABASE_URL=postgres://postgres:postgres_dev_only@localhost:5432/postgres npm test
```

Without `PGGUARD_IT_DATABASE_URL`, the live tests are skipped and only the unit tests run.

---

## DML preview and row cap (`run_dml` `dry_run` + `max_affected_rows`)

Agents that run `DELETE`/`UPDATE` with a bad `WHERE` clause are a common horror story
([HN: agent deleted the prod DB](https://news.ycombinator.com/item?id=47911524),
[HN discussion](https://news.ycombinator.com/item?id=44632270)). `run_dml` now runs every
statement as:

```text
BEGIN
  set_config(<timeouts>, true); set_config('app.user_id', <jwt sub>, true)   -- same as reads
  <your INSERT/UPDATE/DELETE>          -- extended protocol: one statement only
  dry_run        -> ROLLBACK, return rowCount (+ up to 5 RETURNING rows)
  rowCount > cap -> ROLLBACK, return an error
  otherwise      -> COMMIT
```

- `dry_run: true` needs no `confirm`. It returns `rowCount`, `would_exceed_cap` and a
  `sample` from a `RETURNING` clause. The count goes through the same RLS policy and
  principal as the real write, so it is the real count for that user at that moment.
- `max_affected_rows` comes from `config/policy.yaml` (default 100; writer 50, migrator
  1000, admin 10000). The cap is checked inside the write's own transaction, so there is
  no gap between "preview said 3 rows" and "the write hit 3000".
- Writes now also get the policy's `statement_timeout` / `lock_timeout`.

**Real vs not verified.** Tested against a live Postgres 17 (9 integration tests: counts,
RLS per principal and fail-closed, cap rollback, commit under the cap, WITH CHECK errors,
clean pooled session) plus unit tests of the SQL order. Limits: a rolled-back statement
still advances sequences, runs triggers (their writes are undone; anything they do outside
the database is not), and holds row locks until the rollback, so a dry run on a hot table
can block other writers for up to `lock_timeout`/`statement_timeout`. The count is a
snapshot; it can differ when the real write runs later. DDL is unchanged
(`run_ddl` `dry_run` still only parses). This repo has no CI workflow; tests were run
locally.

---

## Security notes (short)

**Phase 1 security fixes (this is a learning project; the threat model and limits are below).**

What changed, and why:

- **Cross-tenant read via `set_config` (fixed, reproduced live).** Before, `SELECT * FROM corp.orders WHERE set_config('app.user_id','2',true) IS NOT NULL` let user 1 read user 2's rows, because the RLS policy trusted a plain GUC that any role can rewrite. `tests/rls-spoof.integration.test.ts` reproduces the leak on Postgres 17 with the old policy, then shows it is blocked.
  - *DB layer (the real fix):* Postgres cannot make a custom GUC read-only, so a SECURITY DEFINER *setter* alone would not help. Instead PgGuard also sets `app.user_id_mac = HMAC-SHA256(key, 'pgguard:v1:'||user_id)` and the policy calls `pgguard.current_user_id()`, a SECURITY DEFINER function that reads the key from a table the agent roles cannot read and returns the id only if the MAC verifies (`docker/postgres/optional/rls-principal-verify.sql`). A rewritten id gives NULL → no rows. I chose this over per-tenant roles because it needs one key, no role per user and no `SET ROLE` from the gateway.
  - *Gateway layer:* function calls are checked by walking the parsed SQL (AST) plus a quote-aware lexer, not by regex. `set_config`, `dblink*`, `*fdw*` functions, `pg_terminate_backend`/`pg_cancel_backend`, advisory locks, `pg_sleep*` and file/large-object functions are blocked, including `"dblink"(`, `pg_catalog."SET_CONFIG"(`, calls in CTEs/subqueries/WHERE, inside `EXPLAIN`, and SQL the parser cannot read. `CREATE SERVER`/`FOREIGN TABLE`/`EXTENSION`, `USER MAPPING` and `U&` escapes are refused.
- **Verified identity, fail closed.** `require_jwt: true` by default; tokens must verify as HS256 with `PGGUARD_JWT_SECRET`. With no secret, tokens are refused instead of decoded. `PGGUARD_DEV_INSECURE_JWT=1` restores decode-only/no-token behaviour for local dev only.
- **Row cap the agent can't raise.** `run_select` uses `min(max_rows, policy max_rows)` and truncates returned rows, so a `LIMIT` inside a subquery no longer skips the cap.
- **TLS.** `sslmode=verify-ca` now validates the certificate chain (it used to set `rejectUnauthorized:false`); `verify-full` also checks the hostname; unknown modes are refused.

Still true / not fixed yet (phases 2–5):

- The token is still a tool argument. It must be signed, but an agent holding several users' tokens can pick among them.
- The HMAC key is static per deployment, with no expiry or session binding; an agent can read its *own* MAC. Key rotation is manual (`pgguard.set_rls_key`). Avoid `log_statement=all` / parameter logging, which would record MACs.
- Function blocking is a denylist; a new or extension function with side effects is not caught. Read-only access, timeouts and schemas are still enforced per transaction by the app, not on the DB role (phase 2). No schema allowlist or byte cap yet (phase 3). `confirm:true` is still agent-supplied, not human approval (phase 4). No DB host allowlist, tamper-evident audit or CI against Postgres (phase 5).
- Old RLS policies that read `current_setting('app.user_id')` directly are still spoofable at the DB layer; move them to `pgguard.current_user_id()`.

Also: use least-privilege DB roles, keep DML/DDL behind `confirm`, ship `data/audit/` off the box, and treat Compose Vault as dev-only.

Full guidance: [SECURITY.md](./SECURITY.md) · [GOVERNANCE.md](./GOVERNANCE.md) · [ARCHITECTURE.md](./ARCHITECTURE.md)

---

## Contributing / support

Issues and PRs welcome on [vk-ai/pg-governance-agent](https://github.com/vk-ai/pg-governance-agent). Start with the docs table above before changing policy or MCP tools.
