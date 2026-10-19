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
| `list_schemas` / `list_tables` / `describe_table` | Safe introspection, limited to the role's `allowed_schemas` |
| `run_select` | `SELECT` only; allowed schemas only; capped by rows, bytes and cell size (`truncated: true` when a cap applied) |
| `run_dml` | Data changes — requires `confirm: true` plus a human-signed approval (`approval_id` / `approval_token`) when policy requires it; `dry_run: true` previews the affected row count (no approval needed); capped by `max_affected_rows` |
| `run_ddl` | Schema changes — requires `confirm` plus an approval when policy requires it; optional `dry_run` |
| `request_approval` | Queue one exact DML/DDL statement for a human approver (returns `approval_id` + SQL sha256; DML includes a dry-run row count) |
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

Then apply DB-native hardenings (timeouts, read-only default for readers, `NOBYPASSRLS`, lock down `public`):

```bash
psql "$DATABASE_URL" -f scripts/provision-roles.sql
```

Compose demos run the same SQL via `docker/postgres/init/04-agent-roles.sql` on first boot. The MCP server **refuses to start** if preflight finds a superuser/BYPASSRLS role, `statement_timeout=0`, or `dblink`/`postgres_fdw` installed.

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
| `npm run approvals -- <cmd>` | Approver CLI: `keygen`, `list`, `show`, `approve`, `deny` (needs the private key; run it outside the server's environment) |

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
- Timeouts come from `defaults` in `config/policy.yaml` (`statement_timeout_ms`, `lock_timeout_ms`, `idle_in_transaction_session_timeout_ms`; per-role overrides; `0` disables via `SET LOCAL`). Role-level `ALTER ROLE … SET statement_timeout` (phase 2) is the backstop when the app does not set them.
- DDL (`run_ddl` / `withClient`) now gets the same policy timeouts.
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

## Out-of-band approvals (phase 4)

Learning project: this shows one way to make "a human approved this exact statement" something
the gateway can check, instead of trusting the agent's `confirm: true`. It has not been used with
a real change-management system.

**Flow**

1. The agent calls `request_approval` with `tool` (`run_dml` / `run_ddl`) and the exact SQL. PgGuard
   classifies it, runs the schema guard, does a rolled-back dry run for DML, and writes
   `data/approvals/pending/<approval_id>.json`. It returns `approval_id` and the SQL's sha256.
2. A human, in a separate session that holds the Ed25519 **private** key, reviews and approves:
   ```bash
   npm run approvals -- keygen ~/.pgguard-approver          # once; give the server approver.pub
   npm run approvals -- list
   npm run approvals -- show <approval_id>                   # SQL, hash, dry-run row count, reason
   PGGUARD_APPROVAL_PRIVATE_KEY_FILE=~/.pgguard-approver/approver.key \
     npm run approvals -- approve <approval_id> --approver alice --ttl 600
   ```
   (`deny <approval_id> --approver alice --note "…"` refuses it.)
3. The agent retries `run_dml` / `run_ddl` with the same SQL, `confirm: true` and `approval_id`
   (or the printed `approval_token`).

**What the server checks** (`src/approvals/token.ts`, `src/approvals/gate.ts`), before the statement runs:

- **Signed out of band.** The token is `pga1.<claims>.<Ed25519 signature>`. The server holds only the
  public key (`PGGUARD_APPROVAL_PUBLIC_KEY` or `PGGUARD_APPROVAL_PUBLIC_KEY_FILE`). It refuses to start if
  any `PGGUARD_APPROVAL_PRIVATE_KEY*` variable is in its environment.
- **Bound to the SQL.** The token carries `sha256` of the SQL exactly as submitted. Any byte change,
  including whitespace, needs a new approval. It is also bound to the tool, PgGuard role, DB user,
  database name and the JWT `sub` (null when there is no principal). All of these come from the live
  call, never from the token.
- **Expiring.** `exp - iat` must be ≤ `approvals.max_ttl_seconds` (900 in the shipped policy). Expiry has no
  grace period; `clock_skew_seconds` (30) only tolerates an approver clock running ahead for `iat`.
- **Single use.** Each token has a random 128-bit `jti`, recorded in a ledger:
  - `ledger: file` (default): `data/approvals/used/<jti>` created with `O_EXCL`, so two processes on
    one host cannot both use it. It is spent before the statement runs.
  - `ledger: postgres`: `docker/postgres/optional/approval-ledger.sql` installs `pgguard.consume_approval()`,
    a SECURITY DEFINER function writing to a table agent roles cannot read or write. For `run_dml` it runs
    inside the DML transaction, so the approval is spent only if the write commits. It also rejects a
    token whose `exp` has passed by the **database** clock.
- **Row cap.** The approver can set `--max-rows` (DML defaults to the dry-run count they were shown). The run
  uses `min(policy max_affected_rows, approved max)`.
- **No self-approval.** `approver` must differ from the requesting `sub`.
- **Fail closed.** With `required_for: [dml, ddl]` (shipped default) and no public key configured, real runs are
  refused. `dry_run` never needs an approval. `whoami` shows `approvals.public_key_configured`.

**Tests:** `tests/phase4-approvals.test.ts` (40 offline) and `tests/phase4-approvals.integration.test.ts`
(8 live, Postgres 17): end to end request → approve → run once → replay refused; Postgres ledger replay;
cap rollback leaves the approval unspent; approver cap of 0 rolls back a 1-row update; wrong-SQL and
wrong-database tokens never reach the DB; agent roles get `42501` on the ledger table; the DB clock rejects an
expired consume; DDL approved once; a writer's token refused for the migrator role.

**What is real vs. not**

- Real: Ed25519 signing and verification (`node:crypto`, no new dependencies), SQL/scope binding, expiry,
  both ledgers, the CLI, live Postgres tests.
- Not built: no Slack/email/ticket integration, no web UI, no multi-approver quorum, no key rotation or
  revocation list. The request queue is a local directory, so the agent host and the approver must share it,
  or the approver passes the token back by hand.

**Limits (honest)**

- `approver` is a name the key holder types. Anyone with the private key can approve as anyone. One key
  per approver and a revocation list are not implemented.
- The file ledger is per host. Two PgGuard hosts with separate `data/` directories could each accept the
  same token once. Use `ledger: postgres` when more than one server can reach the database.
- Burn then run: with the file ledger (and for all DDL), the approval is spent before the statement. If the
  statement then fails, a new approval is needed. DDL may run in autocommit, so it cannot share a
  transaction with the ledger.
- An agent that calls `pgguard.consume_approval()` directly can burn approvals (deny itself). It cannot
  create one. The schema guard also blocks the `pgguard` schema for roles limited to `corp`.
- The approver sees the SQL text and a dry-run count from one moment in time. Data can change before the
  approved run, and the row cap is the backstop for that.
- Existing pre-phase-4 live suites (`dml-preview`, `read-txn`) set `requiredFor: []` because they test caps
  and RLS, not approvals.
- `npm test` now runs Jest with `--runInBand`. Live suites run `ALTER ROLE` (cluster-wide) in their setup,
  and in parallel one suite could reset another's `statement_timeout` (seen once in six parallel runs as a
  phase 2 timeout). In-band, the full suite took about 7 s locally.

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

**Phase 2 — DB-native baseline:**

- `docker/postgres/init/04-agent-roles.sql` + `scripts/provision-roles.sql`: `app_reader` gets `default_transaction_read_only=on`, role-level `statement_timeout` / `lock_timeout` / `idle_in_transaction_session_timeout`, `search_path=corp`, `NOBYPASSRLS`, connection limits; writer/migrator get timeouts without read-only; `REVOKE CREATE, USAGE ON SCHEMA public FROM PUBLIC`; `FORCE ROW LEVEL SECURITY` on `corp` tables.
- `src/db/preflight.ts`: on MCP startup, refuse to start if the connected role is superuser/BYPASSRLS, `statement_timeout` is 0, read-only default does not match the tier, or `dblink`/`postgres_fdw` is installed. `whoami` exposes the result under `db_preflight`.
- DDL path (`withClient`) applies policy timeouts (previously unset).
- Live PG17 tests: writes via `WITH … DELETE` / `nextval` fail with the classifier bypassed; role timeout cancels `pg_sleep` with no app `SET LOCAL`; preflight rejects a superuser.

**Phase 3: allowed schemas and row/byte result caps (this PR):**

- `allowed_schemas` (defaults + per role, `corp` in the shipped policy) and an optional `search_path` (defaults to the allowlist; must be a subset of it). `src/policy/schemaGuard.ts` parses the SQL and refuses, before any DB call:
  - schema-qualified relations outside the list (FROM, JOIN, subqueries, CTE bodies, UNION branches, LATERAL, INSERT/UPDATE/DELETE targets, DDL names);
  - unqualified `pg_*` relations. Postgres searches `pg_catalog` first, and every `pg_catalog` relation is named `pg_*`;
  - qualified functions, types and column refs in other schemas (built-in `pg_catalog` functions are fine);
  - built-ins that run SQL from a string (`query_to_xml`, `table_to_xml`, `ts_stat`, `crosstab`, …);
  - SQL the parser cannot read (fail closed).
  It runs on `run_select`, `explain_query`, `run_dml` and `run_ddl`. `list_schemas` / `list_tables` are filtered, and `list_tables` / `describe_table` refuse other schemas. PgGuard also sets `search_path` per transaction, so unqualified names resolve the way the guard assumes.
- **Result caps.** `run_select` no longer appends `LIMIT` to the SQL text. It runs `DECLARE pgguard_result NO SCROLL CURSOR FOR <sql>` inside the READ ONLY transaction and `FETCH`es batches of 50 until it has `max_rows + 1` rows, so the extra row shows the result was cut. It also stops at `max_result_bytes`, measured as compact JSON (default 1 MiB, reader 512 KiB). Cells over `max_cell_bytes` (default 64 KiB) are cut: text on a UTF-8 boundary, `bytea` returned as `\x…` hex, `json` as cut text. The response reports `truncated`, `truncated_by` (`rows` / `bytes` / `cells`), `truncated_cells`, `truncated_columns` and `result_bytes`. `max_rows` is still `min(argument, policy)`. `explain_query` output gets the same byte budget.
- `whoami` shows `allowed_schemas`, `search_path`, `max_result_bytes` and `max_cell_bytes`.
- Live PG17 tests:
  - a schema with no grants is refused by Postgres (`42501`) with the guard turned off;
  - a schema that is granted but not allowlisted is refused by the guard and readable with the guard off, so the two layers are independent;
  - 10k-row and wide-row tables are cut by rows and by bytes;
  - 200 KB text and bytea cells are cut to 64 KiB;
  - neither `max_rows: 1e9` nor a `LIMIT` in a subquery raises the cap.

Still true / not fixed yet (phase 5 remains; phase 4 approvals are described above):

- **The schema guard is a UX layer and early deny, not the boundary.** DB grants are the boundary. Gaps the guard does not cover:
  - string-to-OID casts (`'hr.t'::regclass`, `to_regclass`) and size/metadata functions can show that an object *exists*;
  - temp tables (`pg_temp`) are searched before the path;
  - any SQL the parser cannot read is refused, which is stricter than Postgres. Some valid queries (`TABLE t`, `SELECT … FROM ONLY t`, `DELETE … USING`, some DDL) now need rewriting for roles with an allowlist. Leave `allowed_schemas` unset to turn the guard off.
- **Byte caps apply to what the agent receives, not to what crosses the wire.** Each cell is fetched in full before it is cut. That is bounded by `statement_timeout` and Postgres's 1 GB field limit. Plans with Sort/Hash/aggregates still compute their full input before the first `FETCH`.
- Schema allowlists in YAML and GRANTs in the DB can drift. Nothing generates one from the other yet.

- The token is still a tool argument. It must be signed, but an agent holding several users' tokens can pick among them.
- The HMAC key is static per deployment, with no expiry or session binding; an agent can read its *own* MAC. Key rotation is manual (`pgguard.set_rls_key`). Avoid `log_statement=all` / parameter logging, which would record MACs.
- Function blocking is a denylist; a new or extension function with side effects is not caught. A non-superuser can still `SET default_transaction_read_only TO off` — **grants** and `BEGIN READ ONLY` remain the write hard-stop for readers. `confirm:true` alone is agent-supplied; phase 4 adds signed out-of-band approvals on top (see above). No DB host allowlist, tamper-evident audit or CI against Postgres (phase 5).
- Old RLS policies that read `current_setting('app.user_id')` directly are still spoofable at the DB layer; move them to `pgguard.current_user_id()`.

Also: use least-privilege DB roles, keep DML/DDL behind `confirm`, ship `data/audit/` off the box, and treat Compose Vault as dev-only.

Full guidance: [SECURITY.md](./SECURITY.md) · [GOVERNANCE.md](./GOVERNANCE.md) · [ARCHITECTURE.md](./ARCHITECTURE.md)

---

## Contributing / support

Issues and PRs welcome on [vk-ai/pg-governance-agent](https://github.com/vk-ai/pg-governance-agent). Start with the docs table above before changing policy or MCP tools.
