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
| `run_dml` | Data changes — requires `confirm: true` |
| `run_ddl` | Schema changes — requires `confirm`; optional `dry_run` |
| `explain_query` | `EXPLAIN` (`ANALYZE` gated by policy) |
| `get_audit_tail` | Recent audit events |
| `whoami` | Effective role + policy |

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
| `npm test` | Classifier + policy unit tests |
| `npm run policy:check` | Validate `config/policy.yaml` |

---

## Security notes (short)

- Prefer TLS (`PGSSLMODE=require` / `verify-full`) against real databases.
- Use least-privilege DB roles; keep DML/DDL behind `confirm`.
- Audit JSONL under `data/audit/` is append-only — ship or retain per your policy.
- Compose Vault is **dev mode** for demos only.

Full guidance: [SECURITY.md](./SECURITY.md) · [GOVERNANCE.md](./GOVERNANCE.md) · [ARCHITECTURE.md](./ARCHITECTURE.md)

---

## Contributing / support

Issues and PRs welcome on [vk-ai/pg-governance-agent](https://github.com/vk-ai/pg-governance-agent). Start with the docs table above before changing policy or MCP tools.
