# PgGuard Agent — Architecture

## Overview

PgGuard is a **governance MCP server** that sits between an AI client (e.g. Cursor) and a corporate PostgreSQL database. It enforces RBAC, statement-class allowlists, confirmation gates for DML/DDL, Vault-backed secrets, and append-only audit logging.

```
┌─────────────┐     stdio MCP      ┌──────────────────┐
│ Cursor /    │ ◄────────────────► │ PgGuard Agent    │
│ MCP Client  │                    │ (TypeScript)     │
└─────────────┘                    │  - policy.yaml   │
                                   │  - classifier    │
                                   │  - audit JSONL   │
                                   └────────┬─────────┘
                          secrets           │ parameterized SQL
                     ┌──────┴──────┐        ▼
                     │ Vault KV v2 │   ┌──────────┐
                     │ or env      │──►│ Postgres │
                     └─────────────┘   │ 16       │
                                       └──────────┘
```

## Components

| Component | Path | Responsibility |
|-----------|------|----------------|
| MCP server | `src/index.ts`, `src/mcp/` | stdio tools, request routing |
| Policy / RBAC | `config/policy.yaml`, `src/policy/` | Roles, capabilities, confirm gates |
| Approvals (phase 4) | `src/approvals/`, `docker/postgres/optional/approval-ledger.sql` | Ed25519-signed, single-use, expiring, SQL-hash-bound approvals; approver CLI |
| SQL classifier | `src/policy/classifier.ts` | Statement class + blocklist heuristics (`pgsql-ast-parser` + regex) |
| Secrets | `src/secrets/` | Vault KV v2 or env fallback |
| DB access | `src/db/` | `pg` pool, introspection helpers |
| Audit | `src/audit/` | Append-only JSONL under `data/audit/` |
| Compose stack | `docker-compose.yml` | Postgres 16 + Vault 1.15 (dev) + init |

## Data flow

1. Client calls an MCP tool (e.g. `run_select`).
2. Agent resolves `PGGUARD_ROLE` → effective policy (capabilities, max rows, confirm flags).
3. For SQL tools: classify statement → allow/deny → optional `confirm` / `dry_run` → for real DML/DDL, verify and consume a human-signed approval (phase 4).
4. Credentials fetched for the role’s `db_user` from Vault or env, then checked against the phase 5 network policy (host allowlist, resolved addresses, `verify-full` for non-loopback); the connection goes to the checked (pinned) address.
5. Query runs via `node-postgres` (parameterized for introspection; user SQL is single-statement only).
6. Result returned on MCP; hash-chained audit event appended (phase 5); structured log line on stderr.

## Trust boundaries

| Boundary | Trust assumption |
|----------|------------------|
| MCP client ↔ Agent | Client is semi-trusted; agent still enforces policy (client can be compromised). |
| Agent ↔ Vault | Vault token/AppRole is highly sensitive; agent host is trusted for that secret. |
| Agent ↔ Postgres | DB users are least-privilege (`app_reader` / `app_writer` / `app_migrator`). DB is second line of defense. |
| Agent ↔ network | Phase 5 host allowlist + DNS pinning + `verify-full` in process; real egress control is NetworkPolicy/SG + `pg_hba.conf` (`deploy/networkpolicy.yaml`). |
| Audit log | Hash-chained JSONL (optional HMAC key), verified on start; production should ship lines and chain heads to SIEM/WORM storage. |

## Threat model summary

| Threat | Mitigation |
|--------|------------|
| Prompt injection → destructive SQL | Classifier allowlist; role caps; `confirm` for DML/DDL; out-of-band signed approval bound to the SQL hash (phase 4) |
| Multi-statement / stacked queries | Rejected by classifier |
| Privilege escalation (`SET ROLE`, GRANT) | Blocked patterns |
| Secret leakage in repo | Vault / `.env` (gitignored); `.env.example` only |
| Audit tampering | Hash-chained JSONL (HMAC with a key), `npm run audit:verify`, refuse to start on a broken chain; production: external immutable store + recorded heads |
| Agent used as a network pivot (other DBs, metadata service) | `network.allowed_db_hosts` / `allowed_db_cidrs`, link-local always refused, DNS pinning; NetworkPolicy example |
| DB traffic interception | `sslmode=verify-full` required for non-loopback hosts; preflight checks `pg_stat_ssl` |
| EXPLAIN ANALYZE side effects | Gated by role policy |

See [SECURITY.md](./SECURITY.md) and [GOVERNANCE.md](./GOVERNANCE.md).
