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
| SQL classifier | `src/policy/classifier.ts` | Statement class + blocklist heuristics (`pgsql-ast-parser` + regex) |
| Secrets | `src/secrets/` | Vault KV v2 or env fallback |
| DB access | `src/db/` | `pg` pool, introspection helpers |
| Audit | `src/audit/` | Append-only JSONL under `data/audit/` |
| Compose stack | `docker-compose.yml` | Postgres 16 + Vault 1.15 (dev) + init |

## Data flow

1. Client calls an MCP tool (e.g. `run_select`).
2. Agent resolves `PGGUARD_ROLE` → effective policy (capabilities, max rows, confirm flags).
3. For SQL tools: classify statement → allow/deny → optional `confirm` / `dry_run`.
4. Credentials fetched for the role’s `db_user` from Vault or env.
5. Query runs via `node-postgres` (parameterized for introspection; user SQL is single-statement only).
6. Result returned on MCP; audit event appended; structured log line on stderr.

## Trust boundaries

| Boundary | Trust assumption |
|----------|------------------|
| MCP client ↔ Agent | Client is semi-trusted; agent still enforces policy (client can be compromised). |
| Agent ↔ Vault | Vault token/AppRole is highly sensitive; agent host is trusted for that secret. |
| Agent ↔ Postgres | DB users are least-privilege (`app_reader` / `app_writer` / `app_migrator`). DB is second line of defense. |
| Audit log | Local filesystem append-only for demo; production should ship to SIEM/WORM storage. |

## Threat model summary

| Threat | Mitigation |
|--------|------------|
| Prompt injection → destructive SQL | Classifier allowlist; role caps; `confirm` for DML/DDL; dual-control flag for DDL |
| Multi-statement / stacked queries | Rejected by classifier |
| Privilege escalation (`SET ROLE`, GRANT) | Blocked patterns |
| Secret leakage in repo | Vault / `.env` (gitignored); `.env.example` only |
| Audit tampering | Append-only JSONL; production: external immutable store |
| EXPLAIN ANALYZE side effects | Gated by role policy |

See [SECURITY.md](./SECURITY.md) and [GOVERNANCE.md](./GOVERNANCE.md).
