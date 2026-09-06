# PgGuard Agent

Corporate Postgres governance MCP server.

Docs: ARCHITECTURE.md, SECURITY.md, GOVERNANCE.md, LOCAL_TEST.md

License: MIT

## Quickstart

1. Copy env example, install Node packages.
2. Run test and policy check scripts.
3. Start docker compose stack (Postgres + Vault).
4. Build TypeScript and start MCP on stdio.

See LOCAL_TEST.md for Rancher Desktop details.

## MCP tools

- db_health: ping + version
- list_schemas, list_tables, describe_table
- run_select: SELECT only with max rows
- run_dml: data changes require confirm true
- run_ddl: schema changes require confirm; dry_run optional
- explain_query: EXPLAIN; ANALYZE gated
- get_audit_tail: recent audit events
- whoami: role and effective policy

## Roles

PGGUARD_ROLE selects reader, writer, migrator, or admin (config/policy.yaml).

## Package scripts

- build: compile to dist/
- mcp: run stdio server
- test: Jest classifier and policy tests
- policy:check: validate policy.yaml

## Cursor MCP configuration

Add an MCP server that runs node on dist/index.js.
Environment (from .env.example):

- PGGUARD_ROLE=reader
- PGGUARD_SECRETS_PROVIDER=env (or vault)
- PGGUARD_POLICY_PATH=./config/policy.yaml
- PGGUARD_AUDIT_DIR=./data/audit
- PGHOST=127.0.0.1 PGPORT=5432 PGDATABASE=corpdb
- PGUSER=app_reader PGSSLMODE=disable
- For vault: VAULT_ADDR and VAULT_TOKEN (demo token in .env.example)

Demo DB passwords live only in .env.example and Compose init scripts; do not commit .env.

Example Cursor MCP JSON: config/cursor-mcp.example.json
