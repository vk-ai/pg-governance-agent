# Contributing to PgGuard Agent

Thanks for helping! PgGuard is a security-focused MCP server, so we value small, well-tested PRs.

## Setup

Requirements: **Node 20+**, npm, and (for live tests) Docker / Rancher Desktop.

```bash
git clone https://github.com/vk-ai/pg-governance-agent.git
cd pg-governance-agent
npm ci
npm test          # offline suites; live suites skip without a database
npm run build     # tsc -> dist/
npx tsc --noEmit
npm run policy:check
```

### Live tests (Postgres 17)

The integration suites run when `PGGUARD_IT_DATABASE_URL` is set (this is what CI does):

```bash
docker compose up -d postgres
PGGUARD_IT_DATABASE_URL=postgres://postgres:postgres_dev_only@localhost:5432/postgres npm test
```

The TLS suite additionally needs `PGGUARD_IT_TLS_CA` (see `.github/workflows/ci.yml`).

## Workflow

1. Pick an issue (look for [`good first issue`](https://github.com/vk-ai/pg-governance-agent/labels/good%20first%20issue)) and comment that you are on it.
2. Fork, then branch from `main`: `feat/<short-name>` or `fix/<short-name>`.
3. Keep PRs focused; add/adjust tests in `tests/`.
4. Make sure `npm ci && npx tsc --noEmit && npm run policy:check && npm test` pass.
5. Open a PR using the template; CI must be green.

## Coding standards

- TypeScript strict mode, ES modules, no `any` unless justified.
- Fail closed: on missing config/keys, refuse rather than allow.
- Logs go to **stderr** (stdout is the MCP stdio channel).
- Never log secrets, tokens, or full credentials.
- Update docs (README / SECURITY / GOVERNANCE / LOCAL_TEST) when behavior changes.

## Security-sensitive changes

Changes to `src/policy/`, `src/auth/`, `src/approvals/`, `src/audit/`, `src/net/`, `src/db/` or `config/policy.yaml`
need a description of the threat considered and tests for the bypass you are preventing
(see `tests/phase1-bypass.test.ts` for style). Do **not** report vulnerabilities in public issues; see [SECURITY.md](./SECURITY.md)
and use [GitHub private vulnerability reporting](https://github.com/vk-ai/pg-governance-agent/security/advisories/new).

By contributing you agree your work is licensed under the [MIT License](./LICENSE) and you follow the [Code of Conduct](./CODE_OF_CONDUCT.md).
