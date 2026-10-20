# PgGuard Agent — Governance

## Change control

1. **Schema changes (DDL)** require:
   - Agent role `migrator` or `admin`
   - Policy capability `ddl`
   - `confirm: true` on `run_ddl`
   - Optional `dry_run: true` to parse/validate without executing
   - Dual-control flag in policy (`dual_control_ddl: true`) — treat confirm as the second control in automation workflows (pair with human approval in the client/runbook)
2. **Data changes (DML)** require `writer+` and `confirm: true` when `require_confirm_dml` is set.
3. **Reads** are allowed for `reader+` with max-row caps.

## Dual-control for DDL

Corporate expectation: no single actor applies production DDL silently.

- Policy marks migrator/admin with `dual_control_ddl: true`.
- MCP tool refuses DDL without `confirm: true`.
- Audit trail records who (role), what (SQL preview), when.
- Recommended process: PR / change ticket → `request_approval` (includes dry_run count) → human runs `npm run approvals -- approve <id>` → agent runs with `confirm: true` + `approval_id`. The approval is single use, expires, and only matches the exact SQL that was reviewed (phase 4).

## RBAC roles

Defined in `config/policy.yaml`:

| Role | Intent |
|------|--------|
| `reader` | Analyst / read-only agent |
| `writer` | Application data fixes |
| `migrator` | Schema migrations |
| `admin` | Break-glass (still confirm + audit) |

Select with env: `PGGUARD_ROLE=reader`.

## Retention

- Default audit retention guidance: **90 days** (`defaults.audit_retention_days` in policy).
- Demo stores local JSONL, hash-chained since phase 5. Operators should rotate/archive externally, run `npm run audit:verify` before archiving, and record each file's head `{seq, hash}` somewhere the agent host can't write.
- Only `writer` and above have `audit_read` by default; `reader` cannot read other principals' SQL through `get_audit_tail`.
- Seed/demo data in Compose is disposable.

## Statement policy (summary)

| Class | Tools | Roles |
|-------|-------|-------|
| SELECT | `run_select` | reader+ |
| DML | `run_dml` | writer+ + confirm |
| DDL | `run_ddl` | migrator/admin + confirm |
| EXPLAIN | `explain_query` | per role; ANALYZE gated |
| Blocked | — | multi-stmt, COPY, SET ROLE, GRANT, dangerous fns |


## Principal propagation

End-user identity is separate from the agent role (`PGGUARD_ROLE`). The agent still connects as `db_user` from policy; JWT claims are applied only as session GUCs for RLS and appear on audit rows as `principal`. Operators should treat missing `principal` as "service account only" and enable `require_jwt` when compliance needs human attribution.
