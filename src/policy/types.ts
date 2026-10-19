export type StatementClass =
  | "select"
  | "insert"
  | "update"
  | "delete"
  | "create"
  | "alter"
  | "drop"
  | "explain"
  | "other"
  | "blocked";

export type Capability =
  | "health"
  | "introspect"
  | "select"
  | "dml"
  | "ddl"
  | "explain"
  | "audit_read"
  | "whoami";

export interface RolePolicy {
  description: string;
  db_user: string;
  allow: Capability[];
  deny: Capability[];
  max_rows?: number;
  /** run_dml rolls back (and dry runs flag) statements affecting more rows than this. */
  max_affected_rows?: number;
  require_confirm_dml?: boolean;
  require_confirm_ddl?: boolean;
  allow_explain_analyze?: boolean;
  dual_control_ddl?: boolean;
  /** Per-role overrides for read transactions (ms; 0 disables). */
  statement_timeout_ms?: number;
  lock_timeout_ms?: number;
  idle_in_transaction_session_timeout_ms?: number;
  /** Schemas this role may reference (gateway early-deny; DB grants are the guarantee). Omit to disable the guard. */
  allowed_schemas?: string[];
  /** search_path PgGuard sets in each transaction; must be a subset of allowed_schemas. Defaults to allowed_schemas. */
  search_path?: string[];
  /** run_select / explain_query: total result budget (compact JSON bytes). */
  max_result_bytes?: number;
  /** Per-cell cap; longer text/bytea/json values are cut and reported. */
  max_cell_bytes?: number;
  /** Phase 4: override approvals.required_for for this role ([] turns approvals off for it). */
  approvals_required_for?: ApprovalKind[];
}

/** Statement kinds that can require an out-of-band approval. */
export type ApprovalKind = "dml" | "ddl";

/** Phase 4 `approvals:` block in policy.yaml. */
export interface ApprovalsYaml {
  /** Real (non-dry-run) run_dml / run_ddl calls need a signed approval token. */
  required_for?: ApprovalKind[];
  /** Env var with the approver's Ed25519 public key (PEM). `<env>_FILE` may point at a PEM file instead. */
  public_key_env?: string;
  /** Longest lifetime (exp - iat) the server accepts. */
  max_ttl_seconds?: number;
  /** Tolerated approver clock lead for iat (expiry gets no grace). */
  clock_skew_seconds?: number;
  /** Where single-use jtis are recorded: file (default) or postgres (pgguard.consume_approval). */
  ledger?: "file" | "postgres";
  /** Request queue + file ledger directory. */
  dir?: string;
}

export interface PrincipalPropagationYaml {
  enabled?: boolean;
  jwt_secret_env?: string;
  require_jwt?: boolean;
  claim_sub?: string;
  claim_email?: string;
  session_gucs?: Record<string, string>;
  rls_hmac_key_env?: string;
}

export interface PolicyConfig {
  version: number;
  approvals?: ApprovalsYaml;
  principal_propagation?: PrincipalPropagationYaml;
  defaults: {
    max_rows: number;
    max_affected_rows?: number;
    require_confirm_dml: boolean;
    require_confirm_ddl: boolean;
    allow_explain_analyze: boolean;
    audit_retention_days: number;
    /** Read tools run in BEGIN READ ONLY with these SET LOCAL timeouts (ms; 0 disables). */
    statement_timeout_ms?: number;
    lock_timeout_ms?: number;
    idle_in_transaction_session_timeout_ms?: number;
    allowed_schemas?: string[];
    search_path?: string[];
    max_result_bytes?: number;
    max_cell_bytes?: number;
  };
  blocked_patterns: string[];
  dangerous_functions: string[];
  roles: Record<string, RolePolicy>;
}

export interface ClassificationResult {
  ok: boolean;
  statementClass: StatementClass;
  reason?: string;
  statements: number;
}
