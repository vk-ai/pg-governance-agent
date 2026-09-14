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
  require_confirm_dml?: boolean;
  require_confirm_ddl?: boolean;
  allow_explain_analyze?: boolean;
  dual_control_ddl?: boolean;
}

export interface PrincipalPropagationYaml {
  enabled?: boolean;
  jwt_secret_env?: string;
  require_jwt?: boolean;
  claim_sub?: string;
  claim_email?: string;
  session_gucs?: Record<string, string>;
}

export interface PolicyConfig {
  version: number;
  principal_propagation?: PrincipalPropagationYaml;
  defaults: {
    max_rows: number;
    require_confirm_dml: boolean;
    require_confirm_ddl: boolean;
    allow_explain_analyze: boolean;
    audit_retention_days: number;
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
