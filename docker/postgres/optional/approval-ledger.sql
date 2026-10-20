-- Phase 4: single-use approval ledger (optional; policy approvals.ledger: postgres).
--
-- PgGuard calls pgguard.consume_approval(jti, sql_sha256, tool, approver, expires_at)
-- before running an approved statement. For run_dml the call is inside the DML
-- transaction, so the approval is spent only if the write commits.
--
-- The table is owned by the installer and not granted to agent roles; they can
-- only call the SECURITY DEFINER function. An agent that calls it directly can at
-- most burn an approval (deny itself), not create one: tokens are Ed25519-signed
-- out of band and verified by PgGuard before this runs.
--
-- Install as a superuser / schema owner:
--   psql "$DATABASE_URL" -f docker/postgres/optional/approval-ledger.sql

CREATE SCHEMA IF NOT EXISTS pgguard;
REVOKE ALL ON SCHEMA pgguard FROM PUBLIC;

CREATE TABLE IF NOT EXISTS pgguard.approval_ledger (
  jti          text        PRIMARY KEY CHECK (jti ~ '^[0-9a-f]{32}$'),
  sql_sha256   text        NOT NULL CHECK (sql_sha256 ~ '^[0-9a-f]{64}$'),
  tool         text        NOT NULL,
  approver     text        NOT NULL,
  expires_at   timestamptz NOT NULL,
  consumed_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  consumed_by  name        NOT NULL DEFAULT session_user
);
REVOKE ALL ON pgguard.approval_ledger FROM PUBLIC;

CREATE OR REPLACE FUNCTION pgguard.consume_approval(
  p_jti text, p_sql_sha256 text, p_tool text, p_approver text, p_expires_at timestamptz
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pgguard
AS $$
BEGIN
  IF p_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'approval % expired at %', p_jti, p_expires_at USING ERRCODE = '22023';
  END IF;
  -- PRIMARY KEY makes a second use fail with unique_violation (23505).
  INSERT INTO pgguard.approval_ledger (jti, sql_sha256, tool, approver, expires_at)
  VALUES (p_jti, p_sql_sha256, p_tool, p_approver, p_expires_at);
END;
$$;
REVOKE ALL ON FUNCTION pgguard.consume_approval(text, text, text, text, timestamptz) FROM PUBLIC;

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['app_writer', 'app_migrator'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT USAGE ON SCHEMA pgguard TO %I', r);
      EXECUTE format('GRANT EXECUTE ON FUNCTION pgguard.consume_approval(text, text, text, text, timestamptz) TO %I', r);
    END IF;
  END LOOP;
END $$;
