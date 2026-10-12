-- Verified RLS principal (Phase 1 fix for principal spoofing).
--
-- Problem: any role can call set_config('app.user_id', ...) on a custom GUC; Postgres
-- has no way to make a placeholder GUC read-only for a role. A policy that trusts
-- current_setting('app.user_id') can therefore be rewritten from inside a query, e.g.
--   SELECT * FROM corp.orders WHERE set_config('app.user_id','2',true) IS NOT NULL
--
-- Fix: PgGuard also sets app.user_id_mac = hex(HMAC-SHA256(key, 'pgguard:v1:' || user_id)).
-- RLS policies call pgguard.current_user_id(), a SECURITY DEFINER function that reads
-- the key from a table the agent roles cannot read and returns the user id only when
-- the MAC matches. Without the key an agent cannot mint a MAC for another user, so a
-- rewritten app.user_id yields NULL and the policy matches no rows (fail closed).
--
-- Install (as the table owner / a superuser), then load the key, which must equal
-- the PGGUARD_RLS_HMAC_KEY env var given to PgGuard (hex, 32 bytes recommended):
--   psql "$DATABASE_URL" -f docker/postgres/optional/rls-principal-verify.sql
--   psql "$DATABASE_URL" -c "SELECT pgguard.set_rls_key(decode('<hex key>','hex'))"
-- No extensions needed (HMAC is built from the core sha256() function, PG 11+).

CREATE SCHEMA IF NOT EXISTS pgguard;
REVOKE ALL ON SCHEMA pgguard FROM PUBLIC;

CREATE TABLE IF NOT EXISTS pgguard.rls_key (
  id  boolean PRIMARY KEY DEFAULT true CHECK (id),
  key bytea   NOT NULL CHECK (length(key) BETWEEN 16 AND 64)
);
REVOKE ALL ON pgguard.rls_key FROM PUBLIC;

CREATE OR REPLACE FUNCTION pgguard.hmac_sha256(k bytea, msg bytea) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  kp bytea := k || decode(repeat('00', 64 - length(k)), 'hex');
  ipad bytea := kp;
  opad bytea := kp;
BEGIN
  FOR i IN 0..63 LOOP
    ipad := set_byte(ipad, i, get_byte(kp, i) # 54);  -- 0x36
    opad := set_byte(opad, i, get_byte(kp, i) # 92);  -- 0x5c
  END LOOP;
  RETURN sha256(opad || sha256(ipad || msg));
END
$$;
REVOKE ALL ON FUNCTION pgguard.hmac_sha256(bytea, bytea) FROM PUBLIC;

CREATE OR REPLACE FUNCTION pgguard.current_user_id() RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  uid text := nullif(current_setting('app.user_id', true), '');
  mac text := nullif(current_setting('app.user_id_mac', true), '');
  k bytea;
BEGIN
  IF uid IS NULL OR mac IS NULL THEN RETURN NULL; END IF;
  SELECT key INTO k FROM pgguard.rls_key WHERE id;
  IF k IS NULL THEN RETURN NULL; END IF;
  IF encode(pgguard.hmac_sha256(k, convert_to('pgguard:v1:' || uid, 'UTF8')), 'hex') = lower(mac) THEN
    RETURN uid;
  END IF;
  RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION pgguard.current_user_id() FROM PUBLIC;

CREATE OR REPLACE FUNCTION pgguard.set_rls_key(k bytea) RETURNS void
LANGUAGE sql VOLATILE
SET search_path = pg_catalog
AS $$
  INSERT INTO pgguard.rls_key (id, key) VALUES (true, k)
  ON CONFLICT (id) DO UPDATE SET key = EXCLUDED.key;
$$;
REVOKE ALL ON FUNCTION pgguard.set_rls_key(bytea) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_reader') THEN
    GRANT USAGE ON SCHEMA pgguard TO app_reader;
    GRANT EXECUTE ON FUNCTION pgguard.current_user_id() TO app_reader;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_writer') THEN
    GRANT USAGE ON SCHEMA pgguard TO app_writer;
    GRANT EXECUTE ON FUNCTION pgguard.current_user_id() TO app_writer;
  END IF;
END
$$;
