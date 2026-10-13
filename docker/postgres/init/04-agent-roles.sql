-- Phase 2: DB-native baseline for agent roles.
-- Runs after 01-schema.sql (roles + corp grants already exist).
-- These settings are the primary guarantee for (a) read-only and (c) timeouts;
-- the gateway classifier / BEGIN READ ONLY / SET LOCAL are a second layer.
--
-- Note: a non-superuser can still `SET default_transaction_read_only TO off` for
-- their session. Grants (SELECT-only for app_reader) and FORCE RLS remain the
-- hard backstops. Role statement_timeout applies at login and cancels long work
-- even when the app forgets SET LOCAL (unless the session explicitly sets
-- statement_timeout = 0).

-- ---------------------------------------------------------------------------
-- app_reader: read-only tier
-- ---------------------------------------------------------------------------
ALTER ROLE app_reader WITH
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION
  NOBYPASSRLS
  CONNECTION LIMIT 10;

ALTER ROLE app_reader SET default_transaction_read_only = on;
ALTER ROLE app_reader SET statement_timeout = '15s';
ALTER ROLE app_reader SET lock_timeout = '2s';
ALTER ROLE app_reader SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE app_reader SET search_path = corp;

-- ---------------------------------------------------------------------------
-- app_writer: DML tier (not read-only; still timed and locked down)
-- ---------------------------------------------------------------------------
ALTER ROLE app_writer WITH
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION
  NOBYPASSRLS
  CONNECTION LIMIT 5;

ALTER ROLE app_writer SET default_transaction_read_only = off;
ALTER ROLE app_writer SET statement_timeout = '15s';
ALTER ROLE app_writer SET lock_timeout = '2s';
ALTER ROLE app_writer SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE app_writer SET search_path = corp;

-- ---------------------------------------------------------------------------
-- app_migrator: DDL tier (longer timeouts; still no BYPASSRLS / superuser)
-- ---------------------------------------------------------------------------
ALTER ROLE app_migrator WITH
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION
  NOBYPASSRLS
  CONNECTION LIMIT 3;

ALTER ROLE app_migrator SET default_transaction_read_only = off;
ALTER ROLE app_migrator SET statement_timeout = '60s';
ALTER ROLE app_migrator SET lock_timeout = '10s';
ALTER ROLE app_migrator SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE app_migrator SET search_path = corp;

-- ---------------------------------------------------------------------------
-- Lock down public schema (Postgres 15+ already revokes CREATE from PUBLIC;
-- also revoke USAGE so unqualified names cannot resolve to public objects).
-- Agent roles use search_path=corp and do not need public.
-- ---------------------------------------------------------------------------
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE USAGE ON SCHEMA public FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- FORCE RLS on corp tables that may carry policies (table owners and the
-- roles above otherwise bypass RLS). ENABLE remains in optional/*.sql so
-- default demos keep full-table SELECT until RLS is opted in.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['orgs', 'employees', 'orders']
  LOOP
    IF EXISTS (
      SELECT 1 FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'corp' AND c.relname = t AND c.relkind = 'r'
    ) THEN
      EXECUTE format('ALTER TABLE corp.%I FORCE ROW LEVEL SECURITY', t);
    END IF;
  END LOOP;
END
$$;

-- Do not install dblink / postgres_fdw / untrusted PLs in agent databases.
-- Preflight (src/db/preflight.ts) refuses to start if those extensions exist.
