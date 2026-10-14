-- Apply DB-native agent-role controls on an existing database (non-Compose).
-- Prerequisites: roles app_reader / app_writer / app_migrator already exist
-- (see README "Create least-privilege DB users" or docker/postgres/init/01-schema.sql).
-- Safe to re-run (idempotent ALTERs / REVOKEs).
--
--   psql "$DATABASE_URL" -f scripts/provision-roles.sql
--
-- Same body as docker/postgres/init/04-agent-roles.sql.

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

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE USAGE ON SCHEMA public FROM PUBLIC;

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
