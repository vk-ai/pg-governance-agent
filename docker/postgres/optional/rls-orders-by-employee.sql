-- Demo: tenant-style RLS on corp.orders keyed by the PgGuard principal GUC.
--
-- Apply manually (not part of the Compose init, so default demos keep full-table SELECT):
--   psql "$DATABASE_URL" -f docker/postgres/optional/rls-orders-by-employee.sql
--
-- Fails closed: when app.user_id is unset or empty, nullif(...) yields NULL, the
-- comparison is NULL, and the policy matches no rows. An earlier version of this
-- example also allowed all rows when the setting was NULL/'' (fail open).
--
-- PgGuard sets app.user_id with set_config(..., true) inside the same transaction
-- as the query (BEGIN READ ONLY for read tools), so the value is visible here.
-- Note: table owners and superusers bypass RLS unless FORCE ROW LEVEL SECURITY is set.

ALTER TABLE corp.orders ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS orders_by_employee ON corp.orders;
CREATE POLICY orders_by_employee ON corp.orders
  FOR ALL
  TO app_reader, app_writer
  USING (
    employee_id::text = nullif(current_setting('app.user_id', true), '')
  )
  WITH CHECK (
    employee_id::text = nullif(current_setting('app.user_id', true), '')
  );
