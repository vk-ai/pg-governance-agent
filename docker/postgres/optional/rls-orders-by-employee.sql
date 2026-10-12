-- Demo: tenant-style RLS on corp.orders keyed by the PgGuard principal GUC.
--
-- Apply manually (not part of the Compose init, so default demos keep full-table SELECT):
--   psql "$DATABASE_URL" -f docker/postgres/optional/rls-orders-by-employee.sql
--
-- Fails closed: when app.user_id is unset or empty, nullif(...) yields NULL, the
-- comparison is NULL, and the policy matches no rows. An earlier version of this
-- example also allowed all rows when the setting was NULL/'' (fail open).
--
-- Requires docker/postgres/optional/rls-principal-verify.sql first. The policy reads
-- pgguard.current_user_id(), which returns app.user_id only when PgGuard's HMAC in
-- app.user_id_mac checks out, so set_config('app.user_id', ...) inside agent SQL
-- cannot switch tenants.
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
    employee_id::text = pgguard.current_user_id()
  )
  WITH CHECK (
    employee_id::text = pgguard.current_user_id()
  );
