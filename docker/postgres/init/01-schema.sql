-- PgGuard demo corporate schema
CREATE SCHEMA IF NOT EXISTS corp;

-- App roles (login users for least-privilege demos)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') THEN
    CREATE ROLE app_reader LOGIN PASSWORD 'reader_demo_pass';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') THEN
    CREATE ROLE app_writer LOGIN PASSWORD 'writer_demo_pass';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_migrator') THEN
    CREATE ROLE app_migrator LOGIN PASSWORD 'migrator_demo_pass';
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS corp.orgs (
  id          SERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  region      TEXT NOT NULL DEFAULT 'US',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS corp.employees (
  id          SERIAL PRIMARY KEY,
  org_id      INT NOT NULL REFERENCES corp.orgs(id),
  email       TEXT NOT NULL UNIQUE,
  full_name   TEXT NOT NULL,
  title       TEXT,
  hired_at    DATE NOT NULL DEFAULT CURRENT_DATE,
  active      BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS corp.orders (
  id          SERIAL PRIMARY KEY,
  org_id      INT NOT NULL REFERENCES corp.orgs(id),
  employee_id INT REFERENCES corp.employees(id),
  amount_cents BIGINT NOT NULL CHECK (amount_cents >= 0),
  currency    CHAR(3) NOT NULL DEFAULT 'USD',
  status      TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'paid', 'cancelled', 'refunded')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_employees_org ON corp.employees(org_id);
CREATE INDEX IF NOT EXISTS idx_orders_org ON corp.orders(org_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON corp.orders(status);

-- Grants: reader SELECT; writer DML; migrator DDL on corp
GRANT USAGE ON SCHEMA corp TO app_reader, app_writer, app_migrator;
GRANT SELECT ON ALL TABLES IN SCHEMA corp TO app_reader, app_writer, app_migrator;
GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA corp TO app_writer, app_migrator;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA corp TO app_writer, app_migrator;
GRANT CREATE ON SCHEMA corp TO app_migrator;
ALTER DEFAULT PRIVILEGES IN SCHEMA corp GRANT SELECT ON TABLES TO app_reader, app_writer, app_migrator;
ALTER DEFAULT PRIVILEGES IN SCHEMA corp GRANT INSERT, UPDATE, DELETE ON TABLES TO app_writer, app_migrator;
ALTER DEFAULT PRIVILEGES IN SCHEMA corp GRANT USAGE, SELECT ON SEQUENCES TO app_writer, app_migrator;
