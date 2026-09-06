-- Dummy corporate seed data
INSERT INTO corp.orgs (name, region) VALUES
  ('Acme Holdings', 'US'),
  ('Globex APAC', 'APAC'),
  ('Initech EU', 'EU')
ON CONFLICT (name) DO NOTHING;

INSERT INTO corp.employees (org_id, email, full_name, title) VALUES
  (1, 'ada@acme.example', 'Ada Lovelace', 'Principal Engineer'),
  (1, 'alan@acme.example', 'Alan Turing', 'Staff Engineer'),
  (2, 'grace@globex.example', 'Grace Hopper', 'Engineering Manager'),
  (3, 'linus@initech.example', 'Linus Torvalds', 'SRE')
ON CONFLICT (email) DO NOTHING;

INSERT INTO corp.orders (org_id, employee_id, amount_cents, status) VALUES
  (1, 1, 125000, 'paid'),
  (1, 2, 4999, 'pending'),
  (2, 3, 88000, 'paid'),
  (3, 4, 1500, 'cancelled'),
  (1, 1, 22000, 'refunded');
