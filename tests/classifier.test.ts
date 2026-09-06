import {
  classifySql,
  isDml,
  isDdl,
  isSelect,
  stripComments,
} from "../src/policy/classifier.js";

describe("classifySql", () => {
  test("allows simple select", () => {
    const r = classifySql("SELECT id, name FROM corp.orgs");
    expect(r.ok).toBe(true);
    expect(isSelect(r.statementClass)).toBe(true);
  });

  test("allows select with trailing semicolon", () => {
    const r = classifySql("SELECT 1;");
    expect(r.ok).toBe(true);
    expect(r.statementClass).toBe("select");
  });

  test("blocks multiple statements", () => {
    const r = classifySql("SELECT 1; DROP TABLE corp.orgs");
    expect(r.ok).toBe(false);
    expect(r.statementClass).toBe("blocked");
    expect(r.reason).toMatch(/Multiple statements/i);
  });

  test("blocks COPY", () => {
    const r = classifySql("COPY corp.orgs TO '/tmp/x'");
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/COPY/i);
  });

  test("blocks SET ROLE", () => {
    const r = classifySql("SET ROLE app_migrator");
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/SET ROLE/i);
  });

  test("blocks dangerous function pg_read_file", () => {
    const r = classifySql("SELECT pg_read_file('/etc/passwd')");
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/pg_read_file/i);
  });

  test("blocks GRANT", () => {
    const r = classifySql("GRANT ALL ON corp.orgs TO public");
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/GRANT/i);
  });

  test("classifies INSERT as dml", () => {
    const r = classifySql("INSERT INTO corp.orgs (name, region) VALUES ('X', 'US')");
    expect(r.ok).toBe(true);
    expect(isDml(r.statementClass)).toBe(true);
    expect(r.statementClass).toBe("insert");
  });

  test("classifies UPDATE as dml", () => {
    const r = classifySql("UPDATE corp.orgs SET region = 'EU' WHERE id = 1");
    expect(r.ok).toBe(true);
    expect(isDml(r.statementClass)).toBe(true);
  });

  test("classifies DELETE as dml", () => {
    const r = classifySql("DELETE FROM corp.orders WHERE status = 'cancelled'");
    expect(r.ok).toBe(true);
    expect(isDml(r.statementClass)).toBe(true);
  });

  test("classifies CREATE TABLE as ddl", () => {
    const r = classifySql("CREATE TABLE corp.audit_tmp (id INT)");
    expect(r.ok).toBe(true);
    expect(isDdl(r.statementClass)).toBe(true);
    expect(r.statementClass).toBe("create");
  });

  test("classifies ALTER as ddl", () => {
    const r = classifySql("ALTER TABLE corp.orgs ADD COLUMN notes TEXT");
    expect(r.ok).toBe(true);
    expect(isDdl(r.statementClass)).toBe(true);
  });

  test("classifies DROP as ddl", () => {
    const r = classifySql("DROP TABLE IF EXISTS corp.audit_tmp");
    expect(r.ok).toBe(true);
    expect(isDdl(r.statementClass)).toBe(true);
  });

  test("classifies EXPLAIN", () => {
    const r = classifySql("EXPLAIN SELECT * FROM corp.orgs");
    expect(r.ok).toBe(true);
    expect(r.statementClass).toBe("explain");
  });

  test("blocks empty sql", () => {
    const r = classifySql("   ");
    expect(r.ok).toBe(false);
  });

  test("stripComments removes line and block comments", () => {
    const s = stripComments("SELECT 1 -- hi\n /* block */ + 2");
    expect(s).not.toMatch(/hi/);
    expect(s).not.toMatch(/block/);
  });

  test("blocks CREATE USER", () => {
    const r = classifySql("CREATE USER evil PASSWORD 'x'");
    expect(r.ok).toBe(false);
  });
});
