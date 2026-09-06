import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadPolicyConfig,
  resolveEffectivePolicy,
  hasCapability,
  validatePolicyFile,
} from "../src/policy/loader.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const policyPath = path.join(__dirname, "..", "config", "policy.yaml");

describe("policy loader", () => {
  test("loads policy.yaml", () => {
    const cfg = loadPolicyConfig(policyPath);
    expect(cfg.roles.reader).toBeDefined();
    expect(cfg.roles.writer).toBeDefined();
    expect(cfg.roles.migrator).toBeDefined();
    expect(cfg.roles.admin).toBeDefined();
  });

  test("reader cannot dml/ddl", () => {
    const cfg = loadPolicyConfig(policyPath);
    const eff = resolveEffectivePolicy(cfg, "reader");
    expect(hasCapability(eff, "select")).toBe(true);
    expect(hasCapability(eff, "dml")).toBe(false);
    expect(hasCapability(eff, "ddl")).toBe(false);
  });

  test("writer can dml but not ddl", () => {
    const cfg = loadPolicyConfig(policyPath);
    const eff = resolveEffectivePolicy(cfg, "writer");
    expect(hasCapability(eff, "dml")).toBe(true);
    expect(hasCapability(eff, "ddl")).toBe(false);
  });

  test("migrator can ddl with dual control", () => {
    const cfg = loadPolicyConfig(policyPath);
    const eff = resolveEffectivePolicy(cfg, "migrator");
    expect(hasCapability(eff, "ddl")).toBe(true);
    expect(eff.dualControlDdl).toBe(true);
    expect(eff.requireConfirmDdl).toBe(true);
  });

  test("validatePolicyFile ok", () => {
    const r = validatePolicyFile(policyPath);
    expect(r.ok).toBe(true);
  });
});
