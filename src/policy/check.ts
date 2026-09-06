#!/usr/bin/env node
import { validatePolicyFile } from "./loader.js";
import { log } from "../utils/logger.js";

const result = validatePolicyFile();
if (!result.ok) {
  log("error", "policy_check_failed", { errors: result.errors });
  console.error("policy:check FAILED");
  for (const e of result.errors) console.error(" -", e);
  process.exit(1);
}
console.log("policy:check OK");
log("info", "policy_check_ok", {});
