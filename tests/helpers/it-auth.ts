/** Shared test-only secrets for live-Postgres suites (never used outside tests). */
import { createHmac } from "node:crypto";

export const TEST_JWT_SECRET = "pgguard-test-only-jwt-secret";
export const TEST_RLS_KEY_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

export function signedJwt(claims: Record<string, unknown>, secret = TEST_JWT_SECRET): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const data = `${enc({ alg: "HS256", typ: "JWT" })}.${enc(claims)}`;
  return `${data}.${createHmac("sha256", secret).update(data).digest("base64url")}`;
}

export function unsignedJwt(claims: Record<string, unknown>): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${enc({ alg: "none", typ: "JWT" })}.${enc(claims)}.`;
}

export const RLS_SQL_FILES = [
  "docker/postgres/init/01-schema.sql",
  "docker/postgres/init/02-seed.sql",
  "docker/postgres/optional/rls-principal-verify.sql",
  "docker/postgres/optional/rls-orders-by-employee.sql",
];

export const SET_KEY_SQL = `SELECT pgguard.set_rls_key(decode('${TEST_RLS_KEY_HEX}', 'hex'))`;
