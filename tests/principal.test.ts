import { createHmac } from "node:crypto";
import {
  verifyHs256Jwt,
  decodeJwtPayload,
  gucsForPrincipal,
  principalFromClaims,
  resolvePrincipal,
  DEFAULT_PRINCIPAL_PROPAGATION,
  PrincipalError,
} from "../src/auth/principal.js";

function b64url(buf: Buffer | string): string {
  const b = typeof buf === "string" ? Buffer.from(buf, "utf8") : buf;
  return b.toString("base64url");
}

function signHs256(payload: Record<string, unknown>, secret: string): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const sig = createHmac("sha256", secret).update(data).digest();
  return `${data}.${b64url(sig)}`;
}

describe("principal / JWT", () => {
  const secret = "test-secret-do-not-use-in-prod";

  test("verifyHs256Jwt accepts valid token", () => {
    const token = signHs256(
      { sub: "user-42", email: "a@example.com", exp: Math.floor(Date.now() / 1000) + 3600 },
      secret,
    );
    const p = verifyHs256Jwt(token, secret);
    expect(p.sub).toBe("user-42");
    expect(p.email).toBe("a@example.com");
  });

  test("verifyHs256Jwt rejects bad signature", () => {
    const token = signHs256({ sub: "user-42" }, secret);
    expect(() => verifyHs256Jwt(token, "wrong")).toThrow(PrincipalError);
  });

  test("verifyHs256Jwt rejects expired", () => {
    const token = signHs256(
      { sub: "user-42", exp: Math.floor(Date.now() / 1000) - 10 },
      secret,
    );
    expect(() => verifyHs256Jwt(token, secret)).toThrow(/expired/i);
  });

  test("gucsForPrincipal maps claims", () => {
    const p = principalFromClaims({ sub: "u1", email: "e@x.com" });
    const gucs = gucsForPrincipal(p, DEFAULT_PRINCIPAL_PROPAGATION);
    expect(gucs["app.user_id"]).toBe("u1");
    expect(gucs["app.user_email"]).toBe("e@x.com");
  });

  test("resolvePrincipal with secret verifies", () => {
    const prev = process.env.PGGUARD_JWT_SECRET;
    process.env.PGGUARD_JWT_SECRET = secret;
    try {
      const token = signHs256({ sub: "abc" }, secret);
      const p = resolvePrincipal({ bearer_token: token }, DEFAULT_PRINCIPAL_PROPAGATION);
      expect(p?.sub).toBe("abc");
    } finally {
      if (prev === undefined) delete process.env.PGGUARD_JWT_SECRET;
      else process.env.PGGUARD_JWT_SECRET = prev;
    }
  });

  test("resolvePrincipal without secret decodes only", () => {
    const prev = process.env.PGGUARD_JWT_SECRET;
    delete process.env.PGGUARD_JWT_SECRET;
    try {
      const token = signHs256({ sub: "dev-user", email: "d@x.com" }, secret);
      const p = resolvePrincipal({ bearer_token: token }, {
        ...DEFAULT_PRINCIPAL_PROPAGATION,
        require_jwt: false,
      });
      expect(p?.sub).toBe("dev-user");
      // decode path still works
      expect(decodeJwtPayload(token).sub).toBe("dev-user");
    } finally {
      if (prev !== undefined) process.env.PGGUARD_JWT_SECRET = prev;
    }
  });

  test("require_jwt fails without token", () => {
    expect(() =>
      resolvePrincipal({}, { ...DEFAULT_PRINCIPAL_PROPAGATION, require_jwt: true }),
    ).toThrow(/required/i);
  });
});
