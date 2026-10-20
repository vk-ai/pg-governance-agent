/**
 * Phase 5: DB network allowlist + TLS requirement, checked before any connection.
 *
 * PgGuard resolves the credential host itself, checks the name and every
 * resolved address against policy, then connects to the address it checked
 * (DNS pinning) with the original hostname kept as the TLS servername, so a
 * second DNS answer cannot redirect the socket after the check.
 *
 * This is an application-level guard. Real egress control belongs in the
 * network (Kubernetes NetworkPolicy, security groups) and in pg_hba.conf;
 * see deploy/networkpolicy.yaml and the README.
 */
import dns from "node:dns";
import net from "node:net";
import type { DbCredentials } from "../secrets/types.js";

/** Resolved `network:` policy. */
export interface NetworkPolicy {
  /** False when policy.yaml has no `network:` block (no allowlist; whoami says so). */
  enforced: boolean;
  /** Host names (exact or `*.suffix`), IP literals, or CIDRs the credential host must match. */
  allowedDbHosts: string[];
  /** When set, every resolved address must fall inside one of these. */
  allowedDbCidrs: string[];
  /** libpq sslmode required for non-loopback targets. Only verify-full is accepted. */
  requireSslmode: "verify-full";
  /** Allow non-verify-full sslmode when every resolved address is loopback (local dev). */
  plaintextLoopbackOk: boolean;
  /** Connect to the checked address instead of re-resolving the name (default true). */
  pinResolvedIp: boolean;
}

export const NETWORK_OFF: NetworkPolicy = {
  enforced: false,
  allowedDbHosts: [],
  allowedDbCidrs: [],
  requireSslmode: "verify-full",
  plaintextLoopbackOk: false,
  pinResolvedIp: false,
};

export class NetworkPolicyError extends Error {
  constructor(
    public readonly code:
      | "host_not_allowed"
      | "address_not_allowed"
      | "address_forbidden"
      | "tls_required"
      | "dns_failed",
    message: string,
  ) {
    super(message);
    this.name = "NetworkPolicyError";
  }
}

export type LookupFn = (host: string) => Promise<{ address: string; family: number }[]>;

export const systemLookup: LookupFn = async (host) =>
  dns.promises.lookup(host, { all: true, verbatim: true });

const HOST_LABEL_RE = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

function normName(h: string): string {
  return h.trim().toLowerCase().replace(/\.$/, "");
}

/** `::ffff:10.0.0.1` → `10.0.0.1`; strips IPv6 brackets and zone ids. */
export function normAddress(a: string): string {
  let s = a.trim().replace(/^\[|\]$/g, "");
  const pct = s.indexOf("%");
  if (pct >= 0) s = s.slice(0, pct);
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(s);
  if (m) return m[1]!;
  return s.toLowerCase();
}

function family(a: string): "ipv4" | "ipv6" | null {
  const v = net.isIP(a);
  return v === 4 ? "ipv4" : v === 6 ? "ipv6" : null;
}

function parseCidr(entry: string): { addr: string; prefix: number; type: "ipv4" | "ipv6" } | null {
  const [a, p] = entry.split("/");
  if (!a || p === undefined) return null;
  const addr = normAddress(a);
  const type = family(addr);
  const prefix = Number(p);
  if (!type || !/^\d+$/.test(p)) return null;
  if (prefix < 0 || prefix > (type === "ipv4" ? 32 : 128)) return null;
  return { addr, prefix, type };
}

/** Validate one allowed_db_hosts entry; returns an error message or null. */
export function hostEntryError(entry: unknown): string | null {
  if (typeof entry !== "string" || !entry.trim()) return "entries must be non-empty strings";
  const e = entry.trim();
  if (e.includes("/")) return parseCidr(e) ? null : `invalid CIDR '${e}'`;
  if (family(normAddress(e))) return null;
  const name = normName(e.startsWith("*.") ? e.slice(2) : e);
  if (e.includes("*") && !e.startsWith("*.")) return `wildcards are only allowed as a leading '*.' ('${e}')`;
  if (name.includes("*")) return `only one leading wildcard is allowed ('${e}')`;
  const labels = name.split(".");
  if (labels.length < 1 || labels.some((l) => !HOST_LABEL_RE.test(l))) return `invalid host name '${e}'`;
  if (e.startsWith("*.") && labels.length < 2) return `wildcard needs at least two labels after '*.' ('${e}')`;
  return null;
}

function blockListFor(cidrsOrIps: string[]): net.BlockList {
  const bl = new net.BlockList();
  for (const raw of cidrsOrIps) {
    const e = raw.trim();
    const c = parseCidr(e);
    if (c) {
      bl.addSubnet(c.addr, c.prefix, c.type);
      continue;
    }
    const a = normAddress(e);
    const t = family(a);
    if (t) bl.addAddress(a, t);
  }
  return bl;
}

function inList(bl: net.BlockList, address: string): boolean {
  const a = normAddress(address);
  const t = family(a);
  return t ? bl.check(a, t) : false;
}

/** Addresses PgGuard never connects to, whatever the policy says (metadata services, unspecified). */
const FORBIDDEN = blockListFor(["169.254.0.0/16", "fe80::/10", "0.0.0.0/8", "::/128", "fd00:ec2::254/128"]);
const LOOPBACK = blockListFor(["127.0.0.0/8", "::1/128"]);

export function isLoopback(address: string): boolean {
  return inList(LOOPBACK, address);
}

/** Does the credential host match an allowed_db_hosts entry? */
export function hostAllowed(host: string, allowed: string[]): boolean {
  const h = normName(host);
  const hostIp = family(normAddress(h)) ? normAddress(h) : null;
  for (const raw of allowed) {
    const e = raw.trim();
    if (hostIp) {
      if (e.includes("/") || family(normAddress(e))) {
        if (inList(blockListFor([e]), hostIp)) return true;
      }
      continue;
    }
    if (e.includes("/") || family(normAddress(e))) continue;
    const n = normName(e);
    if (n.startsWith("*.")) {
      const suffix = n.slice(1); // ".example.com"
      if (h.endsWith(suffix) && h.length > suffix.length) return true;
    } else if (h === n) {
      return true;
    }
  }
  return false;
}

export interface NetworkDecision {
  host: string;
  /** Addresses the name resolved to (or the literal). */
  resolved: string[];
  /** Address PgGuard will connect to (pinned), or the original host when pinning is off. */
  connectHost: string;
  /** Hostname used for TLS SNI + certificate check (unset for IP literals). */
  tlsServername?: string;
  loopbackOnly: boolean;
  sslmode: string;
}

/**
 * Check `creds` against the policy and return credentials that connect to the
 * verified address. Throws {@link NetworkPolicyError} before any socket is opened.
 */
export async function enforceNetworkPolicy(
  creds: DbCredentials,
  policy: NetworkPolicy,
  lookup: LookupFn = systemLookup,
): Promise<{ creds: DbCredentials; decision: NetworkDecision | null }> {
  if (!policy.enforced) return { creds, decision: null };
  const host = normName(creds.host || "");
  if (!host || !hostAllowed(host, policy.allowedDbHosts)) {
    throw new NetworkPolicyError(
      "host_not_allowed",
      `DB host '${creds.host}' is not in network.allowed_db_hosts; refusing to connect`,
    );
  }
  const literal = family(normAddress(host)) ? normAddress(host) : null;
  let resolved: string[];
  if (literal) {
    resolved = [literal];
  } else {
    try {
      resolved = [...new Set((await lookup(host)).map((r) => normAddress(r.address)))];
    } catch (e) {
      throw new NetworkPolicyError("dns_failed", `Could not resolve DB host '${creds.host}': ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!resolved.length) throw new NetworkPolicyError("dns_failed", `DB host '${creds.host}' resolved to no addresses`);
  }
  for (const a of resolved) {
    if (inList(FORBIDDEN, a)) {
      throw new NetworkPolicyError("address_forbidden", `DB host '${creds.host}' resolves to ${a} (link-local/unspecified); refusing to connect`);
    }
  }
  if (policy.allowedDbCidrs.length) {
    const bl = blockListFor(policy.allowedDbCidrs);
    const bad = resolved.filter((a) => !inList(bl, a));
    if (bad.length) {
      throw new NetworkPolicyError(
        "address_not_allowed",
        `DB host '${creds.host}' resolves to ${bad.join(", ")}, outside network.allowed_db_cidrs; refusing to connect`,
      );
    }
  }
  const loopbackOnly = resolved.every(isLoopback);
  const sslmode = (creds.sslmode || "disable").trim().toLowerCase();
  if (sslmode !== policy.requireSslmode && !(policy.plaintextLoopbackOk && loopbackOnly)) {
    throw new NetworkPolicyError(
      "tls_required",
      `sslmode=${sslmode} for DB host '${creds.host}'; network policy requires sslmode=${policy.requireSslmode}` +
        (policy.plaintextLoopbackOk ? " for non-loopback hosts" : ""),
    );
  }
  const connectHost = policy.pinResolvedIp ? resolved[0]! : creds.host;
  const tlsServername = literal ? undefined : host;
  return {
    creds: { ...creds, host: connectHost, tlsServername },
    decision: { host, resolved, connectHost, tlsServername, loopbackOnly, sslmode },
  };
}
