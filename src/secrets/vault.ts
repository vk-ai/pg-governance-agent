import type { DbCredentials, SecretsProvider } from "./types.js";
import { log } from "../utils/logger.js";

interface VaultKvData {
  host?: string;
  port?: string | number;
  database?: string;
  sslmode?: string;
  user?: string;
  password?: string;
  reader_user?: string;
  reader_password?: string;
  writer_user?: string;
  writer_password?: string;
  migrator_user?: string;
  migrator_password?: string;
}

/**
 * Fetch DB credentials from HashiCorp Vault KV v2.
 * Path default: secret/data/pgguard/db (API path; mount secret, key pgguard/db).
 * Auth: VAULT_TOKEN or AppRole (VAULT_ROLE_ID + VAULT_SECRET_ID).
 */
export class VaultSecretsProvider implements SecretsProvider {
  private addr: string;
  private kvPath: string;
  private token?: string;

  constructor() {
    this.addr = (process.env.VAULT_ADDR || "http://127.0.0.1:8200").replace(/\/$/, "");
    // Accept either logical path secret/pgguard/db or API path secret/data/pgguard/db
    const raw = process.env.VAULT_KV_PATH || "secret/data/pgguard/db";
    this.kvPath = raw.includes("/data/") ? raw : raw.replace(/^(secret)\//, "secret/data/");
    this.token = process.env.VAULT_TOKEN;
  }

  private async ensureToken(): Promise<string> {
    if (this.token) return this.token;
    const roleId = process.env.VAULT_ROLE_ID;
    const secretId = process.env.VAULT_SECRET_ID;
    if (!roleId || !secretId) {
      throw new Error("Vault auth requires VAULT_TOKEN or VAULT_ROLE_ID+VAULT_SECRET_ID");
    }
    const res = await fetch(`${this.addr}/v1/auth/approle/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
    });
    if (!res.ok) {
      throw new Error(`Vault AppRole login failed: ${res.status} ${await res.text()}`);
    }
    const body = (await res.json()) as { auth?: { client_token?: string } };
    const tok = body.auth?.client_token;
    if (!tok) throw new Error("Vault AppRole login returned no client_token");
    this.token = tok;
    return tok;
  }

  async getDbCredentials(roleDbUser?: string): Promise<DbCredentials> {
    const token = await this.ensureToken();
    const url = `${this.addr}/v1/${this.kvPath.replace(/^\//, "")}`;
    log("info", "vault_fetch", { path: this.kvPath });
    const res = await fetch(url, { headers: { "X-Vault-Token": token } });
    if (!res.ok) {
      throw new Error(`Vault read failed: ${res.status} ${await res.text()}`);
    }
    const body = (await res.json()) as { data?: { data?: VaultKvData } };
    const data = body.data?.data;
    if (!data) throw new Error("Vault KV response missing data.data");

    const user = roleDbUser || data.user || "app_reader";
    let password = data.password || "";
    if (user === (data.reader_user || "app_reader") && data.reader_password) {
      password = data.reader_password;
    } else if (user === (data.writer_user || "app_writer") && data.writer_password) {
      password = data.writer_password;
    } else if (user === (data.migrator_user || "app_migrator") && data.migrator_password) {
      password = data.migrator_password;
    }

    return {
      host: data.host || "localhost",
      port: Number(data.port || 5432),
      database: data.database || "corpdb",
      user,
      password,
      sslmode: data.sslmode || "disable",
    };
  }
}
