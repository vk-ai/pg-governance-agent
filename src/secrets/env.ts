import type { DbCredentials, SecretsProvider } from "./types.js";

/** Local demo fallback — reads standard PG* / role-mapped env vars. */
export class EnvSecretsProvider implements SecretsProvider {
  async getDbCredentials(roleDbUser?: string): Promise<DbCredentials> {
    const user = roleDbUser || process.env.PGUSER || "app_reader";
    const password =
      process.env.PGPASSWORD ||
      (user === "app_writer"
        ? process.env.PGPASSWORD_WRITER || "writer_demo_pass"
        : user === "app_migrator"
          ? process.env.PGPASSWORD_MIGRATOR || "migrator_demo_pass"
          : "reader_demo_pass");

    return {
      host: process.env.PGHOST || "localhost",
      port: Number(process.env.PGPORT || 5432),
      database: process.env.PGDATABASE || "corpdb",
      user,
      password,
      sslmode: process.env.PGSSLMODE || "disable",
    };
  }
}
