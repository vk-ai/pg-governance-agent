export interface DbCredentials {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  sslmode?: string;
}

export interface SecretsProvider {
  getDbCredentials(roleDbUser?: string): Promise<DbCredentials>;
}
