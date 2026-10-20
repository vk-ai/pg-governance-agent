export interface DbCredentials {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  sslmode?: string;
  /** CA bundle (PEM file path) for verify-ca / verify-full, like libpq sslrootcert. */
  sslrootcert?: string;
  /** Set by the network guard when it pins an address: the hostname TLS must verify. */
  tlsServername?: string;
}

export interface SecretsProvider {
  getDbCredentials(roleDbUser?: string): Promise<DbCredentials>;
}
