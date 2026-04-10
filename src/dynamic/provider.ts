/**
 * Dynamic Secrets Provider Interface
 *
 * Each provider knows how to create temporary credentials at an upstream
 * service (database, cloud IAM, etc.) and revoke them when the lease expires.
 *
 * Follows the HashiCorp Vault secrets engine pattern:
 *   1. Admin stores a "connection config" (admin creds + connection info)
 *   2. Agent requests a lease → provider creates a temp credential
 *   3. Lease expires or is revoked → provider destroys the temp credential
 */

export interface DynamicCredential {
  /** Provider-specific credential data returned to the agent */
  credential: Record<string, string>;
  /** Internal handle used by the provider to revoke this credential later */
  revocation_handle: string;
}

export interface DynamicProvider {
  /** Provider type identifier (e.g. "postgresql", "mysql", "ssh-ca") */
  readonly type: string;

  /**
   * Create a temporary credential.
   * @param config - Connection/admin config stored in the dynamic secret
   * @param identity - The requesting agent's identity (used for username generation)
   * @param ttlSeconds - How long the credential should live
   */
  create(
    config: Record<string, string>,
    identity: string,
    ttlSeconds: number
  ): Promise<DynamicCredential>;

  /**
   * Revoke a previously created credential.
   * @param config - Same connection config used during creation
   * @param revocationHandle - The handle returned from create()
   */
  revoke(
    config: Record<string, string>,
    revocationHandle: string
  ): Promise<void>;

  /**
   * Validate that the admin connection config is correct and functional.
   * @param config - Connection config to test
   */
  validate(config: Record<string, string>): Promise<{ ok: boolean; error?: string }>;

  /**
   * Return the required config keys for this provider.
   */
  requiredConfig(): string[];
}
