/**
 * Stockage temporaire à usage unique (codes OTP, `state`, `nonce`, PKCE...).
 * Implémentations typiques : Redis, ou une table avec expiration.
 */
export interface ChallengeStore {
  save(key: string, value: string, expiresAt: Date): Promise<void>;

  /**
   * Lit ET supprime la valeur de façon atomique : un challenge ne peut
   * être consommé qu'une seule fois. Retourne `null` si absent ou expiré.
   */
  consume(key: string): Promise<string | null>;
}
