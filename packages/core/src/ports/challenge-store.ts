/**
 * Stockage temporaire à usage unique (codes OTP, `state`, `nonce`, PKCE...).
 * Implémentations typiques : Redis, ou une table avec expiration.
 */
export interface ChallengeStore {
  save(key: string, value: string, expiresAt: Date): Promise<void>;

  /**
   * Vérifie la valeur sous le même verrou que sa consommation. La valeur n'est
   * supprimée que si `predicate` renvoie vrai. Un résultat non consommé reste
   * disponible pour un nouvel essai.
   */
  consumeIf(
    key: string,
    predicate: (value: string) => boolean,
  ): Promise<{ value: string; consumed: boolean } | null>;

  /**
   * Lit ET supprime la valeur de façon atomique : un challenge ne peut
   * être consommé qu'une seule fois. Retourne `null` si absent ou expiré.
   */
  consume(key: string): Promise<string | null>;
}
