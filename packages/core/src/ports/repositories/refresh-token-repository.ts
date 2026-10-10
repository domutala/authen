import type { RefreshTokenRecord } from "../../domain/token/refresh-token.js";
import type { TokenId } from "../../shared/types.js";

export interface RefreshTokenRepository {
  /** Recherche par condensat du token (jamais par la valeur en clair). */
  findByHash(tokenHash: string): Promise<RefreshTokenRecord | null>;

  create(record: RefreshTokenRecord): Promise<void>;

  /**
   * Marque le token comme consommé, de façon ATOMIQUE et conditionnelle
   * (ex. `UPDATE ... SET consumed_at = ?, replaced_by = ?
   *       WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL`).
   * Retourne `true` si CET appel a consommé le token, `false` s'il l'était déjà.
   * C'est ce qui empêche deux requêtes simultanées d'utiliser le même token.
   */
  markConsumed(
    id: TokenId,
    consumedAt: Date,
    replacedByTokenId: TokenId,
  ): Promise<boolean>;
}
