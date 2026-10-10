import type { ClientId, SessionId, TokenFamilyId } from "../../shared/types.js";

/**
 * Une famille = toute la chaîne de refresh tokens d'une session pour un client.
 * Chaque rotation remplace le token précédent dans la même famille.
 * Si un ancien token réapparaît (vol possible), on révoque toute la famille.
 */
export interface TokenFamily {
  id: TokenFamilyId;

  sessionId: SessionId;
  clientId: ClientId;
  /** Scopes accordés, conservés à chaque rotation. */
  scopes: string[];

  createdAt: Date;
  expiresAt: Date;

  revokedAt: Date | null;
  revocationReason: string | null;
}
