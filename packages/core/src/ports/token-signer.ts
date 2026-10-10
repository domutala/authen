import type { ClientId, SessionId, UserId } from "../shared/types.js";

/**
 * Contenu d'un access token, côté Authen (modèle interne).
 * La traduction vers les claims OAuth/OIDC (iss, sub, aud, iat, exp...)
 * est faite par l'adaptateur de protocole.
 * Les dates sont en secondes Unix.
 */
export interface TokenClaims {
  issuer: string;
  subject: UserId;
  audience: string;

  sessionId: SessionId;
  clientId: ClientId;

  issuedAt: number;
  expiresAt: number;

  scopes: string[];
}

export interface TokenSigner {
  sign(claims: TokenClaims): Promise<string>;

  /**
   * Retourne `null` si le jeton est invalide : signature, algorithme non autorisé,
   * émetteur, audience ou expiration incorrects.
   * Les pannes techniques (KMS injoignable...) doivent, elles, lever une exception.
   */
  verify(token: string, expectedAudience: string): Promise<TokenClaims | null>;
}
