import type { TokenFamilyId, TokenId } from "../../shared/types.js";

export interface RefreshTokenRecord {
  id: TokenId;
  familyId: TokenFamilyId;

  tokenHash: string;

  issuedAt: Date;
  expiresAt: Date;

  consumedAt: Date | null;
  revokedAt: Date | null;
  replacedByTokenId: TokenId | null;
}
