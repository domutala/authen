import type { TokenFamily } from "../../domain/token/token-family.js";
import type { SessionId, TokenFamilyId } from "../../shared/types.js";

export interface TokenFamilyRepository {
  findById(id: TokenFamilyId): Promise<TokenFamily | null>;
  findBySessionId(sessionId: SessionId): Promise<TokenFamily[]>;
  create(family: TokenFamily): Promise<void>;
  update(family: TokenFamily): Promise<void>;
}
