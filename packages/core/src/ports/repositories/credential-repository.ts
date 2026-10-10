import type { Credential } from "../../domain/user/credential.js";
import type { CredentialId, UserId } from "../../shared/types.js";

export interface CredentialRepository {
  findById(id: CredentialId): Promise<Credential | null>;
  findByUserId(userId: UserId): Promise<Credential[]>;
  create(credential: Credential): Promise<void>;
  update(credential: Credential): Promise<void>;
}
