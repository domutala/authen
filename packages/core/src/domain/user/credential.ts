import type {
  CredentialId,
  IdentityId,
  Metadata,
  ProviderInstanceId,
  Timestamps,
  UserId,
} from "../../shared/types.js";

export type CredentialStatus = "active" | "revoked" | "expired";

export interface Credential extends Timestamps {
  id: CredentialId;
  userId: UserId;
  identityId: IdentityId | null;

  providerInstanceId: ProviderInstanceId;
  type: string;

  status: CredentialStatus;

  secretRef: string | null;
  publicData: Metadata;

  expiresAt: Date | null;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
}
