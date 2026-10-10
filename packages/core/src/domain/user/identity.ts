import type {
  IdentityId,
  Metadata,
  ProviderInstanceId,
  Timestamps,
  UserId,
} from "../../shared/types.js";

export type IdentityStatus = "active" | "disabled" | "unlinked";

export interface Identity extends Timestamps {
  id: IdentityId;
  userId: UserId;

  providerInstanceId: ProviderInstanceId;
  providerSubject: string;

  status: IdentityStatus;
  verifiedAt: Date | null;
  lastUsedAt: Date | null;

  metadata: Metadata;
}
