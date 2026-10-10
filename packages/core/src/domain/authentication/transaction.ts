import type {
  ClientId,
  Metadata,
  ProviderInstanceId,
  Timestamps,
  TransactionId,
  UserId,
} from "../../shared/types.js";

export type TransactionStatus =
  | "pending"
  | "waiting"
  | "completed"
  | "failed"
  | "expired"
  | "cancelled";

export type TransactionPurpose =
  | "sign_in"
  | "sign_up"
  | "link_identity"
  | "step_up"
  | "recovery";

export interface AuthenticationTransaction extends Timestamps {
  id: TransactionId;

  providerInstanceId: ProviderInstanceId;
  clientId: ClientId | null;
  userId: UserId | null;

  purpose: TransactionPurpose;
  status: TransactionStatus;
  currentStep: string;

  attempts: number;
  maxAttempts: number;

  stateHash: string | null;
  challengeRef: string | null;

  expiresAt: Date;
  completedAt: Date | null;

  metadata: Metadata;
}
