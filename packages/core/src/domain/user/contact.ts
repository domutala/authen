import type { ContactId, Timestamps, UserId } from "../../shared/types.js";

export type ContactType = "email" | "phone";

export interface UserContact extends Timestamps {
  id: ContactId;
  userId: UserId;

  type: ContactType;
  value: string;
  normalizedValue: string;

  isPrimary: boolean;
  verifiedAt: Date | null;
}
