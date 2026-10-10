import type { Timestamps, UserId } from "../../shared/types.js";

export interface UserProfile extends Timestamps {
  userId: UserId;

  displayName: string | null;
  givenName: string | null;
  familyName: string | null;
  avatarUrl: string | null;

  locale: string | null;
  timezone: string | null;
}
