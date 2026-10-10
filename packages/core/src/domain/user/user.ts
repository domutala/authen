import type { Timestamps, UserId } from "../../shared/types.js";

export type UserStatus = "pending" | "active" | "suspended" | "disabled";

export interface User extends Timestamps {
  id: UserId;
  status: UserStatus;
  lastAuthenticatedAt: Date | null;
  disabledAt: Date | null;
}
