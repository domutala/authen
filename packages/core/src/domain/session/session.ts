import type { SessionId, Timestamps, UserId } from "../../shared/types.js";
import type { AuthenticationContext } from "../authentication/auth-context.js";

export type SessionStatus = "active" | "revoked" | "expired";

export interface DeviceInfo {
  deviceId: string | null;
  name: string | null;
  userAgent: string | null;
  ipAddress: string | null;
}

export interface Session extends Timestamps {
  id: SessionId;
  userId: UserId;

  status: SessionStatus;
  context: AuthenticationContext;
  device: DeviceInfo;

  authenticatedAt: Date;
  lastActivityAt: Date;

  expiresAt: Date;
  absoluteExpiresAt: Date;

  revokedAt: Date | null;
  revocationReason: string | null;
}
