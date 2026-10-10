/** Types d'événements de sécurité émis par le core (utiles pour l'audit). */
export const SecurityEventType = {
  AuthenticationSucceeded: "authentication.succeeded",
  AuthenticationFailed: "authentication.failed",
  UserRegistered: "user.registered",
  IdentityLinked: "identity.linked",
  IdentityUnlinked: "identity.unlinked",
  SessionCreated: "session.created",
  SessionRevoked: "session.revoked",
  RefreshTokenReuseDetected: "token.reuse_detected",
} as const;

export type SecurityEventType =
  (typeof SecurityEventType)[keyof typeof SecurityEventType];
