/**
 * Codes d'erreur stables, utilisables par les couches HTTP / OIDC
 * pour choisir le bon statut ou le bon message (jamais le texte de l'erreur).
 */
export type AuthenticationErrorCode =
  | "provider_not_found"
  | "provider_disabled"
  | "invalid_provider_response"
  | "transaction_not_found"
  | "transaction_not_active"
  | "transaction_expired"
  | "user_required"
  | "user_not_found"
  | "invalid_user_transition"
  | "identity_not_found"
  | "identity_conflict"
  | "last_identity"
  | "profile_not_found"
  | "session_not_found";

/**
 * Erreur "technique ou de contrat" : l'appelant a mal utilisé le service,
 * ou l'état est incohérent. Les refus normaux d'authentification
 * (mauvais code, compte suspendu...) ne sont PAS des exceptions :
 * ils sont renvoyés sous forme de résultat `rejected`.
 */
export class AuthenticationError extends Error {
  readonly code: AuthenticationErrorCode;

  constructor(
    code: AuthenticationErrorCode,
    message?: string,
    options?: { cause?: unknown },
  ) {
    super(message ?? code, options);
    this.name = "AuthenticationError";
    this.code = code;
  }
}
