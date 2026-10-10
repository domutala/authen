import type { Credential } from "../../domain/user/credential.js";
import type { CredentialId, UserId } from "../../shared/types.js";
import type {
  AuthenticationProvider,
  AuthStep,
} from "./authentication-provider.js";

/** Capacités facultatives : un provider ne les implémente que s'il les supporte. */
export interface CredentialEnrollmentProvider {
  enroll(userId: UserId, input: unknown): Promise<Credential>;
}

export interface CredentialRevocationProvider {
  revokeCredential(credentialId: CredentialId): Promise<void>;
}

export interface RecoveryProvider {
  beginRecovery(userId: UserId, input: unknown): Promise<AuthStep>;
}

/** Type guards : permettent de tester une capacité avant de l'utiliser. */
export function supportsEnrollment(
  provider: AuthenticationProvider,
): provider is AuthenticationProvider & CredentialEnrollmentProvider {
  return (
    provider.manifest.capabilities.includes("enrollment") &&
    typeof (provider as Partial<CredentialEnrollmentProvider>).enroll ===
      "function"
  );
}

export function supportsRevocation(
  provider: AuthenticationProvider,
): provider is AuthenticationProvider & CredentialRevocationProvider {
  return (
    typeof (provider as Partial<CredentialRevocationProvider>)
      .revokeCredential === "function"
  );
}

export function supportsRecovery(
  provider: AuthenticationProvider,
): provider is AuthenticationProvider & RecoveryProvider {
  return (
    provider.manifest.capabilities.includes("recovery") &&
    typeof (provider as Partial<RecoveryProvider>).beginRecovery === "function"
  );
}
