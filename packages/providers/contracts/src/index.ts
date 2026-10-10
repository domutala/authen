// Les contrats providers vivent maintenant dans @authen/core (ports/providers),
// car AuthenticationService en a besoin et un package ne peut pas dépendre
// de lui-même en cercle. Ce package reste comme point d'entrée léger pour les providers.
export type {
  AuthenticationProvider,
  AuthStep,
  CredentialEnrollmentProvider,
  CredentialRevocationProvider,
  ProviderCapability,
  ProviderContext,
  ProviderManifest,
  ProviderRegistry,
  RecoveryProvider,
  VerifiedProviderIdentity,
} from "@authen/core";

export {
  supportsEnrollment,
  supportsRecovery,
  supportsRevocation,
} from "@authen/core";
