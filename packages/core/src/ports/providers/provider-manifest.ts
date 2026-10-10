/**
 * Une capacité décrit ce qu'un provider sait faire.
 * Le `(string & {})` permet d'ajouter des capacités custom sans perdre l'autocomplétion.
 */
export type ProviderCapability =
  | "password"
  | "challenge"
  | "redirect"
  | "passkey"
  | "enrollment"
  | "recovery"
  | (string & {});

/** Carte d'identité d'un type de provider (ex. "google", "email-otp"). */
export interface ProviderManifest {
  type: string;
  name: string;
  version: string;

  capabilities: readonly ProviderCapability[];
}
