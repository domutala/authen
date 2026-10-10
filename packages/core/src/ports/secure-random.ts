/** Source d'aléa cryptographiquement sûre (crypto.randomBytes / Web Crypto). */
export interface SecureRandom {
  /** Retourne `byteLength` octets aléatoires encodés en base64url. */
  token(byteLength: number): string;

  /**
   * Retourne `length` chiffres décimaux uniformément répartis (codes OTP).
   * L'implémentation doit éviter le biais de modulo (ex. `crypto.randomInt`).
   */
  digits(length: number): string;
}
