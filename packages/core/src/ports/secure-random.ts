/** Source d'aléa cryptographiquement sûre (crypto.randomBytes / Web Crypto). */
export interface SecureRandom {
  /** Retourne `byteLength` octets aléatoires encodés en base64url. */
  token(byteLength: number): string;
}
