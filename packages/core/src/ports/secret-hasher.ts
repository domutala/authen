/**
 * Hachage de secrets FAIBLES en entropie (mots de passe) : lent et salé
 * (argon2id, scrypt...). Ne pas utiliser pour les refresh tokens :
 * voir `TokenDigester`.
 */
export interface SecretHasher {
  hash(secret: string): Promise<string>;
  verify(secret: string, hash: string): Promise<boolean>;
}
