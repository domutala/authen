export interface SigningKeyRecord {
  kid: string;
  algorithm: "RS256";
  /** Partie publique au format JWK (publiée dans le JWKS). */
  publicJwk: Record<string, unknown>;
  /** Clé privée PKCS#8 chiffrée (AES-256-GCM) : jamais stockée en clair. */
  privateKeyEncrypted: string;
  /** `active` signe ; `retiring` ne signe plus mais reste vérifiable (et publiée). */
  status: "active" | "retiring";
  createdAt: Date;
  retiredAt: Date | null;
  /** Date de retrait du JWKS pour une clé `retiring`. */
  expiresAt: Date | null;
}

export interface SigningKeyTransaction {
  list(): Promise<SigningKeyRecord[]>;
  insert(record: SigningKeyRecord): Promise<void>;
  update(record: SigningKeyRecord): Promise<void>;
  delete(kid: string): Promise<void>;
}

export interface SigningKeyStore {
  /**
   * Exécute `work` de façon exclusive (verrou) : deux instances qui démarrent
   * ou font tourner les clés en même temps ne créent pas deux clés actives.
   */
  transaction<T>(work: (tx: SigningKeyTransaction) => Promise<T>): Promise<T>;
}
