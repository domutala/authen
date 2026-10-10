import type {
  AuthenticationTransaction,
  Credential,
  CredentialId,
  Identity,
  IdentityId,
  ProviderInstance,
  ProviderInstanceId,
  RefreshTokenRecord,
  Session,
  SessionId,
  TokenFamily,
  TokenFamilyId,
  TokenId,
  TransactionId,
  User,
  UserId,
  UserProfile,
} from "@authen/core";

/** Photo de toutes les tables à un instant donné (voir `MemoryDatabase.snapshot`). */
export type MemorySnapshot = ReadonlyArray<ReadonlyMap<unknown, unknown>>;

/**
 * "Base de données" en mémoire : une `Map` par table, partagée par tous les
 * repositories. Rien n'est persisté : tout disparaît avec le processus.
 *
 * Elle sait prendre une photo (`snapshot`) et la restaurer (`restore`), ce qui
 * permet à `MemoryTransactionRunner` d'annuler une transaction qui échoue.
 */
export class MemoryDatabase {
  readonly users = new Map<UserId, User>();
  readonly identities = new Map<IdentityId, Identity>();
  readonly profiles = new Map<UserId, UserProfile>();
  readonly credentials = new Map<CredentialId, Credential>();
  readonly sessions = new Map<SessionId, Session>();
  readonly transactions = new Map<TransactionId, AuthenticationTransaction>();
  readonly providerInstances = new Map<ProviderInstanceId, ProviderInstance>();
  readonly tokenFamilies = new Map<TokenFamilyId, TokenFamily>();
  readonly refreshTokens = new Map<TokenId, RefreshTokenRecord>();

  private tables(): Map<unknown, unknown>[] {
    return [
      this.users,
      this.identities,
      this.profiles,
      this.credentials,
      this.sessions,
      this.transactions,
      this.providerInstances,
      this.tokenFamilies,
      this.refreshTokens,
    ] as Map<unknown, unknown>[];
  }

  /**
   * Copie superficielle des tables. Suffisant car les services ne modifient
   * jamais un objet en place : ils le remplacent (`{ ...objet, champ }`), et
   * les repositories stockent des copies (voir `clone`).
   */
  snapshot(): MemorySnapshot {
    return this.tables().map((table) => new Map(table));
  }

  restore(snapshot: MemorySnapshot): void {
    this.tables().forEach((table, index) => {
      table.clear();
      for (const [key, value] of snapshot[index] ?? []) table.set(key, value);
    });
  }

  /** Vide toutes les tables (utile entre deux tests). */
  clear(): void {
    for (const table of this.tables()) table.clear();
  }
}

/**
 * Copie profonde à chaque lecture / écriture, comme le ferait une vraie base :
 * un appelant ne peut pas modifier l'état stocké par accident.
 */
export function clone<T>(value: T): T {
  return structuredClone(value);
}
