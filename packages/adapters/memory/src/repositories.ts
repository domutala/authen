import type {
  AuthenticationTransaction,
  Credential,
  CredentialId,
  CredentialRepository,
  Identity,
  IdentityId,
  IdentityRepository,
  ProfileRepository,
  ProviderInstance,
  ProviderInstanceId,
  ProviderInstanceRepository,
  RefreshTokenRecord,
  RefreshTokenRepository,
  Session,
  SessionId,
  SessionRepository,
  TokenFamily,
  TokenFamilyId,
  TokenFamilyRepository,
  TokenId,
  TransactionId,
  TransactionRepository,
  User,
  UserId,
  UserProfile,
  UserRepository,
} from "@authen/core";
import { AuthenticationError, RepositoryError } from "@authen/core";
import { clone, type MemoryDatabase } from "./database.js";

export class MemoryUserRepository implements UserRepository {
  private readonly db: MemoryDatabase;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async findById(id: UserId): Promise<User | null> {
    const user = this.db.users.get(id);
    return user ? clone(user) : null;
  }

  async create(user: User): Promise<void> {
    assertAbsent(this.db.users, user.id, "user");
    this.db.users.set(user.id, clone(user));
  }

  async update(user: User): Promise<void> {
    assertPresent(this.db.users, user.id, "user");
    this.db.users.set(user.id, clone(user));
  }
}

export class MemoryIdentityRepository implements IdentityRepository {
  private readonly db: MemoryDatabase;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async findById(id: IdentityId): Promise<Identity | null> {
    const identity = this.db.identities.get(id);
    return identity ? clone(identity) : null;
  }

  async findByProviderSubject(
    instanceId: ProviderInstanceId,
    subject: string,
  ): Promise<Identity | null> {
    for (const identity of this.db.identities.values()) {
      if (
        identity.providerInstanceId === instanceId &&
        identity.providerSubject === subject
      ) {
        return clone(identity);
      }
    }
    return null;
  }

  async findByUserId(userId: UserId): Promise<Identity[]> {
    return [...this.db.identities.values()]
      .filter((identity) => identity.userId === userId)
      .map(clone);
  }

  async create(identity: Identity): Promise<void> {
    assertAbsent(this.db.identities, identity.id, "identity");
    this.assertReferences(identity);
    // Contrainte d'unicité (instance, subject), comme un index UNIQUE en base.
    for (const existing of this.db.identities.values()) {
      if (
        existing.providerInstanceId === identity.providerInstanceId &&
        existing.providerSubject === identity.providerSubject
      ) {
        throw new AuthenticationError(
          "identity_conflict",
          `Identité déjà existante : ${identity.providerSubject}`,
        );
      }
    }
    this.db.identities.set(identity.id, clone(identity));
  }

  async update(identity: Identity): Promise<void> {
    assertPresent(this.db.identities, identity.id, "identity");
    this.assertReferences(identity);
    this.db.identities.set(identity.id, clone(identity));
  }

  private assertReferences(identity: Identity): void {
    assertForeignKey(this.db.users, identity.userId, "identity.userId");
    assertForeignKey(
      this.db.providerInstances,
      identity.providerInstanceId,
      "identity.providerInstanceId",
    );
  }
}

export class MemoryProfileRepository implements ProfileRepository {
  private readonly db: MemoryDatabase;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async findByUserId(userId: UserId): Promise<UserProfile | null> {
    const profile = this.db.profiles.get(userId);
    return profile ? clone(profile) : null;
  }

  async create(profile: UserProfile): Promise<void> {
    assertAbsent(this.db.profiles, profile.userId, "profile");
    assertForeignKey(this.db.users, profile.userId, "profile.userId");
    this.db.profiles.set(profile.userId, clone(profile));
  }

  async update(profile: UserProfile): Promise<void> {
    assertPresent(this.db.profiles, profile.userId, "profile");
    assertForeignKey(this.db.users, profile.userId, "profile.userId");
    this.db.profiles.set(profile.userId, clone(profile));
  }
}

export class MemoryCredentialRepository implements CredentialRepository {
  private readonly db: MemoryDatabase;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async findById(id: CredentialId): Promise<Credential | null> {
    const credential = this.db.credentials.get(id);
    return credential ? clone(credential) : null;
  }

  async findByUserId(userId: UserId): Promise<Credential[]> {
    return [...this.db.credentials.values()]
      .filter((credential) => credential.userId === userId)
      .map(clone);
  }

  async create(credential: Credential): Promise<void> {
    assertAbsent(this.db.credentials, credential.id, "credential");
    this.assertReferences(credential);
    this.db.credentials.set(credential.id, clone(credential));
  }

  async update(credential: Credential): Promise<void> {
    assertPresent(this.db.credentials, credential.id, "credential");
    this.assertReferences(credential);
    this.db.credentials.set(credential.id, clone(credential));
  }

  private assertReferences(credential: Credential): void {
    assertForeignKey(this.db.users, credential.userId, "credential.userId");
    assertForeignKey(
      this.db.identities,
      credential.identityId,
      "credential.identityId",
    );
    assertForeignKey(
      this.db.providerInstances,
      credential.providerInstanceId,
      "credential.providerInstanceId",
    );
  }
}

export class MemorySessionRepository implements SessionRepository {
  private readonly db: MemoryDatabase;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async findById(id: SessionId): Promise<Session | null> {
    const session = this.db.sessions.get(id);
    return session ? clone(session) : null;
  }

  async findByUserId(userId: UserId): Promise<Session[]> {
    return [...this.db.sessions.values()]
      .filter((session) => session.userId === userId)
      .map(clone);
  }

  async create(session: Session): Promise<void> {
    assertAbsent(this.db.sessions, session.id, "session");
    assertForeignKey(this.db.users, session.userId, "session.userId");
    this.db.sessions.set(session.id, clone(session));
  }

  async update(session: Session): Promise<void> {
    assertPresent(this.db.sessions, session.id, "session");
    assertForeignKey(this.db.users, session.userId, "session.userId");
    this.db.sessions.set(session.id, clone(session));
  }
}

export class MemoryTransactionRepository implements TransactionRepository {
  private readonly db: MemoryDatabase;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async findById(id: TransactionId): Promise<AuthenticationTransaction | null> {
    const transaction = this.db.transactions.get(id);
    return transaction ? clone(transaction) : null;
  }

  async create(transaction: AuthenticationTransaction): Promise<void> {
    assertAbsent(this.db.transactions, transaction.id, "transaction");
    this.assertReferences(transaction);
    this.db.transactions.set(transaction.id, clone(transaction));
  }

  async update(
    transaction: AuthenticationTransaction,
    expected: Pick<AuthenticationTransaction, "status" | "attempts" | "updatedAt">,
  ): Promise<boolean> {
    assertPresent(this.db.transactions, transaction.id, "transaction");
    const current = this.db.transactions.get(transaction.id)!;
    if (
      current.status !== expected.status ||
      current.attempts !== expected.attempts ||
      current.updatedAt.getTime() !== expected.updatedAt.getTime()
    ) {
      return false;
    }
    this.assertReferences(transaction);
    this.db.transactions.set(transaction.id, clone(transaction));
    return true;
  }

  private assertReferences(transaction: AuthenticationTransaction): void {
    assertForeignKey(
      this.db.providerInstances,
      transaction.providerInstanceId,
      "transaction.providerInstanceId",
    );
    if (transaction.userId !== null) {
      assertForeignKey(this.db.users, transaction.userId, "transaction.userId");
    }
  }
}

export class MemoryProviderInstanceRepository implements ProviderInstanceRepository {
  private readonly db: MemoryDatabase;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async findById(id: ProviderInstanceId): Promise<ProviderInstance | null> {
    const instance = this.db.providerInstances.get(id);
    return instance ? clone(instance) : null;
  }

  /** Ajoute ou remplace une instance (pas dans le port : sert à préparer les tests). */
  async save(instance: ProviderInstance): Promise<void> {
    this.db.providerInstances.set(instance.id, clone(instance));
  }
}

export class MemoryTokenFamilyRepository implements TokenFamilyRepository {
  private readonly db: MemoryDatabase;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async findById(id: TokenFamilyId): Promise<TokenFamily | null> {
    const family = this.db.tokenFamilies.get(id);
    return family ? clone(family) : null;
  }

  async findBySessionId(sessionId: SessionId): Promise<TokenFamily[]> {
    return [...this.db.tokenFamilies.values()]
      .filter((family) => family.sessionId === sessionId)
      .map(clone);
  }

  async create(family: TokenFamily): Promise<void> {
    assertAbsent(this.db.tokenFamilies, family.id, "token family");
    assertForeignKey(this.db.sessions, family.sessionId, "tokenFamily.sessionId");
    this.db.tokenFamilies.set(family.id, clone(family));
  }

  async update(family: TokenFamily): Promise<void> {
    assertPresent(this.db.tokenFamilies, family.id, "token family");
    assertForeignKey(this.db.sessions, family.sessionId, "tokenFamily.sessionId");
    this.db.tokenFamilies.set(family.id, clone(family));
  }
}

export class MemoryRefreshTokenRepository implements RefreshTokenRepository {
  private readonly db: MemoryDatabase;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async findByHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
    for (const record of this.db.refreshTokens.values()) {
      if (record.tokenHash === tokenHash) return clone(record);
    }
    return null;
  }

  async create(record: RefreshTokenRecord): Promise<void> {
    assertAbsent(this.db.refreshTokens, record.id, "refresh token");
    assertForeignKey(
      this.db.tokenFamilies,
      record.familyId,
      "refreshToken.familyId",
    );
    for (const existing of this.db.refreshTokens.values()) {
      if (existing.tokenHash === record.tokenHash) {
        throw new RepositoryError(
          "duplicate_key",
          "Le condensat du refresh token existe déjà",
        );
      }
    }
    this.db.refreshTokens.set(record.id, clone(record));
  }

  /**
   * Atomique : JavaScript n'exécute qu'une seule tâche à la fois, et il n'y a
   * aucun `await` entre la lecture et l'écriture. Deux appels simultanés ne
   * peuvent donc pas consommer le même token.
   */
  async markConsumed(
    id: TokenId,
    consumedAt: Date,
    replacedByTokenId: TokenId,
  ): Promise<boolean> {
    const record = this.db.refreshTokens.get(id);
    if (!record || record.consumedAt !== null || record.revokedAt !== null) {
      return false;
    }
    this.db.refreshTokens.set(id, {
      ...record,
      consumedAt,
      replacedByTokenId,
    });
    return true;
  }
}

function assertAbsent<K, V>(map: Map<K, V>, key: K, entity: string): void {
  if (map.has(key)) {
    throw new RepositoryError(
      "duplicate_key",
      `${entity} déjà existant : ${String(key)}`,
    );
  }
}

function assertPresent<K, V>(map: Map<K, V>, key: K, entity: string): void {
  if (!map.has(key)) {
    throw new RepositoryError(
      "record_not_found",
      `${entity} introuvable : ${String(key)}`,
    );
  }
}

function assertForeignKey<K, V>(map: Map<K, V>, key: K, field: string): void {
  if (!map.has(key)) {
    throw new RepositoryError(
      "constraint_violation",
      `${field} référence une ligne inexistante : ${String(key)}`,
    );
  }
}
