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
import { AuthenticationError } from "@authen/core";
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
    this.db.users.set(user.id, clone(user));
  }

  async update(user: User): Promise<void> {
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
    this.db.identities.set(identity.id, clone(identity));
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
    this.db.profiles.set(profile.userId, clone(profile));
  }

  async update(profile: UserProfile): Promise<void> {
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
    this.db.credentials.set(credential.id, clone(credential));
  }

  async update(credential: Credential): Promise<void> {
    this.db.credentials.set(credential.id, clone(credential));
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
    this.db.sessions.set(session.id, clone(session));
  }

  async update(session: Session): Promise<void> {
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
    this.db.transactions.set(transaction.id, clone(transaction));
  }

  // Pas de verrou optimiste ici : l'adaptateur mémoire ne simule pas la
  // concurrence entre deux `continue()` simultanés sur la même transaction.
  async update(transaction: AuthenticationTransaction): Promise<void> {
    this.db.transactions.set(transaction.id, clone(transaction));
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
    this.db.tokenFamilies.set(family.id, clone(family));
  }

  async update(family: TokenFamily): Promise<void> {
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
