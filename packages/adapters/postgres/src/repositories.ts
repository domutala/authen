import {
  type AuthenticationContext,
  type AuthenticationTransaction,
  type Credential,
  type CredentialId,
  type CredentialRepository,
  type Identity,
  type IdentityId,
  type IdentityRepository,
  type ProfileRepository,
  type ProviderInstance,
  type ProviderInstanceId,
  type ProviderInstanceRepository,
  RepositoryError,
  type RefreshTokenRecord,
  type RefreshTokenRepository,
  type Session,
  type SessionId,
  type SessionRepository,
  type TokenFamily,
  type TokenFamilyId,
  type TokenFamilyRepository,
  type TokenId,
  type TransactionId,
  type TransactionRepository,
  type User,
  type UserId,
  type UserProfile,
  type UserRepository,
} from "@authen/core";
import { and, eq, isNull } from "drizzle-orm";
import type { PostgresDatabase } from "./database.js";
import { translateDatabaseError } from "./errors.js";
import {
  authenticationTransactions,
  credentials,
  identities,
  profiles,
  providerInstances,
  refreshTokens,
  sessions,
  tokenFamilies,
  users,
} from "./schema.js";

abstract class Base {
  constructor(protected readonly db: PostgresDatabase) {}
  protected async write<T>(
    work: () => Promise<T>,
    identity = false,
  ): Promise<T> {
    try {
      return await work();
    } catch (error) {
      translateDatabaseError(error, { identityConflict: identity });
    }
  }
  protected assertUpdated(rows: unknown[]) {
    if (rows.length === 0) throw new RepositoryError("record_not_found");
  }
}

export class PostgresUserRepository extends Base implements UserRepository {
  async findById(id: UserId) {
    return as<User>(
      (
        await this.db.executor
          .select()
          .from(users)
          .where(eq(users.id, id))
          .limit(1)
      )[0],
    );
  }
  async create(value: User) {
    await this.write(() => this.db.executor.insert(users).values(value));
  }
  async update(value: User) {
    const rows = await this.write(() =>
      this.db.executor
        .update(users)
        .set(value)
        .where(eq(users.id, value.id))
        .returning({ id: users.id }),
    );
    this.assertUpdated(rows);
  }
}

export class PostgresIdentityRepository
  extends Base
  implements IdentityRepository
{
  async findById(id: IdentityId) {
    return as<Identity>(
      (
        await this.db.executor
          .select()
          .from(identities)
          .where(eq(identities.id, id))
          .limit(1)
      )[0],
    );
  }
  async findByProviderSubject(instanceId: ProviderInstanceId, subject: string) {
    return as<Identity>(
      (
        await this.db.executor
          .select()
          .from(identities)
          .where(
            and(
              eq(identities.providerInstanceId, instanceId),
              eq(identities.providerSubject, subject),
            ),
          )
          .limit(1)
      )[0],
    );
  }
  async findByUserId(userId: UserId) {
    return (await this.db.executor
      .select()
      .from(identities)
      .where(eq(identities.userId, userId))) as Identity[];
  }
  async create(value: Identity) {
    await this.write(
      () => this.db.executor.insert(identities).values(value),
      true,
    );
  }
  async update(value: Identity) {
    const rows = await this.write(
      () =>
        this.db.executor
          .update(identities)
          .set(value)
          .where(eq(identities.id, value.id))
          .returning({ id: identities.id }),
      true,
    );
    this.assertUpdated(rows);
  }
}

export class PostgresProfileRepository
  extends Base
  implements ProfileRepository
{
  async findByUserId(userId: UserId) {
    return as<UserProfile>(
      (
        await this.db.executor
          .select()
          .from(profiles)
          .where(eq(profiles.userId, userId))
          .limit(1)
      )[0],
    );
  }
  async create(value: UserProfile) {
    await this.write(() => this.db.executor.insert(profiles).values(value));
  }
  async update(value: UserProfile) {
    const rows = await this.write(() =>
      this.db.executor
        .update(profiles)
        .set(value)
        .where(eq(profiles.userId, value.userId))
        .returning({ id: profiles.userId }),
    );
    this.assertUpdated(rows);
  }
}

export class PostgresCredentialRepository
  extends Base
  implements CredentialRepository
{
  async findById(id: CredentialId) {
    return as<Credential>(
      (
        await this.db.executor
          .select()
          .from(credentials)
          .where(eq(credentials.id, id))
          .limit(1)
      )[0],
    );
  }
  async findByUserId(userId: UserId) {
    return (await this.db.executor
      .select()
      .from(credentials)
      .where(eq(credentials.userId, userId))) as Credential[];
  }
  async create(value: Credential) {
    await this.write(() => this.db.executor.insert(credentials).values(value));
  }
  async update(value: Credential) {
    const rows = await this.write(() =>
      this.db.executor
        .update(credentials)
        .set(value)
        .where(eq(credentials.id, value.id))
        .returning({ id: credentials.id }),
    );
    this.assertUpdated(rows);
  }
}

export class PostgresSessionRepository
  extends Base
  implements SessionRepository
{
  async findById(id: SessionId) {
    return mapSession(
      (
        await this.db.executor
          .select()
          .from(sessions)
          .where(eq(sessions.id, id))
          .limit(1)
      )[0],
    );
  }
  async findByUserId(userId: UserId) {
    return (
      await this.db.executor
        .select()
        .from(sessions)
        .where(eq(sessions.userId, userId))
    ).map(mapSessionRequired);
  }
  async create(value: Session) {
    await this.write(() => this.db.executor.insert(sessions).values(value));
  }
  async update(value: Session) {
    const rows = await this.write(() =>
      this.db.executor
        .update(sessions)
        .set(value)
        .where(eq(sessions.id, value.id))
        .returning({ id: sessions.id }),
    );
    this.assertUpdated(rows);
  }
}

export class PostgresTransactionRepository
  extends Base
  implements TransactionRepository
{
  async findById(id: TransactionId) {
    return as<AuthenticationTransaction>(
      (
        await this.db.executor
          .select()
          .from(authenticationTransactions)
          .where(eq(authenticationTransactions.id, id))
          .limit(1)
      )[0],
    );
  }
  async create(value: AuthenticationTransaction) {
    await this.write(() =>
      this.db.executor.insert(authenticationTransactions).values(value),
    );
  }
  async update(value: AuthenticationTransaction) {
    const rows = await this.write(() =>
      this.db.executor
        .update(authenticationTransactions)
        .set(value)
        .where(eq(authenticationTransactions.id, value.id))
        .returning({ id: authenticationTransactions.id }),
    );
    this.assertUpdated(rows);
  }
}

export class PostgresProviderInstanceRepository
  extends Base
  implements ProviderInstanceRepository
{
  async findById(id: ProviderInstanceId) {
    return as<ProviderInstance>(
      (
        await this.db.executor
          .select()
          .from(providerInstances)
          .where(eq(providerInstances.id, id))
          .limit(1)
      )[0],
    );
  }
  async create(value: ProviderInstance) {
    await this.write(() =>
      this.db.executor.insert(providerInstances).values(value),
    );
  }
  async update(value: ProviderInstance) {
    const rows = await this.write(() =>
      this.db.executor
        .update(providerInstances)
        .set(value)
        .where(eq(providerInstances.id, value.id))
        .returning({ id: providerInstances.id }),
    );
    this.assertUpdated(rows);
  }
}

export class PostgresTokenFamilyRepository
  extends Base
  implements TokenFamilyRepository
{
  async findById(id: TokenFamilyId) {
    return as<TokenFamily>(
      (
        await this.db.executor
          .select()
          .from(tokenFamilies)
          .where(eq(tokenFamilies.id, id))
          .limit(1)
      )[0],
    );
  }
  async findBySessionId(sessionId: SessionId) {
    return (await this.db.executor
      .select()
      .from(tokenFamilies)
      .where(eq(tokenFamilies.sessionId, sessionId))) as TokenFamily[];
  }
  async create(value: TokenFamily) {
    await this.write(() =>
      this.db.executor.insert(tokenFamilies).values(value),
    );
  }
  async update(value: TokenFamily) {
    const rows = await this.write(() =>
      this.db.executor
        .update(tokenFamilies)
        .set(value)
        .where(eq(tokenFamilies.id, value.id))
        .returning({ id: tokenFamilies.id }),
    );
    this.assertUpdated(rows);
  }
}

export class PostgresRefreshTokenRepository
  extends Base
  implements RefreshTokenRepository
{
  async findByHash(tokenHash: string) {
    return as<RefreshTokenRecord>(
      (
        await this.db.executor
          .select()
          .from(refreshTokens)
          .where(eq(refreshTokens.tokenHash, tokenHash))
          .limit(1)
      )[0],
    );
  }
  async create(value: RefreshTokenRecord) {
    await this.write(() =>
      this.db.executor.insert(refreshTokens).values(value),
    );
  }
  async markConsumed(
    id: TokenId,
    consumedAt: Date,
    replacedByTokenId: TokenId,
  ) {
    const rows = await this.write(() =>
      this.db.executor
        .update(refreshTokens)
        .set({ consumedAt, replacedByTokenId })
        .where(
          and(
            eq(refreshTokens.id, id),
            isNull(refreshTokens.consumedAt),
            isNull(refreshTokens.revokedAt),
          ),
        )
        .returning({ id: refreshTokens.id }),
    );
    return rows.length === 1;
  }
}

function as<T>(value: unknown): T | null {
  return value ? (value as T) : null;
}

type SessionRow = typeof sessions.$inferSelect;
function mapSession(value: SessionRow | undefined): Session | null {
  return value ? mapSessionRequired(value) : null;
}
function mapSessionRequired(value: SessionRow): Session {
  const context = value.context as unknown as Record<string, unknown>;
  return {
    ...value,
    id: value.id as SessionId,
    userId: value.userId as UserId,
    context: {
      ...context,
      providerInstanceId: context.providerInstanceId as ProviderInstanceId,
      methods: context.methods as string[],
      assuranceLevel: context.assuranceLevel as string,
      authenticatedAt: date(context.authenticatedAt),
      verifiedAt: date(context.verifiedAt),
    } as AuthenticationContext,
  };
}
function date(value: unknown): Date {
  return value instanceof Date ? value : new Date(value as string);
}
