import type { Clock } from "@authen/core";
import type { Pool } from "pg";
import { PostgresChallengeStore } from "./challenge-store.js";
import { PostgresDatabase } from "./database.js";
import {
  PostgresCredentialRepository,
  PostgresIdentityRepository,
  PostgresProfileRepository,
  PostgresProviderInstanceRepository,
  PostgresRefreshTokenRepository,
  PostgresSessionRepository,
  PostgresTokenFamilyRepository,
  PostgresTransactionRepository,
  PostgresUserRepository,
} from "./repositories.js";

export interface PostgresAdapterOptions {
  /** Horloge utilisée pour l'expiration des challenges (réelle par défaut). */
  clock?: Clock;
}

/** Assemble tous les repositories sur un même contexte transactionnel Drizzle. */
export function createPostgresAdapter(
  pool: Pool,
  options: PostgresAdapterOptions = {},
) {
  const clock = options.clock ?? { now: () => new Date() };
  const database = new PostgresDatabase(pool);
  const repositories = {
    users: new PostgresUserRepository(database),
    identities: new PostgresIdentityRepository(database),
    profiles: new PostgresProfileRepository(database),
    credentials: new PostgresCredentialRepository(database),
    sessions: new PostgresSessionRepository(database),
    transactions: new PostgresTransactionRepository(database),
    providerInstances: new PostgresProviderInstanceRepository(database),
    tokenFamilies: new PostgresTokenFamilyRepository(database),
    refreshTokens: new PostgresRefreshTokenRepository(database),
  };

  const challenges = new PostgresChallengeStore(database, clock);

  return { database, unitOfWork: database, repositories, challenges };
}

export type PostgresAdapter = ReturnType<typeof createPostgresAdapter>;
