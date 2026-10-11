import type { Pool } from "pg";
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

/** Assemble tous les repositories sur un même contexte transactionnel TypeORM. */
export function createPostgresAdapter(pool: Pool) {
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

  return { database, unitOfWork: database, repositories };
}

export type PostgresAdapter = ReturnType<typeof createPostgresAdapter>;
