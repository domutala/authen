import { AuthenticationError, RepositoryError } from "@authen/core";

interface PostgresDriverError {
  code?: string;
  constraint?: string;
  detail?: string;
}

export function translateDatabaseError(
  error: unknown,
  options: { identityConflict?: boolean } = {},
): never {
  const driver = findPostgresError(error);
  if (!driver) throw error;
  if (driver.code === "23505") {
    if (
      options.identityConflict &&
      driver.constraint === "authen_identities_provider_subject_key"
    ) {
      throw new AuthenticationError("identity_conflict", driver.detail, {
        cause: error,
      });
    }
    throw new RepositoryError("duplicate_key", driver.detail);
  }
  if (driver.code === "23503" || driver.code === "23514") {
    throw new RepositoryError("constraint_violation", driver.detail);
  }
  throw error;
}

function findPostgresError(error: unknown): PostgresDriverError | null {
  let current = error;
  for (let depth = 0; depth < 4; depth++) {
    if (typeof current !== "object" || current === null) return null;
    const candidate = current as PostgresDriverError & { cause?: unknown };
    if (typeof candidate.code === "string") return candidate;
    current = candidate.cause;
  }
  return null;
}

export function assertUpdated(affected: number | null | undefined): void {
  if (affected === 0) throw new RepositoryError("record_not_found");
}
