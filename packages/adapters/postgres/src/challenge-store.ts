import type { ChallengeStore, Clock } from "@authen/core";
import { eq, lte } from "drizzle-orm";
import type { PostgresDatabase } from "./database.js";
import { challenges } from "./schema.js";

/** Challenges à usage unique (OTP, state, nonce...) stockés en table. */
export class PostgresChallengeStore implements ChallengeStore {
  constructor(
    private readonly db: PostgresDatabase,
    private readonly clock: Clock,
  ) {}

  async save(key: string, value: string, expiresAt: Date): Promise<void> {
    await this.db.executor.delete(challenges).where(
      lte(challenges.expiresAt, this.clock.now()),
    );
    await this.db.executor
      .insert(challenges)
      .values({ key, value, expiresAt })
      .onConflictDoUpdate({ target: challenges.key, set: { value, expiresAt } });
  }

  /** `DELETE ... RETURNING` : lecture et suppression atomiques, un seul gagnant. */
  async consume(key: string): Promise<string | null> {
    const rows = await this.db.executor
      .delete(challenges)
      .where(eq(challenges.key, key))
      .returning();
    const row = rows[0];
    if (!row) return null;
    return row.expiresAt > this.clock.now() ? row.value : null;
  }
}

