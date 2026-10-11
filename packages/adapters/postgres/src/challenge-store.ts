import type { ChallengeStore, Clock } from "@authen/core";
import { eq, lte, sql } from "drizzle-orm";
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
    const result = await this.consumeIf(key, () => true);
    return result?.consumed ? result.value : null;
  }

  async consumeIf(
    key: string,
    predicate: (value: string) => boolean,
  ): Promise<{ value: string; consumed: boolean } | null> {
    return this.db.run(async () => {
      const result = await this.db.executor.execute<{
        value: string;
        expires_at: Date;
      }>(sql`
        SELECT value, expires_at
        FROM authen_challenges
        WHERE key = ${key}
        FOR UPDATE
      `);
      const row = result.rows[0];
      if (!row) return null;
      if (new Date(row.expires_at) <= this.clock.now()) {
        await this.db.executor.delete(challenges).where(eq(challenges.key, key));
        return null;
      }
      const consumed = predicate(row.value);
      if (consumed) {
        await this.db.executor.delete(challenges).where(eq(challenges.key, key));
      }
      return { value: row.value, consumed };
    });
  }
}
