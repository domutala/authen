import type { PostgresDatabase } from "@authen/adapter-postgres";
import { signingKeys } from "@authen/adapter-postgres";
import { eq, sql } from "drizzle-orm";
import type {
  SigningKeyRecord,
  SigningKeyStore,
  SigningKeyTransaction,
} from "./types.js";

/** Store en mémoire (développement) : transactions sérialisées. */
export class MemorySigningKeyStore implements SigningKeyStore {
  private readonly keys = new Map<string, SigningKeyRecord>();
  private tail: Promise<unknown> = Promise.resolve();

  transaction<T>(work: (tx: SigningKeyTransaction) => Promise<T>): Promise<T> {
    const tx: SigningKeyTransaction = {
      list: async () => [...this.keys.values()].map((r) => structuredClone(r)),
      insert: async (r) => void this.keys.set(r.kid, structuredClone(r)),
      update: async (r) => void this.keys.set(r.kid, structuredClone(r)),
      delete: async (kid) => void this.keys.delete(kid),
    };
    const run = this.tail.then(() => work(tx));
    this.tail = run.catch(() => undefined);
    return run;
  }
}

/** Store PostgreSQL : verrou consultatif par transaction (multi-instances). */
export class PostgresSigningKeyStore implements SigningKeyStore {
  constructor(private readonly db: PostgresDatabase) {}

  transaction<T>(work: (tx: SigningKeyTransaction) => Promise<T>): Promise<T> {
    return this.db.run(async () => {
      const executor = () => this.db.executor;
      await executor().execute(
        sql`SELECT pg_advisory_xact_lock(hashtext('authen_signing_keys'))`,
      );
      return work({
        async list() {
          const rows = await executor().select().from(signingKeys);
          return rows.map((row) => ({
            ...row,
            algorithm: "RS256" as const,
          }));
        },
        async insert(record) {
          await executor().insert(signingKeys).values(record);
        },
        async update(record) {
          await executor()
            .update(signingKeys)
            .set(record)
            .where(eq(signingKeys.kid, record.kid));
        },
        async delete(kid) {
          await executor().delete(signingKeys).where(eq(signingKeys.kid, kid));
        },
      });
    });
  }
}
