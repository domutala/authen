import type { TransactionRunner } from "@authen/core";
import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { AsyncLocalStorage } from "node:async_hooks";
import type { Pool } from "pg";
import * as tables from "./schema.js";

export type AuthenDatabase = NodePgDatabase<typeof tables>;

/** Client Drizzle partagé et contexte transactionnel des repositories. */
export class PostgresDatabase implements TransactionRunner {
  private readonly transactions = new AsyncLocalStorage<AuthenDatabase>();
  readonly client: AuthenDatabase;

  constructor(readonly pool: Pool) {
    this.client = drizzle(pool, { schema: tables });
  }

  get executor(): AuthenDatabase {
    return this.transactions.getStore() ?? this.client;
  }

  async run<T>(work: () => Promise<T>): Promise<T> {
    if (this.transactions.getStore()) return work();

    return this.client.transaction(
      (transaction) =>
        this.transactions.run(transaction as unknown as AuthenDatabase, work),
      { isolationLevel: "read committed" },
    );
  }
}
