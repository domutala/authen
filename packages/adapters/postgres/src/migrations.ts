import { sql } from "drizzle-orm";
import { readFile } from "node:fs/promises";
import type { PostgresDatabase } from "./database.js";

/** Migrations SQL, appliquées dans l'ordre. Ne jamais modifier une migration déjà livrée. */
const MIGRATIONS = [
  "001_initial",
  "002_server_stores",
  "003_signing_keys",
] as const;

/** Applique les migrations manquantes ; chacune dans sa propre transaction. */
export async function migratePostgres(
  database: PostgresDatabase,
): Promise<void> {
  await database.run(async () => {
    await database.executor.execute(sql`
      CREATE TABLE IF NOT EXISTS authen_migrations (
        id text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);
  });

  for (const migrationId of MIGRATIONS) {
    const migration = await readFile(
      new URL(`../migrations/${migrationId}.sql`, import.meta.url),
      "utf8",
    );
    await database.run(async () => {
      // Verrou consultatif : deux instances qui démarrent ensemble migrent à tour de rôle.
      await database.executor.execute(
        sql`SELECT pg_advisory_xact_lock(hashtext('authen_migrations'))`,
      );
      const applied = await database.executor.execute<{ id: string }>(sql`
        SELECT id FROM authen_migrations WHERE id = ${migrationId}
      `);
      if (applied.rows.length > 0) return;

      await database.executor.execute(sql.raw(migration));
      await database.executor.execute(sql`
        INSERT INTO authen_migrations (id) VALUES (${migrationId})
      `);
    });
  }
}
