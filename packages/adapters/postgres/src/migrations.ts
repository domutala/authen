import { sql } from "drizzle-orm";
import { readFile } from "node:fs/promises";
import type { PostgresDatabase } from "./database.js";

/** Applique la migration initiale SQL via le client Drizzle. */
export async function migratePostgres(
  database: PostgresDatabase,
): Promise<void> {
  const migrationId = "001_initial";
  const migration = await readFile(
    new URL("../migrations/001_initial.sql", import.meta.url),
    "utf8",
  );
  await database.run(async () => {
    await database.executor.execute(sql`
      CREATE TABLE IF NOT EXISTS authen_migrations (
        id text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);
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
