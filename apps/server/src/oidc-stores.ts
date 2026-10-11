import type { ClientId, Clock } from "@authen/core";
import {
  authorizationCodes,
  oauthClients,
  type PostgresDatabase,
} from "@authen/adapter-postgres";
import type {
  AuthorizationCodeRecord,
  AuthorizationCodeStore,
  OAuthClient,
  OAuthClientRegistry,
} from "@authen/protocol-oauth-oidc";
import { and, eq, gt, lte } from "drizzle-orm";

export class PostgresOAuthClientRegistry implements OAuthClientRegistry {
  constructor(
    private readonly db: PostgresDatabase,
    private readonly clock: Clock,
  ) {}

  async findById(id: ClientId): Promise<OAuthClient | null> {
    const row = (
      await this.db.executor
        .select()
        .from(oauthClients)
        .where(eq(oauthClients.id, id))
        .limit(1)
    )[0];
    return row
      ? {
          id: row.id as ClientId,
          redirectUris: row.redirectUris,
          allowedScopes: row.allowedScopes,
        }
      : null;
  }

  /** Crée ou met à jour un client (utilisé pour le client déclaré dans l'env). */
  async upsert(client: OAuthClient): Promise<void> {
    const now = this.clock.now();
    await this.db.executor
      .insert(oauthClients)
      .values({
        id: client.id,
        redirectUris: client.redirectUris,
        allowedScopes: client.allowedScopes,
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: oauthClients.id,
        set: {
          redirectUris: client.redirectUris,
          allowedScopes: client.allowedScopes,
          updatedAt: now,
        },
      });
  }
}

export class PostgresAuthorizationCodeStore implements AuthorizationCodeStore {
  constructor(
    private readonly db: PostgresDatabase,
    private readonly clock: Clock,
  ) {}

  async save(record: AuthorizationCodeRecord): Promise<void> {
    await this.db.executor
      .delete(authorizationCodes)
      .where(lte(authorizationCodes.expiresAt, this.clock.now()));
    await this.db.executor.insert(authorizationCodes).values(record);
  }

  /**
   * Un seul `DELETE ... RETURNING` conditionnel : vérification et consommation
   * atomiques. Deux échanges simultanés du même code : un seul reçoit la ligne.
   */
  async redeem(input: {
    codeHash: string;
    clientId: ClientId;
    redirectUri: string;
    codeChallenge: string;
  }): Promise<AuthorizationCodeRecord | null> {
    const rows = await this.db.executor
      .delete(authorizationCodes)
      .where(
        and(
          eq(authorizationCodes.codeHash, input.codeHash),
          eq(authorizationCodes.clientId, input.clientId),
          eq(authorizationCodes.redirectUri, input.redirectUri),
          eq(authorizationCodes.codeChallenge, input.codeChallenge),
          gt(authorizationCodes.expiresAt, this.clock.now()),
        ),
      )
      .returning();
    const row = rows[0];
    if (!row) return null;
    return {
      ...row,
      clientId: row.clientId as ClientId,
      userId: row.userId as AuthorizationCodeRecord["userId"],
      sessionId: row.sessionId as AuthorizationCodeRecord["sessionId"],
    };
  }
}
