import {
  AuthenticationError,
  type Identity,
  type IdentityId,
  type ProviderInstance,
  type ProviderInstanceId,
  type RefreshTokenRecord,
  type Session,
  type SessionId,
  type TokenFamily,
  type TokenFamilyId,
  type TokenId,
  type User,
  type UserId,
} from "@authen/core";
import assert from "node:assert/strict";
import { test } from "node:test";
import pg from "pg";
import { createPostgresAdapter, migratePostgres } from "../src/index.js";

const url = process.env.AUTHEN_POSTGRES_TEST_URL;

test(
  "PostgreSQL : unicité et consommation atomique",
  { skip: url ? false : "AUTHEN_POSTGRES_TEST_URL absent" },
  async () => {
    if (!url) return;
    const pool = new pg.Pool({ connectionString: url });
    try {
      await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
      const adapter = createPostgresAdapter(pool);
      await migratePostgres(adapter.database);
      const { repositories } = adapter;
      const now = new Date("2026-01-01T00:00:00Z");
      const user: User = {
        id: "user-1" as UserId,
        status: "active",
        lastAuthenticatedAt: now,
        disabledAt: null,
        createdAt: now,
        updatedAt: now,
      };
      const provider: ProviderInstance = {
        id: "email-main" as ProviderInstanceId,
        type: "email-otp",
        enabled: true,
        configurationRef: "test",
        metadata: {},
        createdAt: now,
        updatedAt: now,
      };
      await repositories.users.create(user);
      await repositories.providerInstances.create(provider);

      const identity: Identity = {
        id: "identity-1" as IdentityId,
        userId: user.id,
        providerInstanceId: provider.id,
        providerSubject: "user@example.com",
        status: "active",
        verifiedAt: now,
        lastUsedAt: null,
        metadata: {},
        createdAt: now,
        updatedAt: now,
      };
      await repositories.identities.create(identity);
      await assert.rejects(
        repositories.identities.create({
          ...identity,
          id: "identity-2" as IdentityId,
        }),
        (error: unknown) =>
          error instanceof AuthenticationError &&
          error.code === "identity_conflict",
      );

      const session: Session = {
        id: "session-1" as SessionId,
        userId: user.id,
        status: "active",
        context: {
          providerInstanceId: provider.id,
          methods: ["email_otp"],
          assuranceLevel: "standard",
          authenticatedAt: now,
          verifiedAt: now,
        },
        device: {
          deviceId: null,
          name: null,
          userAgent: null,
          ipAddress: null,
        },
        authenticatedAt: now,
        lastActivityAt: now,
        expiresAt: new Date("2026-01-02T00:00:00Z"),
        absoluteExpiresAt: new Date("2026-02-01T00:00:00Z"),
        revokedAt: null,
        revocationReason: null,
        createdAt: now,
        updatedAt: now,
      };
      await repositories.sessions.create(session);
      const family: TokenFamily = {
        id: "family-1" as TokenFamilyId,
        sessionId: session.id,
        clientId: "client-1" as TokenFamily["clientId"],
        scopes: ["openid"],
        createdAt: now,
        expiresAt: session.absoluteExpiresAt,
        revokedAt: null,
        revocationReason: null,
      };
      await repositories.tokenFamilies.create(family);
      const token = (id: string, hash: string): RefreshTokenRecord => ({
        id: id as TokenId,
        familyId: family.id,
        tokenHash: hash,
        issuedAt: now,
        expiresAt: family.expiresAt,
        consumedAt: null,
        revokedAt: null,
        replacedByTokenId: null,
      });
      const current = token("token-1", "hash-1");
      const replacement = token("token-2", "hash-2");
      await repositories.refreshTokens.create(current);
      await repositories.refreshTokens.create(replacement);

      const results = await Promise.all([
        repositories.refreshTokens.markConsumed(
          current.id,
          now,
          replacement.id,
        ),
        repositories.refreshTokens.markConsumed(
          current.id,
          now,
          replacement.id,
        ),
      ]);
      assert.deepEqual(results.sort(), [false, true]);
    } finally {
      await pool.end();
    }
  },
);

test(
  "PostgreSQL : challenge à usage unique et expiration",
  { skip: url ? false : "AUTHEN_POSTGRES_TEST_URL absent" },
  async () => {
    if (!url) return;
    const pool = new pg.Pool({ connectionString: url });
    try {
      await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
      let now = new Date("2026-01-01T00:00:00Z");
      const adapter = createPostgresAdapter(pool, {
        clock: { now: () => now },
      });
      await migratePostgres(adapter.database);
      await migratePostgres(adapter.database); // idempotent

      const { challenges } = adapter;
      await challenges.save("k", "v", new Date("2026-01-01T00:10:00Z"));
      const results = await Promise.all([
        challenges.consume("k"),
        challenges.consume("k"),
      ]);
      assert.deepEqual(results.sort(), [null, "v"]);

      await challenges.save("old", "v", new Date("2026-01-01T00:10:00Z"));
      now = new Date("2026-01-01T00:11:00Z");
      assert.equal(await challenges.consume("old"), null);
    } finally {
      await pool.end();
    }
  },
);
