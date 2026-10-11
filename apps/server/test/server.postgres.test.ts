import type { OtpMessage } from "@authen/provider-email-otp";
import { migratePostgres, createPostgresAdapter } from "@authen/adapter-postgres";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { test } from "node:test";
import pg from "pg";
import { buildServer } from "../src/server.js";

const url = process.env.AUTHEN_POSTGRES_TEST_URL;

test(
  "serveur Postgres : flux complet, code à usage unique, survie au redémarrage",
  { skip: url ? false : "AUTHEN_POSTGRES_TEST_URL absent" },
  async () => {
    if (!url) return;
    process.env.AUTHEN_SIGNING_SECRET = "x".repeat(48);

    const pool = new pg.Pool({ connectionString: url });
    await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
    await migratePostgres(createPostgresAdapter(pool).database);
    await pool.end();

    const messages: OtpMessage[] = [];
    const options = {
      issuer: "http://identity.test",
      databaseUrl: url,
      otpSender: {
        async send(message: OtpMessage) {
          messages.push(message);
        },
      },
    };

    // Deux instances qui démarrent en même temps : une seule clé active.
    const [a, b] = await Promise.all([buildServer(options), buildServer(options)]);
    const kidsAtStart = (await a.inject({ method: "GET", url: "/jwks.json" })).json().keys.map((k: { kid: string }) => k.kid);
    assert.equal(kidsAtStart.length, 1);
    await b.close();
    const first = a;
    let cookie: string;
    let accessToken: string;
    try {
      const started = await first.inject({
        method: "POST",
        url: "/auth/email/start",
        payload: { email: "ada@example.com" },
      });
      assert.equal(started.statusCode, 202);
      const verified = await first.inject({
        method: "POST",
        url: "/auth/email/verify",
        payload: {
          transactionId: started.json().transactionId,
          code: messages[0]!.code,
        },
      });
      assert.equal(verified.statusCode, 200);
      cookie = String(verified.headers["set-cookie"]).split(";")[0]!;

      const verifier = randomBytes(48).toString("base64url");
      const challenge = createHash("sha256")
        .update(verifier)
        .digest("base64url");
      const authorize = await first.inject({
        method: "GET",
        url: `/authorize?${new URLSearchParams({
          response_type: "code",
          client_id: "authen-web",
          redirect_uri: "http://localhost:3001/callback",
          scope: "openid profile",
          code_challenge: challenge,
          code_challenge_method: "S256",
        })}`,
        headers: { cookie },
      });
      assert.equal(authorize.statusCode, 302);
      const code = new URL(String(authorize.headers.location)).searchParams.get(
        "code",
      )!;

      const exchange = () =>
        first.inject({
          method: "POST",
          url: "/token",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          payload: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            code_verifier: verifier,
            client_id: "authen-web",
            redirect_uri: "http://localhost:3001/callback",
          }).toString(),
        });
      // Deux échanges simultanés du même code : un seul doit réussir.
      const results = await Promise.all([exchange(), exchange()]);
      assert.deepEqual(results.map((r) => r.statusCode).sort(), [200, 400]);
      accessToken = results.find((r) => r.statusCode === 200)!.json()
        .access_token;
    } finally {
      await first.close();
    }

    // Redémarrage : même base, même secret. Session et token restent valides.
    const second = await buildServer(options);
    try {
      const kidsAfter = (await second.inject({ method: "GET", url: "/jwks.json" })).json().keys.map((k: { kid: string }) => k.kid);
      assert.deepEqual(kidsAfter, kidsAtStart);

      const userinfo = await second.inject({
        method: "GET",
        url: "/userinfo",
        headers: { authorization: `Bearer ${accessToken}` },
      });
      assert.equal(userinfo.statusCode, 200);
      assert.ok(userinfo.json().sub);

      const authorize = await second.inject({
        method: "GET",
        url: `/authorize?${new URLSearchParams({
          response_type: "code",
          client_id: "authen-web",
          redirect_uri: "http://localhost:3001/callback",
          scope: "openid",
          code_challenge: "a".repeat(43),
          code_challenge_method: "S256",
        })}`,
        headers: { cookie },
      });
      assert.equal(authorize.statusCode, 302);
      assert.match(String(authorize.headers.location), /callback\?code=/);
    } finally {
      await second.close();
    }
  },
);

test("serveur : DATABASE_URL sans secret de signature est refusé", async () => {
  delete process.env.AUTHEN_SIGNING_SECRET;
  await assert.rejects(
    buildServer({ issuer: "http://identity.test", databaseUrl: "postgres://x" }),
    /AUTHEN_SIGNING_SECRET/,
  );
});
