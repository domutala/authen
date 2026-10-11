import type { OtpMessage } from "@authen/provider-email-otp";
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildServer } from "../src/server.js";

test("serveur Fastify : santé, discovery et session email OTP", async () => {
  const messages: OtpMessage[] = [];
  const app = await buildServer({
    issuer: "http://identity.test",
    databaseUrl: null,
    secureCookies: false,
    otpSender: {
      async send(message) {
        messages.push(message);
      },
    },
  });
  try {
    const health = await app.inject({ method: "GET", url: "/health" });
    assert.equal(health.statusCode, 200);
    assert.deepEqual(health.json(), { status: "ok" });

    const discovery = await app.inject({
      method: "GET",
      url: "/.well-known/openid-configuration",
    });
    assert.equal(discovery.statusCode, 200);
    assert.equal(discovery.json().issuer, "http://identity.test");

    const started = await app.inject({
      method: "POST",
      url: "/auth/email/start",
      payload: { email: "ada@example.com" },
    });
    assert.equal(started.statusCode, 202);
    const transactionId = started.json().transactionId as string;
    assert.equal(messages.length, 1);

    const verified = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { transactionId, code: messages[0]!.code },
    });
    assert.equal(verified.statusCode, 200);
    const cookie = verified.headers["set-cookie"];
    assert.match(String(cookie), /authen_session=/);

    const verifier = "a".repeat(43);
    const { createHash } = await import("node:crypto");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorize = await app.inject({
      method: "GET",
      url: `/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "authen-web",
        redirect_uri: "http://localhost:3001/callback",
        scope: "openid profile",
        code_challenge: challenge,
        code_challenge_method: "S256",
      })}`,
      headers: { cookie: String(cookie).split(";")[0]! },
    });
    assert.equal(authorize.statusCode, 302);
    assert.match(
      String(authorize.headers.location),
      /^http:\/\/localhost:3001\/callback\?code=/,
    );
  } finally {
    await app.close();
  }
});
