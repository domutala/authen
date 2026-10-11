import type { ClientId, ProviderInstanceId, Session } from "@authen/core";
import { createMemoryCore, ManualClock } from "@authen/adapter-memory";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  MemoryAuthorizationCodeStore,
  MemoryOAuthClientRegistry,
  OidcTransport,
  type OidcIdTokenSigner,
} from "../src/index.js";

test("OIDC : authorization code + PKCE, échange unique et userinfo", async () => {
  const clock = new ManualClock(new Date("2026-01-01T00:00:00Z"));
  const core = createMemoryCore({
    clock,
    issuer: "https://identity.example.com",
    audience: "api",
  });
  const user = await core.services.users.create();
  await core.services.profiles.createFromClaims(user.id, { name: "Ada" });
  const session = await core.services.sessions.create({
    userId: user.id,
    context: {
      providerInstanceId: "email-main" as ProviderInstanceId,
      methods: ["email_otp"],
      assuranceLevel: "standard",
      authenticatedAt: clock.now(),
      verifiedAt: clock.now(),
    },
  });

  const clientId = "web-app" as ClientId;
  const clients = new MemoryOAuthClientRegistry();
  clients.register({
    id: clientId,
    redirectUris: ["https://app.example.com/callback"],
    allowedScopes: ["openid", "profile"],
  });
  const signer: OidcIdTokenSigner = {
    algorithm: "RS256",
    async sign(claims) {
      return `id.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`;
    },
    async jwks() {
      return { keys: [{ kty: "RSA", kid: "test" }] };
    },
  };
  const transport = new OidcTransport({
    clients,
    codes: new MemoryAuthorizationCodeStore(clock),
    authentication: {
      async resolve(): Promise<Session> {
        return session;
      },
      async required(): Promise<Response> {
        return Response.json({ login: true }, { status: 401 });
      },
    },
    sessions: core.services.sessions,
    tokens: core.services.tokens,
    profiles: core.services.profiles,
    idTokens: signer,
    random: core.random,
    digester: core.digester,
    clock,
    options: { issuer: "https://identity.example.com" },
  });

  const verifier = "a".repeat(43);
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const authorize = new URL("https://identity.example.com/authorize");
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: "https://app.example.com/callback",
    scope: "openid profile",
    state: "state-1",
    nonce: "nonce-1",
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();
  const authorization = await transport.handle(new Request(authorize));
  assert.equal(authorization.status, 302);
  const callback = new URL(authorization.headers.get("location")!);
  assert.equal(callback.searchParams.get("state"), "state-1");
  const code = callback.searchParams.get("code");
  assert.ok(code);

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    redirect_uri: "https://app.example.com/callback",
    code_verifier: verifier,
  });
  const wrongVerifier = new URLSearchParams(body);
  wrongVerifier.set("code_verifier", "b".repeat(43));
  const rejected = await transport.handle(
    new Request("https://identity.example.com/token", {
      method: "POST",
      body: wrongVerifier,
    }),
  );
  assert.equal(rejected.status, 400);

  const exchange = await transport.handle(
    new Request("https://identity.example.com/token", { method: "POST", body }),
  );
  assert.equal(exchange.status, 200);
  const token = (await exchange.json()) as Record<string, unknown>;
  assert.equal(token.token_type, "Bearer");
  assert.equal(typeof token.id_token, "string");

  const replay = await transport.handle(
    new Request("https://identity.example.com/token", {
      method: "POST",
      body: new URLSearchParams(body),
    }),
  );
  assert.equal(replay.status, 400);
  assert.deepEqual(await replay.json(), { error: "invalid_grant" });

  const userinfo = await transport.handle(
    new Request("https://identity.example.com/userinfo", {
      headers: { authorization: `Bearer ${String(token.access_token)}` },
    }),
  );
  assert.equal(userinfo.status, 200);
  assert.deepEqual(await userinfo.json(), {
    sub: user.id,
    name: "Ada",
    given_name: null,
    family_name: null,
    picture: null,
    locale: null,
  });
});

test("OIDC : une redirect URI non enregistrée est refusée sans redirection", async () => {
  const clock = new ManualClock();
  const core = createMemoryCore({ clock });
  const clients = new MemoryOAuthClientRegistry();
  clients.register({
    id: "app" as ClientId,
    redirectUris: ["https://safe.example/cb"],
    allowedScopes: ["openid"],
  });
  const transport = new OidcTransport({
    clients,
    codes: new MemoryAuthorizationCodeStore(clock),
    authentication: {
      async resolve() {
        return null;
      },
      async required() {
        return new Response(null, { status: 401 });
      },
    },
    sessions: core.services.sessions,
    tokens: core.services.tokens,
    profiles: core.services.profiles,
    idTokens: {
      algorithm: "RS256",
      async sign() {
        return "id";
      },
      async jwks() {
        return { keys: [] };
      },
    },
    random: core.random,
    digester: core.digester,
    clock,
    options: { issuer: "https://identity.example.com" },
  });
  const response = await transport.handle(
    new Request(
      "https://identity.example.com/authorize?client_id=app&redirect_uri=https%3A%2F%2Fevil.example%2Fcb",
    ),
  );
  assert.equal(response.status, 400);
  assert.equal(response.headers.get("location"), null);
});
