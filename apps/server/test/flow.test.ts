import type { OtpMessage } from "@authen/provider-email-otp";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { test } from "node:test";
import { RateLimiter } from "../src/rate-limiter.js";
import { safeReturnTo } from "../src/return-to.js";
import { buildServer } from "../src/server.js";

const ISSUER = "http://identity.test";
const REDIRECT = "http://localhost:3001/callback";

async function start(rateLimits = {}) {
  const messages: OtpMessage[] = [];
  const app = await buildServer({
    issuer: ISSUER,
    databaseUrl: null,
    rateLimits,
    otpSender: {
      async send(message) {
        messages.push(message);
      },
    },
  });
  return { app, messages };
}

type App = Awaited<ReturnType<typeof start>>["app"];

async function login(app: App, messages: OtpMessage[], returnTo?: string) {
  const started = await app.inject({
    method: "POST",
    url: "/auth/email/start",
    payload: { email: `u${messages.length}@example.com` },
  });
  assert.equal(started.statusCode, 202);
  const verified = await app.inject({
    method: "POST",
    url: "/auth/email/verify",
    payload: {
      transactionId: started.json().transactionId,
      code: messages.at(-1)!.code,
      ...(returnTo ? { return_to: returnTo } : {}),
    },
  });
  assert.equal(verified.statusCode, 200);
  return {
    cookie: String(verified.headers["set-cookie"]).split(";")[0]!,
    body: verified.json() as { returnTo: string | null },
  };
}

function pkcePair() {
  const verifier = randomBytes(48).toString("base64url");
  return {
    verifier,
    challenge: createHash("sha256").update(verifier).digest("base64url"),
  };
}

const authorizeUrl = (challenge: string, scope = "openid profile") =>
  `/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: "authen-web",
    redirect_uri: REDIRECT,
    scope,
    code_challenge: challenge,
    code_challenge_method: "S256",
  })}`;

test("Login : /authorize redirige vers /login, la connexion reprend le flux", async () => {
  const { app, messages } = await start();
  try {
    const { challenge } = pkcePair();
    const anonymous = await app.inject({ method: "GET", url: authorizeUrl(challenge) });
    assert.equal(anonymous.statusCode, 302);
    const loginUrl = new URL(String(anonymous.headers.location));
    assert.equal(loginUrl.pathname, "/login");
    const returnTo = loginUrl.searchParams.get("return_to")!;
    assert.match(returnTo, /^\/authorize\?/);

    const page = await app.inject({ method: "GET", url: `/login?return_to=${encodeURIComponent(returnTo)}` });
    assert.equal(page.json().returnTo, returnTo);

    const { cookie, body } = await login(app, messages, returnTo);
    assert.equal(body.returnTo, returnTo);

    const resumed = await app.inject({ method: "GET", url: body.returnTo!, headers: { cookie } });
    assert.equal(resumed.statusCode, 302);
    assert.match(String(resumed.headers.location), /callback\?code=/);
  } finally {
    await app.close();
  }
});

test("Login : un return_to externe est ignoré (pas d'open redirect)", async () => {
  const { app, messages } = await start();
  try {
    const { body } = await login(app, messages, "https://evil.example/authorize?x=1");
    assert.equal(body.returnTo, null);
  } finally {
    await app.close();
  }
});

test("safeReturnTo : n'accepte que /authorize de ce serveur", () => {
  const ok = (v: string) => safeReturnTo(v, ISSUER);
  assert.equal(ok("/authorize?a=1"), "/authorize?a=1");
  assert.equal(ok(`${ISSUER}/authorize?a=1`), "/authorize?a=1");
  for (const bad of [
    "//evil.com/authorize",
    "/\\evil.com/authorize",
    "https://evil.com/authorize",
    "javascript:alert(1)",
    "/token",
    "/authorize/../token",
    "",
  ]) {
    assert.equal(ok(bad), null, bad);
  }
});

test("Refresh token : rotation, ancien token refusé, mauvais client refusé sans consommer", async () => {
  const { app, messages } = await start();
  try {
    const { cookie } = await login(app, messages);
    const { verifier, challenge } = pkcePair();
    const authorize = await app.inject({ method: "GET", url: authorizeUrl(challenge), headers: { cookie } });
    const code = new URL(String(authorize.headers.location)).searchParams.get("code")!;

    const post = (form: Record<string, string>) =>
      app.inject({
        method: "POST",
        url: "/token",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        payload: new URLSearchParams(form).toString(),
      });

    const exchanged = await post({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: "authen-web",
      redirect_uri: REDIRECT,
    });
    assert.equal(exchanged.statusCode, 200);
    const first = exchanged.json();

    // Client inconnu : refusé.
    const unknown = await post({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "inconnu" });
    assert.equal(unknown.statusCode, 401);
    assert.equal(unknown.json().error, "invalid_client");

    const refreshed = await post({
      grant_type: "refresh_token",
      refresh_token: first.refresh_token,
      client_id: "authen-web",
    });
    assert.equal(refreshed.statusCode, 200);
    const second = refreshed.json();
    assert.notEqual(second.refresh_token, first.refresh_token);
    assert.equal(second.token_type, "Bearer");

    const userinfo = await app.inject({
      method: "GET",
      url: "/userinfo",
      headers: { authorization: `Bearer ${second.access_token}` },
    });
    assert.equal(userinfo.statusCode, 200);

    // Réutilisation de l'ancien token : refus, et toute la famille est révoquée.
    const reuse = await post({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "authen-web" });
    assert.equal(reuse.statusCode, 400);
    assert.equal(reuse.json().error, "invalid_grant");
    const afterReuse = await post({ grant_type: "refresh_token", refresh_token: second.refresh_token, client_id: "authen-web" });
    assert.equal(afterReuse.statusCode, 400);

    // Discovery annonce le grant ; le JWKS vérifie l'access token.
    const discovery = await app.inject({ method: "GET", url: "/.well-known/openid-configuration" });
    assert.ok(discovery.json().grant_types_supported.includes("refresh_token"));
    const jwks = await app.inject({ method: "GET", url: "/jwks.json" });
    const header = JSON.parse(Buffer.from(second.access_token.split(".")[0], "base64url").toString());
    assert.ok(jwks.json().keys.some((k: { kid: string }) => k.kid === header.kid));
  } finally {
    await app.close();
  }
});

test("Rate limiting : /auth/email/start limité par adresse puis par IP", async () => {
  const { app } = await start({ startPerEmail: 2, startPerIp: 5 });
  try {
    const send = (email: string) =>
      app.inject({ method: "POST", url: "/auth/email/start", payload: { email } });

    assert.equal((await send("a@example.com")).statusCode, 202);
    assert.equal((await send("A@example.com ")).statusCode, 202);
    const limited = await send("a@example.com");
    assert.equal(limited.statusCode, 429);
    assert.ok(Number(limited.headers["retry-after"]) > 0);

    // Les requêtes refusées comptent aussi pour l'IP (3 sur 5 ici).
    assert.equal((await send("b@example.com")).statusCode, 202);
    // Limite de l'IP atteinte.
    assert.equal((await send("c@example.com")).statusCode, 202);
    assert.equal((await send("d@example.com")).statusCode, 429);
  } finally {
    await app.close();
  }
});

test("RateLimiter : la fenêtre se rouvre après expiration", () => {
  let now = 0;
  const limiter = new RateLimiter({ limit: 2, windowMs: 1000, now: () => now });
  assert.equal(limiter.hit("k").allowed, true);
  assert.equal(limiter.hit("k").allowed, true);
  assert.equal(limiter.hit("k").allowed, false);
  now = 1001;
  assert.equal(limiter.hit("k").allowed, true);
});
