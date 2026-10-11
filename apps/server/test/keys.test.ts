import { ManualClock } from "@authen/adapter-memory";
import type { SessionId, ClientId, UserId } from "@authen/core";
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  KeyRing,
  MemorySigningKeyStore,
  RingAccessTokenSigner,
  RingIdTokenSigner,
} from "../src/keys/index.js";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const ISSUER = "https://auth.test";

function setup(secret = "s".repeat(40)) {
  const clock = new ManualClock(new Date("2026-01-01T00:00:00Z"));
  const store = new MemorySigningKeyStore();
  const ring = (overrides = {}) =>
    new KeyRing({
      store,
      clock,
      encryptionSecret: secret,
      rotationIntervalMs: 30 * DAY,
      overlapMs: HOUR,
      modulusLength: 2048,
      ...overrides,
    });
  return { clock, store, ring };
}

const claims = (clock: ManualClock, ttlSeconds = 900) => {
  const iat = Math.floor(clock.now().getTime() / 1000);
  return {
    issuer: ISSUER,
    subject: "u1" as UserId,
    audience: "api",
    sessionId: "s1" as SessionId,
    clientId: "c1" as ClientId,
    issuedAt: iat,
    expiresAt: iat + ttlSeconds,
    scopes: ["openid"],
  };
};

test("Clés : créées au démarrage, le même kid survit à un redémarrage", async () => {
  const { ring } = setup();
  const first = ring();
  await first.init();
  const kid = (await first.signingKey()).kid;

  const second = ring(); // autre instance, même store
  await second.init();
  assert.equal((await second.signingKey()).kid, kid);
  assert.equal((await second.jwks()).keys.length, 1);
});

test("Clés : le JWKS ne contient aucune partie privée", async () => {
  const { ring } = setup();
  const r = ring();
  await r.init();
  const [key] = (await r.jwks()).keys;
  assert.ok(key);
  for (const secret of ["d", "p", "q", "dp", "dq", "qi"]) {
    assert.equal(secret in key, false);
  }
  assert.equal(key.alg, "RS256");
});

test("Clés : la clé privée est chiffrée au repos et le mauvais secret échoue", async () => {
  const { store, ring } = setup();
  await ring().init();
  const [record] = await store.transaction((tx) => tx.list());
  assert.ok(record);
  assert.doesNotMatch(record.privateKeyEncrypted, /PRIVATE KEY/);

  const wrong = ring({ encryptionSecret: "x".repeat(40) });
  await assert.rejects(wrong.init().then(() => wrong.signingKey()), /déchiffrer/);
});

test("Access token : signature, vérification et refus des tokens altérés", async () => {
  const { clock, ring } = setup();
  const r = ring();
  await r.init();
  const signer = new RingAccessTokenSigner(r, ISSUER);

  const token = await signer.sign(claims(clock));
  assert.deepEqual((await signer.verify(token, "api"))?.scopes, ["openid"]);
  assert.equal(await signer.verify(token, "autre-audience"), null);

  const [h, p, s] = token.split(".");
  const forged = Buffer.from(
    JSON.stringify({ ...JSON.parse(Buffer.from(p!, "base64url").toString()), sub: "root" }),
  ).toString("base64url");
  assert.equal(await signer.verify(`${h}.${forged}.${s}`, "api"), null);

  // alg=none et alg=HS256 sont refusés.
  const none = Buffer.from(JSON.stringify({ alg: "none", typ: "at+jwt" })).toString("base64url");
  assert.equal(await signer.verify(`${none}.${p}.`, "api"), null);

  clock.advance(16 * 60_000);
  assert.equal(await signer.verify(token, "api"), null);
});

test("Un ID token ne peut pas servir d'access token", async () => {
  const { clock, ring } = setup();
  const r = ring();
  await r.init();
  const idToken = await new RingIdTokenSigner(r).sign({
    iss: ISSUER,
    sub: "u1" as UserId,
    aud: "c1" as ClientId,
    iat: 1,
    exp: 9999999999,
    auth_time: 1,
    sid: "s1" as SessionId,
  });
  assert.equal(
    await new RingAccessTokenSigner(r, ISSUER).verify(idToken, "c1"),
    null,
  );
  void clock;
});

test("Rotation : l'ancienne clé reste valide pendant le recouvrement puis disparaît", async () => {
  const { clock, ring } = setup();
  const r = ring();
  await r.init();
  const signer = new RingAccessTokenSigner(r, ISSUER);
  const oldKid = (await r.signingKey()).kid;

  // Token émis 30 min avant l'échéance de rotation (30 jours), valable 3 h.
  clock.advance(30 * DAY - 30 * 60_000);
  const oldToken = await signer.sign(claims(clock, 3 * 3600));
  clock.advance(31 * 60_000);
  const newToken = await signer.sign(claims(clock));
  const newKid = (await r.signingKey()).kid;
  assert.notEqual(newKid, oldKid);

  const kids = (await r.jwks()).keys.map((k) => k.kid);
  assert.deepEqual(new Set(kids), new Set([oldKid, newKid]));
  assert.ok(await signer.verify(newToken, "api"));

  // Un token signé avant la rotation reste vérifiable pendant le recouvrement.
  assert.ok(await signer.verify(oldToken, "api"));

  clock.advance(HOUR + 1000);
  assert.deepEqual((await r.jwks()).keys.map((k) => k.kid), [newKid]);
  assert.equal(await signer.verify(oldToken, "api"), null);
});

test("Rotation manuelle : la nouvelle clé signe, l'ancienne reste publiée", async () => {
  const { clock, ring } = setup();
  const r = ring();
  await r.init();
  const signer = new RingAccessTokenSigner(r, ISSUER);
  const before = await signer.sign(claims(clock));
  const kid = await r.rotate();
  assert.equal((await r.signingKey()).kid, kid);
  assert.equal((await r.jwks()).keys.length, 2);
  assert.ok(await signer.verify(before, "api"));
});

test("Deux instances qui démarrent ensemble ne créent qu'une clé active", async () => {
  const { ring, store } = setup();
  await Promise.all([ring().init(), ring().init(), ring().init()]);
  const records = await store.transaction((tx) => tx.list());
  assert.equal(records.filter((r) => r.status === "active").length, 1);
});
