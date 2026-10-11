import type { AuthResult, ProviderInstance, User, UserId } from "@authen/core";
import { AuthenticationError, RepositoryError } from "@authen/core";
import {
  createEmailOtpProvider,
  type OtpMessage,
} from "@authen/provider-email-otp";
import { createPasswordProvider } from "@authen/provider-password";
import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryCore, ManualClock } from "../src/index.js";

const MINUTE = 60 * 1000;
const EMAIL = "mamadou@example.com";

/** Prépare un core en mémoire avec les providers Email OTP et Password. */
async function setup(options: Parameters<typeof createMemoryCore>[0] = {}) {
  const clock = new ManualClock(new Date("2026-01-01T00:00:00Z"));
  const core = createMemoryCore({ clock, ...options });

  // "Boîte mail" factice : on garde les codes envoyés pour les relire.
  const sent: OtpMessage[] = [];
  core.services.providers.register(
    createEmailOtpProvider({
      challenges: core.challenges,
      digester: core.digester,
      random: core.random,
      clock,
      sender: {
        async send(message) {
          sent.push(message);
        },
      },
    }),
  );

  const password = createPasswordProvider({
    identities: core.repositories.identities,
    identityService: core.services.identities,
    credentials: core.repositories.credentials,
    hasher: core.hasher,
    ids: core.ids,
    clock,
    unitOfWork: core.unitOfWork,
  });
  core.services.providers.register(password);

  const emailInstance = await core.addProviderInstance({
    id: "email-main",
    type: "email-otp",
  });
  const passwordInstance = await core.addProviderInstance({
    id: "password-main",
    type: "password",
  });

  /** Dernier code reçu par email. */
  const lastCode = (): string => {
    const message = sent.at(-1);
    assert.ok(message, "aucun email envoyé");
    return message.code;
  };

  return {
    clock,
    core,
    password,
    emailInstance,
    passwordInstance,
    lastCode,
  };
}

type Env = Awaited<ReturnType<typeof setup>>;

function expectType<T extends AuthResult["type"]>(
  result: AuthResult,
  type: T,
): Extract<AuthResult, { type: T }> {
  assert.equal(result.type, type, JSON.stringify(result));
  return result as Extract<AuthResult, { type: T }>;
}

/** Connexion complète par code email : begin -> lire le code -> continue. */
async function signInWithEmail(env: Env, email = EMAIL) {
  const started = expectType(
    await env.core.services.auth.begin({
      providerInstanceId: env.emailInstance.id,
      clientId: null,
      purpose: "sign_in",
      userId: null,
      input: { email },
    }),
    "challenge",
  );

  return expectType(
    await env.core.services.auth.continue(started.transactionId, {
      code: env.lastCode(),
    }),
    "authenticated",
  );
}

/** Réauthentification email liée à un utilisateur déjà connu. */
async function stepUpWithEmail(env: Env, userId: UserId) {
  const started = expectType(
    await env.core.services.auth.begin({
      providerInstanceId: env.emailInstance.id,
      clientId: null,
      purpose: "step_up",
      userId,
      input: { email: EMAIL },
    }),
    "challenge",
  );

  return expectType(
    await env.core.services.auth.continue(started.transactionId, {
      code: env.lastCode(),
    }),
    "authenticated",
  );
}

test("Email OTP : première connexion crée le compte, la seconde le retrouve", async () => {
  const env = await setup();

  const first = await signInWithEmail(env);
  assert.equal(first.isNewUser, true);

  const user = await env.core.services.users.findById(first.userId);
  assert.equal(user?.status, "active");
  assert.equal(env.core.events.ofType("user.registered").length, 1);

  const identities = await env.core.services.identities.listByUser(
    first.userId,
  );
  assert.equal(identities.length, 1);
  assert.equal(identities[0]?.providerSubject, EMAIL);

  const second = await signInWithEmail(env);
  assert.equal(second.isNewUser, false);
  assert.equal(second.userId, first.userId);
  assert.equal(env.core.events.ofType("user.registered").length, 1);
});

test("Email OTP : l'email est normalisé (majuscules et espaces)", async () => {
  const env = await setup();
  const first = await signInWithEmail(env, EMAIL);
  const second = await signInWithEmail(env, `  ${EMAIL.toUpperCase()} `);
  assert.equal(second.userId, first.userId);
});

test("Email OTP : un mauvais code est refusé puis le bon est accepté", async () => {
  const env = await setup();
  const started = expectType(
    await env.core.services.auth.begin({
      providerInstanceId: env.emailInstance.id,
      clientId: null,
      purpose: "sign_in",
      userId: null,
      input: { email: EMAIL },
    }),
    "challenge",
  );

  const good = env.lastCode();
  const wrong = good === "000000" ? "111111" : "000000";

  const refused = expectType(
    await env.core.services.auth.continue(started.transactionId, {
      code: wrong,
    }),
    "rejected",
  );
  assert.equal(refused.code, "invalid_code");
  assert.equal(refused.retryable, true);

  expectType(
    await env.core.services.auth.continue(started.transactionId, {
      code: good,
    }),
    "authenticated",
  );
});

test("Email OTP : trop de mauvais codes ferme la transaction", async () => {
  const env = await setup({ authentication: { maxAttempts: 2 } });
  const started = expectType(
    await env.core.services.auth.begin({
      providerInstanceId: env.emailInstance.id,
      clientId: null,
      purpose: "sign_in",
      userId: null,
      input: { email: EMAIL },
    }),
    "challenge",
  );

  const good = env.lastCode();
  const wrong = good === "000000" ? "111111" : "000000";

  const first = expectType(
    await env.core.services.auth.continue(started.transactionId, {
      code: wrong,
    }),
    "rejected",
  );
  assert.equal(first.retryable, true);

  const second = expectType(
    await env.core.services.auth.continue(started.transactionId, {
      code: wrong,
    }),
    "rejected",
  );
  assert.equal(second.retryable, false);

  // Même avec le bon code, la transaction est terminée.
  await assert.rejects(
    env.core.services.auth.continue(started.transactionId, { code: good }),
    (error: unknown) =>
      error instanceof AuthenticationError &&
      error.code === "transaction_not_active",
  );
});

test("Email OTP : un code expiré est refusé", async () => {
  const env = await setup();
  const started = expectType(
    await env.core.services.auth.begin({
      providerInstanceId: env.emailInstance.id,
      clientId: null,
      purpose: "sign_in",
      userId: null,
      input: { email: EMAIL },
    }),
    "challenge",
  );

  env.clock.advance(11 * MINUTE);

  await assert.rejects(
    env.core.services.auth.continue(started.transactionId, {
      code: env.lastCode(),
    }),
    (error: unknown) =>
      error instanceof AuthenticationError &&
      error.code === "transaction_expired",
  );
});

test("Inscription fermée : une identité inconnue est refusée", async () => {
  const env = await setup({ security: { allowSelfRegistration: false } });
  const started = expectType(
    await env.core.services.auth.begin({
      providerInstanceId: env.emailInstance.id,
      clientId: null,
      purpose: "sign_in",
      userId: null,
      input: { email: EMAIL },
    }),
    "challenge",
  );

  const refused = expectType(
    await env.core.services.auth.continue(started.transactionId, {
      code: env.lastCode(),
    }),
    "rejected",
  );
  assert.equal(refused.code, "registration_required");
  assert.equal(env.core.db.users.size, 0);
});

test("Session et tokens : émission, rotation, détection de réutilisation", async () => {
  const env = await setup();
  const { sessions, tokens } = env.core.services;

  const auth = await signInWithEmail(env);
  const session = await sessions.create({
    userId: auth.userId,
    context: auth.context,
    device: { name: "test" },
  });

  const clientId = "drive" as Parameters<
    typeof tokens.issueTokenPair
  >[0]["clientId"];
  const pair = await tokens.issueTokenPair({
    session,
    clientId,
    scopes: ["openid"],
  });
  assert.equal((await tokens.verifyAccessToken(pair.accessToken)).valid, true);

  const rotated = await tokens.rotateRefreshToken(pair.refreshToken);
  assert.equal(rotated.type, "rotated");
  if (rotated.type !== "rotated") return;
  assert.notEqual(rotated.tokens.refreshToken, pair.refreshToken);

  // L'ancien refresh token revient : vol possible -> tout est révoqué.
  const reuse = await tokens.rotateRefreshToken(pair.refreshToken);
  assert.deepEqual(reuse, { type: "rejected", reason: "reuse_detected" });

  const afterReuse = await tokens.rotateRefreshToken(
    rotated.tokens.refreshToken,
  );
  assert.equal(afterReuse.type, "rejected");

  const verification = await tokens.verifyAccessToken(
    rotated.tokens.accessToken,
  );
  assert.deepEqual(verification, { valid: false, reason: "session_invalid" });
  assert.equal(env.core.events.ofType("token.reuse_detected").length, 1);
});

test("Session : expiration par inactivité et révocation globale", async () => {
  const env = await setup();
  const { sessions } = env.core.services;
  const auth = await signInWithEmail(env);

  const first = await sessions.create({
    userId: auth.userId,
    context: auth.context,
  });
  const second = await sessions.create({
    userId: auth.userId,
    context: auth.context,
  });

  const revoked = await sessions.revokeAll(auth.userId, {
    exceptSessionId: second.id,
  });
  assert.equal(revoked, 1);
  assert.equal((await sessions.validate(first.id)).valid, false);
  assert.equal((await sessions.validate(second.id)).valid, true);

  env.clock.advance(8 * 24 * 60 * MINUTE);
  const expired = await sessions.validate(second.id);
  assert.deepEqual(expired, { valid: false, reason: "expired" });
});

test("Mot de passe : création par enroll puis connexion", async () => {
  const env = await setup();
  const { auth, enrollment } = env.core.services;
  const user = await signInWithEmail(env);
  const stepUp = await stepUpWithEmail(env, user.userId);

  await enrollment.enroll({
    userId: user.userId,
    providerInstanceId: env.passwordInstance.id,
    stepUpTransactionId: stepUp.transactionId,
    input: {
      identifier: EMAIL,
      password: "correct horse battery staple",
    },
  });

  const signIn = (identifier: string, password: string) =>
    auth.begin({
      providerInstanceId: env.passwordInstance.id,
      clientId: null,
      purpose: "sign_in",
      userId: null,
      input: { identifier, password },
    });

  const ok = expectType(
    await signIn(EMAIL, "correct horse battery staple"),
    "authenticated",
  );
  assert.equal(ok.userId, user.userId);
  assert.equal(ok.isNewUser, false);
  assert.deepEqual(ok.context.methods, ["password"]);

  // Mauvais mot de passe et identifiant inconnu : même réponse (pas d'énumération).
  const wrong = expectType(
    await signIn(EMAIL, "mauvais mot de passe"),
    "rejected",
  );
  const unknown = expectType(
    await signIn("inconnu@example.com", "correct horse battery staple"),
    "rejected",
  );
  assert.equal(wrong.code, "invalid_credentials");
  assert.equal(unknown.code, wrong.code);
});

test("Enrôlement : une connexion ordinaire ne vaut pas step-up", async () => {
  const env = await setup();
  const signIn = await signInWithEmail(env);

  await assert.rejects(
    env.core.services.enrollment.enroll({
      userId: signIn.userId,
      providerInstanceId: env.passwordInstance.id,
      stepUpTransactionId: signIn.transactionId,
      input: {
        identifier: EMAIL,
        password: "correct horse battery staple",
      },
    }),
    (error: unknown) =>
      error instanceof AuthenticationError && error.code === "step_up_required",
  );
  assert.equal(env.core.db.credentials.size, 0);
});

test("Enrôlement : une preuve de step-up expirée est refusée", async () => {
  const env = await setup({ security: { stepUpMaxAgeMs: 5 * MINUTE } });
  const signIn = await signInWithEmail(env);
  const stepUp = await stepUpWithEmail(env, signIn.userId);
  env.clock.advance(5 * MINUTE + 1);

  await assert.rejects(
    env.core.services.enrollment.enroll({
      userId: signIn.userId,
      providerInstanceId: env.passwordInstance.id,
      stepUpTransactionId: stepUp.transactionId,
      input: {
        identifier: EMAIL,
        password: "correct horse battery staple",
      },
    }),
    (error: unknown) =>
      error instanceof AuthenticationError && error.code === "step_up_expired",
  );
  assert.equal(env.core.db.credentials.size, 0);
});

test("Enrôlement : la preuve de step-up est liée au même utilisateur", async () => {
  const env = await setup();
  const signIn = await signInWithEmail(env);
  const stepUp = await stepUpWithEmail(env, signIn.userId);

  await assert.rejects(
    env.core.services.enrollment.enroll({
      userId: "another-user" as UserId,
      providerInstanceId: env.passwordInstance.id,
      stepUpTransactionId: stepUp.transactionId,
      input: {
        identifier: EMAIL,
        password: "correct horse battery staple",
      },
    }),
    (error: unknown) =>
      error instanceof AuthenticationError && error.code === "step_up_invalid",
  );
  assert.equal(env.core.db.credentials.size, 0);
});

test("Mot de passe : l'inscription directe est refusée", async () => {
  const env = await setup();
  const result = expectType(
    await env.core.services.auth.begin({
      providerInstanceId: env.passwordInstance.id,
      clientId: null,
      purpose: "sign_up",
      userId: null,
      input: { identifier: EMAIL, password: "correct horse battery staple" },
    }),
    "rejected",
  );
  assert.equal(result.code, "enrollment_required");
});

test("Provider désactivé : la connexion ne démarre pas", async () => {
  const env = await setup();
  const disabled: ProviderInstance = await env.core.addProviderInstance({
    id: "email-off",
    type: "email-otp",
    enabled: false,
  });

  await assert.rejects(
    env.core.services.auth.begin({
      providerInstanceId: disabled.id,
      clientId: null,
      purpose: "sign_in",
      userId: null,
      input: { email: EMAIL },
    }),
    (error: unknown) =>
      error instanceof AuthenticationError &&
      error.code === "provider_disabled",
  );
});

test("Transaction : une erreur annule toutes les écritures du bloc", async () => {
  const env = await setup();
  const now = env.clock.now();
  const user: User = {
    id: "u-rollback" as UserId,
    status: "active",
    lastAuthenticatedAt: null,
    disabledAt: null,
    createdAt: now,
    updatedAt: now,
  };

  await assert.rejects(
    env.core.unitOfWork.run(async () => {
      await env.core.repositories.users.create(user);
      throw new Error("boom");
    }),
    /boom/,
  );

  assert.equal(await env.core.repositories.users.findById(user.id), null);
});

test("Configuration : les valeurs dangereuses sont refusées au démarrage", () => {
  assert.throws(
    () => createMemoryCore({ authentication: { maxAttempts: 0 } }),
    /authentication\.maxAttempts/,
  );
  assert.throws(
    () => createMemoryCore({ session: { idleTimeoutMs: Number.NaN } }),
    /session\.idleTimeoutMs/,
  );
  assert.throws(
    () => createMemoryCore({ token: { accessTokenTtlSeconds: 0 } }),
    /token\.accessTokenTtlSeconds/,
  );
  assert.throws(
    () => createMemoryCore({ security: { stepUpMaxAgeMs: -1 } }),
    /security\.stepUpMaxAgeMs/,
  );
  assert.throws(() => createMemoryCore({ issuer: "   " }), /token\.issuer/);

  const core = createMemoryCore();
  assert.throws(
    () =>
      createEmailOtpProvider({
        challenges: core.challenges,
        digester: core.digester,
        random: core.random,
        clock: core.clock,
        sender: { async send() {} },
        options: { codeLength: 3 },
      }),
    /emailOtp\.codeLength/,
  );
  assert.throws(
    () =>
      createPasswordProvider({
        identities: core.repositories.identities,
        identityService: core.services.identities,
        credentials: core.repositories.credentials,
        hasher: core.hasher,
        ids: core.ids,
        clock: core.clock,
        unitOfWork: core.unitOfWork,
        options: { minLength: 20, maxLength: 10 },
      }),
    /password\.maxLength/,
  );
});

test("Concurrence OTP : un challenge ne peut authentifier qu'une requête", async () => {
  const env = await setup();
  const started = expectType(
    await env.core.services.auth.begin({
      providerInstanceId: env.emailInstance.id,
      clientId: null,
      purpose: "sign_in",
      userId: null,
      input: { email: EMAIL },
    }),
    "challenge",
  );
  const code = env.lastCode();

  const results = await Promise.all([
    env.core.services.auth.continue(started.transactionId, { code }),
    env.core.services.auth.continue(started.transactionId, { code }),
  ]);

  assert.equal(
    results.filter((result) => result.type === "authenticated").length,
    1,
  );
  assert.equal(
    results.filter((result) => result.type === "rejected").length,
    1,
  );
  assert.equal(env.core.db.users.size, 1);
  assert.equal(env.core.db.identities.size, 1);
});

test("Concurrence refresh token : une seule rotation gagne", async () => {
  const env = await setup();
  const auth = await signInWithEmail(env);
  const session = await env.core.services.sessions.create({
    userId: auth.userId,
    context: auth.context,
  });
  const clientId = "drive" as Parameters<
    typeof env.core.services.tokens.issueTokenPair
  >[0]["clientId"];
  const pair = await env.core.services.tokens.issueTokenPair({
    session,
    clientId,
    scopes: ["openid"],
  });

  const results = await Promise.all([
    env.core.services.tokens.rotateRefreshToken(pair.refreshToken),
    env.core.services.tokens.rotateRefreshToken(pair.refreshToken),
  ]);

  assert.equal(results.filter((result) => result.type === "rotated").length, 1);
  assert.equal(
    results.filter(
      (result) =>
        result.type === "rejected" && result.reason === "reuse_detected",
    ).length,
    1,
  );
  assert.equal(env.core.events.ofType("token.reuse_detected").length, 1);
  assert.deepEqual(await env.core.services.sessions.validate(session.id), {
    valid: false,
    reason: "revoked",
  });
});

test("Repositories : create et update respectent leur contrat", async () => {
  const env = await setup();
  const now = env.clock.now();
  const user: User = {
    id: "u-contract" as UserId,
    status: "active",
    lastAuthenticatedAt: null,
    disabledAt: null,
    createdAt: now,
    updatedAt: now,
  };

  await env.core.repositories.users.create(user);
  await assert.rejects(
    env.core.repositories.users.create(user),
    (error: unknown) =>
      error instanceof RepositoryError && error.code === "duplicate_key",
  );

  await assert.rejects(
    env.core.repositories.users.update({
      ...user,
      id: "u-missing" as UserId,
    }),
    (error: unknown) =>
      error instanceof RepositoryError && error.code === "record_not_found",
  );
});

test("Transaction imbriquée : le rollback externe annule toutes les écritures", async () => {
  const env = await setup();
  const now = env.clock.now();
  const makeUser = (id: string): User => ({
    id: id as UserId,
    status: "active",
    lastAuthenticatedAt: null,
    disabledAt: null,
    createdAt: now,
    updatedAt: now,
  });

  await assert.rejects(
    env.core.unitOfWork.run(async () => {
      await env.core.repositories.users.create(makeUser("u-outer"));
      await env.core.unitOfWork.run(async () => {
        await env.core.repositories.users.create(makeUser("u-inner"));
      });
      throw new Error("rollback outer");
    }),
    /rollback outer/,
  );

  assert.equal(env.core.db.users.has("u-outer" as UserId), false);
  assert.equal(env.core.db.users.has("u-inner" as UserId), false);
});

test("Transactions concurrentes : aucun état partiel n'est observable", async () => {
  const env = await setup();
  const now = env.clock.now();
  const firstId = "u-first" as UserId;
  const secondId = "u-second" as UserId;
  const makeUser = (id: UserId): User => ({
    id,
    status: "active",
    lastAuthenticatedAt: null,
    disabledAt: null,
    createdAt: now,
    updatedAt: now,
  });

  let releaseFirst!: () => void;
  const firstCanFinish = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  let firstWriteDone!: () => void;
  const firstHasWritten = new Promise<void>((resolve) => {
    firstWriteDone = resolve;
  });

  const first = env.core.unitOfWork.run(async () => {
    await env.core.repositories.users.create(makeUser(firstId));
    firstWriteDone();
    await firstCanFinish;
    await env.core.repositories.users.create(makeUser(secondId));
  });
  await firstHasWritten;

  const observer = env.core.unitOfWork.run(async () => ({
    first: await env.core.repositories.users.findById(firstId),
    second: await env.core.repositories.users.findById(secondId),
  }));
  releaseFirst();

  const [, observed] = await Promise.all([first, observer]);
  assert.ok(observed.first);
  assert.ok(observed.second);
});

test("Refresh token : un autre client ne peut pas consommer le token", async () => {
  const env = await setup();
  const { sessions, tokens } = env.core.services;
  const auth = await signInWithEmail(env);
  const session = await sessions.create({
    userId: auth.userId,
    context: auth.context,
  });

  type ClientId = Parameters<typeof tokens.issueTokenPair>[0]["clientId"];
  const owner = "owner" as ClientId;
  const pair = await tokens.issueTokenPair({
    session,
    clientId: owner,
    scopes: ["openid"],
  });

  const stolen = await tokens.rotateRefreshToken(pair.refreshToken, {
    clientId: "other" as ClientId,
  });
  assert.deepEqual(stolen, { type: "rejected", reason: "invalid_token" });

  // Le token n'a pas été consommé : son propriétaire peut toujours l'utiliser.
  const rotated = await tokens.rotateRefreshToken(pair.refreshToken, {
    clientId: owner,
  });
  assert.equal(rotated.type, "rotated");
});
