import type {
  ClientId,
  EventPublisher,
  SessionId,
  TransactionId,
} from "@authen/core";
import { AuthenticationError } from "@authen/core";
import { OidcTransport } from "@authen/protocol-oauth-oidc";
import {
  createEmailOtpProvider,
  type OtpMessage,
  type OtpSender,
} from "@authen/provider-email-otp";

import cookie from "@fastify/cookie";
import Fastify, {
  type FastifyInstance,
  type FastifyLoggerOptions,
  type FastifyReply,
  type FastifyRequest,
} from "fastify";

import { loadEnvironment } from "./env.js";
import { RateLimiter } from "./rate-limiter.js";
import { safeReturnTo } from "./return-to.js";
import { createRuntime } from "./runtime.js";
import type { PinoLoggerOptions } from "fastify/types/logger.js";

const SESSION_COOKIE = "authen_session";

export interface ServerOptions {
  /** URL publique du serveur ; sinon AUTHEN_ISSUER, sinon http://HOST:PORT. */
  issuer?: string;
  otpSender?: OtpSender;
  /** Surcharge du mode d'exécution, principalement pour les tests. */
  environment?: string;
  secureCookies?: boolean;
  /** Surcharge `DATABASE_URL` ; `null` force le stockage mémoire. */
  databaseUrl?: string | null;
  /** Limites de débit (par fenêtre de 15 min pour l'IP, 10 min pour l'email). */
  rateLimits?: Partial<{
    startPerIp: number;
    startPerEmail: number;
    verifyPerIp: number;
  }>;
}

export async function buildServer(
  options: ServerOptions = {},
): Promise<FastifyInstance> {
  const environment = options.environment ?? process.env.NODE_ENV ?? "development";
  if (!options.otpSender && environment === "production") {
    throw new Error("Un OtpSender explicite est requis en production");
  }
  const env = loadEnvironment();
  const envToLogger: Record<
    string,
    (FastifyLoggerOptions & PinoLoggerOptions) | boolean
  > = {
    development: {
      transport: {
        target: "pino-pretty",
        options: {
          translateTime: "HH:MM:ss Z",
          ignore: "pid,hostname",
        },
      },
    },
    production: true,
    test: false,
  };

  const app = Fastify({
    logger: envToLogger[environment] ?? true,
    // Derrière un proxy : l'IP vient de X-Forwarded-For (sinon elle serait falsifiable).
    trustProxy: env.AUTHEN_TRUST_PROXY,
  });
  app.decorate("envs", env);

  const issuer = (
    options.issuer ??
    app.envs.AUTHEN_ISSUER ??
    `http://${app.envs.HOST}:${app.envs.PORT}`
  ).replace(/\/$/, "");

  const clientId = app.envs.OIDC_CLIENT_ID;

  const events: EventPublisher = {
    async publish(event) {
      app.log.info(
        { eventType: event.eventType, userId: event.userId },
        "security event",
      );
    },
  };
  const databaseUrl =
    options.databaseUrl === undefined
      ? app.envs.DATABASE_URL
      : (options.databaseUrl ?? undefined);
  const runtime = await createRuntime({
    issuer,
    databaseUrl,
    signingSecret: app.envs.AUTHEN_SIGNING_SECRET,
    keyRotationDays: app.envs.AUTHEN_KEY_ROTATION_DAYS,
    events,
  });
  app.addHook("onClose", async () => runtime.close());
  app.log.info({ storage: runtime.storage }, "stockage");
  const core = runtime;

  const sender = options.otpSender ?? developmentOtpSender();
  core.services.providers.register(
    createEmailOtpProvider({
      challenges: core.challenges,
      digester: core.digester,
      random: core.random,
      clock: core.clock,
      sender,
    }),
  );
  const email = await core.ensureProviderInstance({
    id: "email-main",
    type: "email-otp",
  });

  await core.ensureClient({
    id: (clientId ?? "authen-web") as ClientId,
    redirectUris: [
      app.envs.OIDC_REDIRECT_URI ?? "http://localhost:3001/callback",
    ],
    allowedScopes: ["openid", "profile"],
  });

  const transport = new OidcTransport({
    clients: core.clients,
    codes: core.codes,
    authentication: {
      async resolve(request) {
        const id = parseCookie(request.headers.get("cookie"), SESSION_COOKIE);
        if (!id) return null;
        const result = await core.services.sessions.validate(id as SessionId);
        return result.valid ? result.session : null;
      },
      async required(request) {
        const target = new URL("/login", issuer);
        const current = new URL(request.url);
        target.searchParams.set(
          "return_to",
          `${current.pathname}${current.search}`,
        );
        return Response.redirect(target, 302);
      },
    },
    sessions: core.services.sessions,
    tokens: core.services.tokens,
    profiles: core.services.profiles,
    idTokens: core.idTokens,
    random: core.random,
    digester: core.digester,
    clock: core.clock,
    options: { issuer },
  });

  await app.register(cookie);

  app.addContentTypeParser(
    "application/x-www-form-urlencoded",
    { parseAs: "string" },
    (_request, body, done) =>
      done(null, Object.fromEntries(new URLSearchParams(body.toString()))),
  );

  app.get("/health", async () => ({ status: "ok" }));

  const limit = options.rateLimits ?? {};
  const limiter = (max: number, windowMs: number) =>
    new RateLimiter({
      limit: max,
      windowMs,
      now: () => core.clock.now().getTime(),
    });
  const startByIp = limiter(limit.startPerIp ?? 10, 15 * 60_000);
  const startByEmail = limiter(limit.startPerEmail ?? 3, 10 * 60_000);
  const verifyByIp = limiter(limit.verifyPerIp ?? 30, 15 * 60_000);

  const tooMany = (reply: FastifyReply, retryAfterSeconds: number) =>
    reply
      .header("retry-after", String(retryAfterSeconds))
      .code(429)
      .send({ error: "rate_limited", retryAfterSeconds });

  app.get("/login", async (request) => ({
    message: "POST /auth/email/start puis /auth/email/verify",
    returnTo: safeReturnTo(queryValue(request.query, "return_to"), issuer),
  }));

  app.post("/auth/email/start", async (request, reply) => {
    const emailAddress = bodyValue(request.body, "email");
    if (!emailAddress) return reply.code(400).send({ error: "email_required" });

    // Limite par IP puis par adresse : empêche d'inonder une boîte mail d'OTP.
    for (const check of [
      startByIp.hit(request.ip),
      startByEmail.hit(emailAddress.trim().toLowerCase()),
    ]) {
      if (!check.allowed) return tooMany(reply, check.retryAfterSeconds);
    }

    const result = await core.services.auth.begin({
      providerInstanceId: email.id,
      clientId: null,
      purpose: "sign_in",
      userId: null,
      input: { email: emailAddress },
    });

    return reply.code(result.type === "challenge" ? 202 : 400).send(result);
  });

  app.post("/auth/email/verify", async (request, reply) => {
    const transactionId = bodyValue(request.body, "transactionId");
    const code = bodyValue(request.body, "code");

    if (!transactionId || !code) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const verifyLimit = verifyByIp.hit(request.ip);
    if (!verifyLimit.allowed)
      return tooMany(reply, verifyLimit.retryAfterSeconds);

    let result;
    try {
      result = await core.services.auth.continue(
        transactionId as TransactionId,
        { code },
      );
    } catch (error) {
      if (error instanceof AuthenticationError) {
        const status = error.code === "transaction_not_found"
          ? 404
          : error.code === "transaction_not_active"
            ? 409
            : 400;
        return reply.code(status).send({ error: error.code });
      }
      throw error;
    }

    if (result.type !== "authenticated") return reply.code(401).send(result);

    const session = await core.services.sessions.create({
      userId: result.userId,
      context: result.context,
    });

    reply.setCookie(SESSION_COOKIE, session.id, {
      httpOnly: true,
      secure: options.secureCookies ?? issuer.startsWith("https://"),
      sameSite: "lax",
      path: "/",
    });

    return {
      userId: result.userId,
      sessionId: session.id,
      // À suivre côté client pour reprendre le flux /authorize interrompu.
      returnTo: safeReturnTo(bodyValue(request.body, "return_to"), issuer),
    };
  });

  for (const path of [
    "/.well-known/openid-configuration",
    "/jwks.json",
    "/authorize",
    "/token",
    "/userinfo",
  ]) {
    app.route({
      method:
        path === "/token"
          ? "POST"
          : path === "/userinfo"
            ? ["GET", "POST"]
            : "GET",
      url: path,
      handler: async (request, reply) =>
        forward(transport, issuer, request, reply),
    });
  }

  return app;
}

async function forward(
  transport: OidcTransport,
  issuer: string,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (value !== undefined)
      headers.set(name, Array.isArray(value) ? value.join(",") : value);
  }
  const body =
    request.method === "GET"
      ? undefined
      : new URLSearchParams(request.body as Record<string, string>);
  const response = await transport.handle(
    new Request(`${issuer}${request.raw.url}`, {
      method: request.method,
      headers,
      ...(body ? { body } : {}),
    }),
  );
  reply.code(response.status);
  response.headers.forEach((value, name) => reply.header(name, value));
  return reply.send(Buffer.from(await response.arrayBuffer()));
}

function bodyValue(body: unknown, key: string): string | null {
  if (typeof body !== "object" || body === null) return null;
  const value = (body as Record<string, unknown>)[key];
  return typeof value === "string" ? value : null;
}
function queryValue(query: unknown, key: string): string | null {
  return bodyValue(query, key);
}
function parseCookie(header: string | null, name: string): string | null {
  for (const part of header?.split(";") ?? []) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}
function developmentOtpSender(): OtpSender {
  return {
    async send(message: OtpMessage) {
      process.stderr.write(
        `[DEV ONLY] OTP for ${message.to}: ${message.code}\n`,
      );
    },
  };
}
