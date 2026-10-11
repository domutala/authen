import type {
  ClientId,
  Clock,
  ProfileService,
  SecureRandom,
  SessionService,
  TokenDigester,
  TokenService,
} from "@authen/core";
import { createHash } from "node:crypto";
import type {
  AuthenticationResolver,
  AuthorizationCodeStore,
  OAuthClientRegistry,
  OidcIdTokenSigner,
} from "./types.js";

export interface OidcTransportOptions {
  issuer: string;
  authorizationCodeTtlMs?: number;
  idTokenTtlSeconds?: number;
}

export interface OidcTransportDeps {
  clients: OAuthClientRegistry;
  codes: AuthorizationCodeStore;
  authentication: AuthenticationResolver;
  sessions: SessionService;
  tokens: TokenService;
  profiles: ProfileService;
  idTokens: OidcIdTokenSigner;
  random: SecureRandom;
  digester: TokenDigester;
  clock: Clock;
  options: OidcTransportOptions;
}

export class OidcTransport {
  private readonly issuer: string;
  private readonly codeTtl: number;
  private readonly idTokenTtl: number;
  constructor(private readonly d: OidcTransportDeps) {
    this.issuer = d.options.issuer.replace(/\/$/, "");
    this.codeTtl = d.options.authorizationCodeTtlMs ?? 60_000;
    this.idTokenTtl = d.options.idTokenTtlSeconds ?? 300;
  }

  async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (
      request.method === "GET" &&
      url.pathname === "/.well-known/openid-configuration"
    )
      return json(this.discovery());
    if (request.method === "GET" && url.pathname === "/jwks.json")
      return json(await this.d.idTokens.jwks());
    if (request.method === "GET" && url.pathname === "/authorize")
      return this.authorize(request, url);
    if (request.method === "POST" && url.pathname === "/token")
      return this.token(request);
    if (
      (request.method === "GET" || request.method === "POST") &&
      url.pathname === "/userinfo"
    )
      return this.userinfo(request);
    return json({ error: "not_found" }, 404);
  }

  private discovery() {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/authorize`,
      token_endpoint: `${this.issuer}/token`,
      userinfo_endpoint: `${this.issuer}/userinfo`,
      jwks_uri: `${this.issuer}/jwks.json`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: [this.d.idTokens.algorithm],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid", "profile"],
      token_endpoint_auth_methods_supported: ["none"],
    };
  }

  private async authorize(request: Request, url: URL): Promise<Response> {
    const p = url.searchParams;
    const clientId = p.get("client_id") as ClientId | null;
    const redirectUri = p.get("redirect_uri");
    const state = p.get("state");
    if (!clientId || !redirectUri) return oauthError("invalid_request", 400);
    const client = await this.d.clients.findById(clientId);
    if (!client || !client.redirectUris.includes(redirectUri))
      return oauthError("invalid_request", 400);
    const fail = (error: string) => redirectError(redirectUri, state, error);
    if (p.get("response_type") !== "code")
      return fail("unsupported_response_type");
    const scopes = splitScope(p.get("scope"));
    if (
      !scopes.includes("openid") ||
      scopes.some((s) => !client.allowedScopes.includes(s))
    )
      return fail("invalid_scope");
    const challenge = p.get("code_challenge");
    if (p.get("code_challenge_method") !== "S256" || !validPkce(challenge))
      return fail("invalid_request");
    const session = await this.d.authentication.resolve(request);
    if (!session) return this.d.authentication.required(request);

    const code = this.d.random.token(32);
    await this.d.codes.save({
      codeHash: await this.d.digester.digest(code),
      clientId,
      userId: session.userId,
      sessionId: session.id,
      redirectUri,
      scopes,
      codeChallenge: challenge!,
      nonce: p.get("nonce"),
      expiresAt: new Date(this.d.clock.now().getTime() + this.codeTtl),
    });
    const target = new URL(redirectUri);
    target.searchParams.set("code", code);
    if (state !== null) target.searchParams.set("state", state);
    return Response.redirect(target, 302);
  }

  private async token(request: Request): Promise<Response> {
    const form = await request.formData();
    const grantType = form.get("grant_type");
    if (grantType === "refresh_token") return this.refresh(form);
    if (grantType !== "authorization_code")
      return oauthError("unsupported_grant_type", 400);
    const code = string(form.get("code"));
    const verifier = string(form.get("code_verifier"));
    const clientId = string(form.get("client_id")) as ClientId | null;
    const redirectUri = string(form.get("redirect_uri"));
    if (!code || !verifier || !clientId || !redirectUri)
      return oauthError("invalid_request", 400);
    if (!validVerifier(verifier)) return oauthError("invalid_grant", 400);
    const record = await this.d.codes.redeem({
      codeHash: await this.d.digester.digest(code),
      clientId,
      redirectUri,
      codeChallenge: pkce(verifier),
    });
    if (!record) return oauthError("invalid_grant", 400);
    const validation = await this.d.sessions.validate(record.sessionId);
    if (!validation.valid || validation.session.userId !== record.userId)
      return oauthError("invalid_grant", 400);
    const tokens = await this.d.tokens.issueTokenPair({
      session: validation.session,
      clientId,
      scopes: record.scopes,
    });
    const now = Math.floor(this.d.clock.now().getTime() / 1000);
    const idToken = await this.d.idTokens.sign({
      iss: this.issuer,
      sub: record.userId,
      aud: clientId,
      iat: now,
      exp: now + this.idTokenTtl,
      auth_time: Math.floor(
        validation.session.authenticatedAt.getTime() / 1000,
      ),
      ...(record.nonce ? { nonce: record.nonce } : {}),
      sid: record.sessionId,
    });
    return json({
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      token_type: "Bearer",
      expires_in: tokens.expiresIn,
      id_token: idToken,
      scope: record.scopes.join(" "),
    });
  }

  /**
   * Renouvellement : rotation du refresh token (usage unique, détection de
   * réutilisation dans le core). Le client doit être celui du token d'origine ;
   * le paramètre `scope` est ignoré : les scopes restent ceux de l'autorisation.
   */
  private async refresh(form: FormData): Promise<Response> {
    const refreshToken = string(form.get("refresh_token"));
    const clientId = string(form.get("client_id")) as ClientId | null;
    if (!refreshToken || !clientId) return oauthError("invalid_request", 400);
    if (!(await this.d.clients.findById(clientId)))
      return oauthError("invalid_client", 401);

    const result = await this.d.tokens.rotateRefreshToken(refreshToken, {
      clientId,
    });
    if (result.type !== "rotated") return oauthError("invalid_grant", 400);

    return json({
      access_token: result.tokens.accessToken,
      refresh_token: result.tokens.refreshToken,
      token_type: "Bearer",
      expires_in: result.tokens.expiresIn,
    });
  }

  private async userinfo(request: Request): Promise<Response> {
    const authorization = request.headers.get("authorization");
    if (!authorization?.startsWith("Bearer "))
      return oauthError("invalid_token", 401);
    const verification = await this.d.tokens.verifyAccessToken(
      authorization.slice(7),
    );
    if (!verification.valid || !verification.claims.scopes.includes("openid"))
      return oauthError("invalid_token", 401);
    const profile = await this.d.profiles.get(verification.claims.subject);
    return json({
      sub: verification.claims.subject,
      ...(verification.claims.scopes.includes("profile") && profile
        ? {
            name: profile.displayName,
            given_name: profile.givenName,
            family_name: profile.familyName,
            picture: profile.avatarUrl,
            locale: profile.locale,
          }
        : {}),
    });
  }
}

function splitScope(value: string | null) {
  return [...new Set((value ?? "").split(/\s+/).filter(Boolean))];
}
function pkce(value: string) {
  return createHash("sha256").update(value, "ascii").digest("base64url");
}
function validPkce(value: string | null): value is string {
  return value !== null && /^[A-Za-z0-9_-]{43}$/.test(value);
}
function validVerifier(value: string): boolean {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(value);
}
function string(value: FormDataEntryValue | null) {
  return typeof value === "string" ? value : null;
}
function json(body: unknown, status = 200) {
  return Response.json(body, {
    status,
    headers: { "cache-control": "no-store", pragma: "no-cache" },
  });
}
function oauthError(error: string, status: number) {
  return json({ error }, status);
}
function redirectError(uri: string, state: string | null, error: string) {
  const target = new URL(uri);
  target.searchParams.set("error", error);
  if (state !== null) target.searchParams.set("state", state);
  return Response.redirect(target, 302);
}
