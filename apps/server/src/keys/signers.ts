import type { TokenClaims, TokenSigner } from "@authen/core";
import type {
  IdTokenClaims,
  OidcIdTokenSigner,
} from "@authen/protocol-oauth-oidc";
import { createSign, createVerify } from "node:crypto";
import type { KeyRing } from "./key-ring.js";

const ACCESS_TOKEN_TYP = "at+jwt";

const encode = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

async function signJwt(
  ring: KeyRing,
  typ: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const { kid, privateKey } = await ring.signingKey();
  const input = `${encode({ alg: "RS256", typ, kid })}.${encode(payload)}`;
  const signature = createSign("RSA-SHA256")
    .update(input)
    .sign(privateKey, "base64url");
  return `${input}.${signature}`;
}

/** `null` si la signature, l'algorithme, le type ou la clé sont invalides. */
async function verifyJwt(
  ring: KeyRing,
  token: string,
  typ: string,
): Promise<Record<string, unknown> | null> {
  const [header, payload, signature, ...rest] = token.split(".");
  if (!header || !payload || !signature || rest.length > 0) return null;

  const parsed = parse(header);
  // Algorithme et type imposés par le serveur, jamais déduits du token.
  if (!parsed || parsed.alg !== "RS256" || parsed.typ !== typ) return null;
  if (typeof parsed.kid !== "string") return null;

  const key = await ring.verificationKey(parsed.kid);
  if (!key) return null;

  const valid = createVerify("RSA-SHA256")
    .update(`${header}.${payload}`)
    .verify(key, signature, "base64url");
  return valid ? parse(payload) : null;
}

function parse(segment: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(
      Buffer.from(segment, "base64url").toString("utf8"),
    );
    return typeof value === "object" && value !== null
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** ID tokens OIDC signés par l'anneau de clés. */
export class RingIdTokenSigner implements OidcIdTokenSigner {
  readonly algorithm = "RS256";
  constructor(private readonly ring: KeyRing) {}

  sign(claims: IdTokenClaims): Promise<string> {
    return signJwt(this.ring, "JWT", { ...claims });
  }

  jwks() {
    return this.ring.jwks();
  }
}

/**
 * Access tokens JWT (RFC 9068, `typ: at+jwt`) signés en RS256 : les autres
 * services les vérifient avec le JWKS, sans connaître de secret.
 */
export class RingAccessTokenSigner implements TokenSigner {
  constructor(
    private readonly ring: KeyRing,
    private readonly issuer: string,
  ) {}

  sign(claims: TokenClaims): Promise<string> {
    return signJwt(this.ring, ACCESS_TOKEN_TYP, {
      iss: claims.issuer,
      sub: claims.subject,
      aud: claims.audience,
      sid: claims.sessionId,
      cid: claims.clientId,
      iat: claims.issuedAt,
      exp: claims.expiresAt,
      scp: claims.scopes,
    });
  }

  async verify(
    token: string,
    expectedAudience: string,
  ): Promise<TokenClaims | null> {
    const body = await verifyJwt(this.ring, token, ACCESS_TOKEN_TYP);
    if (!body) return null;

    const nowSeconds = Math.floor(this.ring.clock.now().getTime() / 1000);
    if (
      body.iss !== this.issuer ||
      body.aud !== expectedAudience ||
      typeof body.exp !== "number" ||
      typeof body.iat !== "number" ||
      body.exp <= nowSeconds ||
      typeof body.sub !== "string" ||
      typeof body.sid !== "string" ||
      typeof body.cid !== "string" ||
      !Array.isArray(body.scp)
    ) {
      return null;
    }
    return {
      issuer: body.iss,
      subject: body.sub as TokenClaims["subject"],
      audience: body.aud,
      sessionId: body.sid as TokenClaims["sessionId"],
      clientId: body.cid as TokenClaims["clientId"],
      issuedAt: body.iat,
      expiresAt: body.exp,
      scopes: body.scp.filter((s): s is string => typeof s === "string"),
    };
  }
}
