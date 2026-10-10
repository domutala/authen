import type {
  Clock,
  SecretHasher,
  SecureRandom,
  TokenClaims,
  TokenDigester,
  TokenSigner,
  UserId,
  SessionId,
  ClientId,
} from "@authen/core";
import {
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  scrypt,
  timingSafeEqual,
} from "node:crypto";

/*
 * Implémentations cryptographiques minimales, basées sur `node:crypto`, pour
 * faire tourner le core sans dépendance externe (développement et tests).
 * En production, on les remplace par l'adaptateur "cryptography" (argon2id,
 * clés asymétriques / KMS...).
 */

export class NodeSecureRandom implements SecureRandom {
  token(byteLength: number): string {
    return randomBytes(byteLength).toString("base64url");
  }

  /** `randomInt` tire chaque chiffre uniformément (pas de biais de modulo). */
  digits(length: number): string {
    let code = "";
    for (let i = 0; i < length; i++) code += randomInt(0, 10).toString();
    return code;
  }
}

/** SHA-256 déterministe : convient aux jetons aléatoires à forte entropie. */
export class Sha256TokenDigester implements TokenDigester {
  async digest(token: string): Promise<string> {
    return createHash("sha256").update(token).digest("hex");
  }
}

/** Hachage de mots de passe avec scrypt (sel aléatoire par mot de passe). */
export class ScryptSecretHasher implements SecretHasher {
  private static readonly N = 16384;
  private static readonly R = 8;
  private static readonly P = 1;
  private static readonly KEY_LENGTH = 32;

  async hash(secret: string): Promise<string> {
    const { N, R, P, KEY_LENGTH } = ScryptSecretHasher;
    const salt = randomBytes(16);
    const key = await derive(secret, salt, KEY_LENGTH, N, R, P);
    return [
      "scrypt",
      N,
      R,
      P,
      salt.toString("base64url"),
      key.toString("base64url"),
    ].join("$");
  }

  async verify(secret: string, hash: string): Promise<boolean> {
    const [scheme, n, r, p, salt, key] = hash.split("$");
    if (scheme !== "scrypt" || !n || !r || !p || !salt || !key) return false;

    const expected = Buffer.from(key, "base64url");
    const actual = await derive(
      secret,
      Buffer.from(salt, "base64url"),
      expected.length,
      Number(n),
      Number(r),
      Number(p),
    );
    return (
      actual.length === expected.length && timingSafeEqual(actual, expected)
    );
  }
}

function derive(
  secret: string,
  salt: Buffer,
  keyLength: number,
  N: number,
  r: number,
  p: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(secret, salt, keyLength, { N, r, p }, (error, key) =>
      error ? reject(error) : resolve(key),
    );
  });
}

export interface HmacTokenSignerOptions {
  /** Secret partagé (HS256). */
  secret: string;
  /** Émetteur écrit dans le token et exigé à la vérification. */
  issuer: string;
  clock: Clock;
}

/**
 * Access tokens au format JWT signés en HS256 (clé symétrique).
 * Pratique en développement : un seul secret. Pour que d'autres services
 * vérifient les tokens sans connaître le secret, passer à une clé asymétrique.
 */
export class HmacTokenSigner implements TokenSigner {
  private readonly o: HmacTokenSignerOptions;

  constructor(options: HmacTokenSignerOptions) {
    this.o = options;
  }

  async sign(claims: TokenClaims): Promise<string> {
    const header = encode({ alg: "HS256", typ: "JWT" });
    const payload = encode({
      iss: claims.issuer,
      sub: claims.subject,
      aud: claims.audience,
      sid: claims.sessionId,
      cid: claims.clientId,
      iat: claims.issuedAt,
      exp: claims.expiresAt,
      scp: claims.scopes,
    });
    return `${header}.${payload}.${this.signature(`${header}.${payload}`)}`;
  }

  async verify(
    token: string,
    expectedAudience: string,
  ): Promise<TokenClaims | null> {
    const parts = token.split(".");
    const [header, payload, signature] = parts;
    if (parts.length !== 3 || !header || !payload || !signature) return null;

    // L'algorithme est imposé par le serveur, jamais lu dans le token.
    const parsedHeader = decode(header);
    if (!parsedHeader || parsedHeader.alg !== "HS256") return null;

    const expected = Buffer.from(this.signature(`${header}.${payload}`));
    const actual = Buffer.from(signature);
    if (
      expected.length !== actual.length ||
      !timingSafeEqual(expected, actual)
    ) {
      return null;
    }

    const body = decode(payload);
    if (!body) return null;

    const nowSeconds = Math.floor(this.o.clock.now().getTime() / 1000);
    if (
      body.iss !== this.o.issuer ||
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
      subject: body.sub as UserId,
      audience: body.aud,
      sessionId: body.sid as SessionId,
      clientId: body.cid as ClientId,
      issuedAt: body.iat,
      expiresAt: body.exp,
      scopes: body.scp.filter((s): s is string => typeof s === "string"),
    };
  }

  private signature(data: string): string {
    return createHmac("sha256", this.o.secret).update(data).digest("base64url");
  }
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function decode(segment: string): Record<string, unknown> | null {
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
