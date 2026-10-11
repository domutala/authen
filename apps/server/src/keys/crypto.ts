import {
  createCipheriv,
  createDecipheriv,
  createHash,
  generateKeyPair,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import { promisify } from "node:util";

const generateKeyPairAsync = promisify(generateKeyPair);

export interface GeneratedKey {
  kid: string;
  publicJwk: Record<string, unknown>;
  privatePem: string;
}

export async function generateRsaKey(modulusLength = 2048): Promise<GeneratedKey> {
  const { publicKey, privateKey } = await generateKeyPairAsync("rsa", {
    modulusLength,
  });
  const jwk = publicKey.export({ format: "jwk" }) as { e: string; n: string };
  // kid = empreinte JWK (RFC 7638) : stable et déterministe pour une clé donnée.
  const thumbprint = createHash("sha256")
    .update(JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n }))
    .digest("base64url");
  return {
    kid: thumbprint,
    publicJwk: { ...jwk, kty: "RSA", use: "sig", alg: "RS256", kid: thumbprint },
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

function encryptionKey(secret: string): Buffer {
  return Buffer.from(
    hkdfSync("sha256", secret, "authen.signing-keys", "v1", 32),
  );
}

/** Chiffre la clé privée ; le `kid` est lié au chiffrement (impossible de permuter deux clés). */
export function encryptPrivateKey(
  secret: string,
  kid: string,
  privatePem: string,
): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(secret), iv);
  cipher.setAAD(Buffer.from(kid));
  const data = Buffer.concat([cipher.update(privatePem, "utf8"), cipher.final()]);
  return [
    "v1",
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    data.toString("base64url"),
  ].join(".");
}

export function decryptPrivateKey(
  secret: string,
  kid: string,
  encrypted: string,
): string {
  const [version, iv, tag, data] = encrypted.split(".");
  if (version !== "v1" || !iv || !tag || !data) {
    throw new Error(`Format de clé privée inconnu (kid ${kid})`);
  }
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      encryptionKey(secret),
      Buffer.from(iv, "base64url"),
    );
    decipher.setAAD(Buffer.from(kid));
    decipher.setAuthTag(Buffer.from(tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(data, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    throw new Error(
      `Impossible de déchiffrer la clé ${kid} : AUTHEN_SIGNING_SECRET a-t-il changé ?`,
    );
  }
}

export type { KeyObject };
