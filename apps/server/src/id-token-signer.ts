import type {
  IdTokenClaims,
  OidcIdTokenSigner,
} from "@authen/protocol-oauth-oidc";
import {
  createHash,
  createSign,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";

/** Signer RS256 en mémoire. En production, injecter une clé persistée/KMS. */
export class RsaIdTokenSigner implements OidcIdTokenSigner {
  readonly algorithm = "RS256";
  private readonly privateKey: KeyObject;
  private readonly publicJwk: JsonWebKey;
  private readonly kid: string;

  constructor() {
    const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
    this.privateKey = pair.privateKey;
    this.publicJwk = pair.publicKey.export({ format: "jwk" });
    this.kid = createHash("sha256")
      .update(pair.publicKey.export({ type: "spki", format: "der" }))
      .digest("base64url")
      .slice(0, 16);
  }

  async sign(claims: IdTokenClaims): Promise<string> {
    const header = encode({ alg: this.algorithm, typ: "JWT", kid: this.kid });
    const payload = encode(claims);
    const input = `${header}.${payload}`;
    const signature = createSign("RSA-SHA256")
      .update(input)
      .sign(this.privateKey, "base64url");
    return `${input}.${signature}`;
  }

  async jwks(): Promise<{ keys: Record<string, unknown>[] }> {
    return {
      keys: [
        { ...this.publicJwk, use: "sig", alg: this.algorithm, kid: this.kid },
      ],
    };
  }
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}
