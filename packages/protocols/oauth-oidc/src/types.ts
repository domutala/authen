import type { ClientId, Session, SessionId, UserId } from "@authen/core";

export interface OAuthClient {
  id: ClientId;
  redirectUris: string[];
  allowedScopes: string[];
}

export interface OAuthClientRegistry {
  findById(id: ClientId): Promise<OAuthClient | null>;
}

export interface AuthorizationCodeRecord {
  codeHash: string;
  clientId: ClientId;
  userId: UserId;
  sessionId: SessionId;
  redirectUri: string;
  scopes: string[];
  codeChallenge: string;
  nonce: string | null;
  expiresAt: Date;
}

export interface AuthorizationCodeStore {
  save(record: AuthorizationCodeRecord): Promise<void>;
  /** Vérification et consommation atomiques : exactement un échange peut gagner. */
  redeem(input: {
    codeHash: string;
    clientId: ClientId;
    redirectUri: string;
    codeChallenge: string;
  }): Promise<AuthorizationCodeRecord | null>;
}

export interface IdTokenClaims {
  iss: string;
  sub: UserId;
  aud: ClientId;
  iat: number;
  exp: number;
  auth_time: number;
  nonce?: string;
  sid: SessionId;
}

export interface OidcIdTokenSigner {
  readonly algorithm: string;
  sign(claims: IdTokenClaims): Promise<string>;
  jwks(): Promise<{ keys: Record<string, unknown>[] }>;
}

export interface AuthenticationResolver {
  resolve(request: Request): Promise<Session | null>;
  required(request: Request): Promise<Response>;
}
