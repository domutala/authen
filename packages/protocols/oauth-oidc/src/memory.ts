import type { ClientId, Clock } from "@authen/core";
import type {
  AuthorizationCodeRecord,
  AuthorizationCodeStore,
  OAuthClient,
  OAuthClientRegistry,
} from "./types.js";

export class MemoryOAuthClientRegistry implements OAuthClientRegistry {
  private readonly clients = new Map<ClientId, OAuthClient>();
  register(client: OAuthClient): void {
    this.clients.set(client.id, structuredClone(client));
  }
  async findById(id: ClientId): Promise<OAuthClient | null> {
    const client = this.clients.get(id);
    return client ? structuredClone(client) : null;
  }
}

export class MemoryAuthorizationCodeStore implements AuthorizationCodeStore {
  private readonly records = new Map<string, AuthorizationCodeRecord>();
  constructor(private readonly clock: Clock) {}
  async save(record: AuthorizationCodeRecord): Promise<void> {
    this.records.set(record.codeHash, structuredClone(record));
  }
  async redeem(input: {
    codeHash: string;
    clientId: ClientId;
    redirectUri: string;
    codeChallenge: string;
  }): Promise<AuthorizationCodeRecord | null> {
    const record = this.records.get(input.codeHash);
    if (!record) return null;
    if (record.expiresAt <= this.clock.now()) {
      this.records.delete(input.codeHash);
      return null;
    }
    if (
      record.clientId !== input.clientId ||
      record.redirectUri !== input.redirectUri ||
      record.codeChallenge !== input.codeChallenge
    ) return null;
    this.records.delete(input.codeHash);
    return structuredClone(record);
  }
}
