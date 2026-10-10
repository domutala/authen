export type Brand<T, Name extends string> = T & {
  readonly __brand: Name;
};

export type UserId = Brand<string, "UserId">;
export type IdentityId = Brand<string, "IdentityId">;
export type ContactId = Brand<string, "ContactId">;
export type CredentialId = Brand<string, "CredentialId">;
export type SessionId = Brand<string, "SessionId">;
export type TransactionId = Brand<string, "TransactionId">;
export type ProviderInstanceId = Brand<string, "ProviderInstanceId">;
export type TokenFamilyId = Brand<string, "TokenFamilyId">;
export type TokenId = Brand<string, "TokenId">;
export type ClientId = Brand<string, "ClientId">;
export type EventId = Brand<string, "EventId">;

export interface Timestamps {
  createdAt: Date;
  updatedAt: Date;
}

export type Metadata = Record<string, unknown>;
