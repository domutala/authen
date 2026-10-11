import type {
  AuthenticationContext,
  CredentialStatus,
  DeviceInfo,
  IdentityStatus,
  Metadata,
  SessionStatus,
  TransactionPurpose,
  TransactionStatus,
  UserStatus,
} from "@authen/core";
import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  unique,
} from "drizzle-orm/pg-core";

const timestamps = {
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
};

export const users = pgTable(
  "authen_users",
  {
    id: text().primaryKey(),
    status: text().$type<UserStatus>().notNull(),
    lastAuthenticatedAt: timestamp("last_authenticated_at", {
      withTimezone: true,
    }),
    disabledAt: timestamp("disabled_at", { withTimezone: true }),
    ...timestamps,
  },
  (t) => [
    check(
      "authen_users_status_check",
      sql`${t.status} IN ('pending','active','suspended','disabled')`,
    ),
  ],
);

export const providerInstances = pgTable("authen_provider_instances", {
  id: text().primaryKey(),
  type: text().notNull(),
  enabled: boolean().notNull(),
  configurationRef: text("configuration_ref").notNull(),
  metadata: jsonb().$type<Metadata>().notNull().default({}),
  ...timestamps,
});

export const identities = pgTable(
  "authen_identities",
  {
    id: text().primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    providerInstanceId: text("provider_instance_id")
      .notNull()
      .references(() => providerInstances.id),
    providerSubject: text("provider_subject").notNull(),
    status: text().$type<IdentityStatus>().notNull(),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    metadata: jsonb().$type<Metadata>().notNull().default({}),
    ...timestamps,
  },
  (t) => [
    unique("authen_identities_provider_subject_key").on(
      t.providerInstanceId,
      t.providerSubject,
    ),
    index("authen_identities_user_id_idx").on(t.userId),
    check(
      "authen_identities_status_check",
      sql`${t.status} IN ('active','disabled','unlinked')`,
    ),
  ],
);

export const profiles = pgTable("authen_profiles", {
  userId: text("user_id")
    .primaryKey()
    .references(() => users.id),
  displayName: text("display_name"),
  givenName: text("given_name"),
  familyName: text("family_name"),
  avatarUrl: text("avatar_url"),
  locale: text(),
  timezone: text(),
  ...timestamps,
});

export const credentials = pgTable(
  "authen_credentials",
  {
    id: text().primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    identityId: text("identity_id").references(() => identities.id),
    providerInstanceId: text("provider_instance_id")
      .notNull()
      .references(() => providerInstances.id),
    type: text().notNull(),
    status: text().$type<CredentialStatus>().notNull(),
    secretRef: text("secret_ref"),
    publicData: jsonb("public_data").$type<Metadata>().notNull().default({}),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    ...timestamps,
  },
  (t) => [
    index("authen_credentials_user_id_idx").on(t.userId),
    check(
      "authen_credentials_status_check",
      sql`${t.status} IN ('active','revoked','expired')`,
    ),
  ],
);

export const sessions = pgTable(
  "authen_sessions",
  {
    id: text().primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    status: text().$type<SessionStatus>().notNull(),
    context: jsonb().$type<AuthenticationContext>().notNull(),
    device: jsonb().$type<DeviceInfo>().notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
    }).notNull(),
    lastActivityAt: timestamp("last_activity_at", {
      withTimezone: true,
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    absoluteExpiresAt: timestamp("absolute_expires_at", {
      withTimezone: true,
    }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    revocationReason: text("revocation_reason"),
    ...timestamps,
  },
  (t) => [
    index("authen_sessions_user_id_idx").on(t.userId),
    check(
      "authen_sessions_status_check",
      sql`${t.status} IN ('active','revoked','expired')`,
    ),
  ],
);

export const authenticationTransactions = pgTable(
  "authen_authentication_transactions",
  {
    id: text().primaryKey(),
    providerInstanceId: text("provider_instance_id")
      .notNull()
      .references(() => providerInstances.id),
    clientId: text("client_id"),
    userId: text("user_id").references(() => users.id),
    purpose: text().$type<TransactionPurpose>().notNull(),
    status: text().$type<TransactionStatus>().notNull(),
    currentStep: text("current_step").notNull(),
    attempts: integer().notNull(),
    maxAttempts: integer("max_attempts").notNull(),
    stateHash: text("state_hash"),
    challengeRef: text("challenge_ref"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    metadata: jsonb().$type<Metadata>().notNull().default({}),
    ...timestamps,
  },
  (t) => [index("authen_auth_transactions_user_id_idx").on(t.userId)],
);

export const tokenFamilies = pgTable(
  "authen_token_families",
  {
    id: text().primaryKey(),
    sessionId: text("session_id")
      .notNull()
      .references(() => sessions.id),
    clientId: text("client_id").notNull(),
    scopes: jsonb().$type<string[]>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    revocationReason: text("revocation_reason"),
  },
  (t) => [index("authen_token_families_session_id_idx").on(t.sessionId)],
);

export const refreshTokens = pgTable(
  "authen_refresh_tokens",
  {
    id: text().primaryKey(),
    familyId: text("family_id")
      .notNull()
      .references(() => tokenFamilies.id),
    tokenHash: text("token_hash").notNull().unique(),
    issuedAt: timestamp("issued_at", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    replacedByTokenId: text("replaced_by_token_id"),
  },
  (t) => [index("authen_refresh_tokens_family_id_idx").on(t.familyId)],
);

export const challenges = pgTable(
  "authen_challenges",
  {
    key: text().primaryKey(),
    value: text().notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (t) => [index("authen_challenges_expires_at_idx").on(t.expiresAt)],
);

export const oauthClients = pgTable("authen_oauth_clients", {
  id: text().primaryKey(),
  redirectUris: jsonb("redirect_uris").$type<string[]>().notNull(),
  allowedScopes: jsonb("allowed_scopes").$type<string[]>().notNull(),
  ...timestamps,
});

export const authorizationCodes = pgTable(
  "authen_authorization_codes",
  {
    codeHash: text("code_hash").primaryKey(),
    clientId: text("client_id")
      .notNull()
      .references(() => oauthClients.id),
    userId: text("user_id")
      .notNull()
      .references(() => users.id),
    sessionId: text("session_id")
      .notNull()
      .references(() => sessions.id),
    redirectUri: text("redirect_uri").notNull(),
    scopes: jsonb().$type<string[]>().notNull(),
    codeChallenge: text("code_challenge").notNull(),
    nonce: text(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (t) => [index("authen_authorization_codes_expires_at_idx").on(t.expiresAt)],
);

export const schema = {
  users,
  providerInstances,
  identities,
  profiles,
  credentials,
  sessions,
  authenticationTransactions,
  tokenFamilies,
  refreshTokens,
  challenges,
  oauthClients,
  authorizationCodes,
};
