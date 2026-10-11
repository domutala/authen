import { createMemoryCore } from "@authen/adapter-memory";
import {
  NodeSecureRandom,
  ScryptSecretHasher,
  Sha256TokenDigester,
  SystemClock,
  UuidIdGenerator,
} from "@authen/adapter-memory";
import {
  createPostgresAdapter,
  migratePostgres,
} from "@authen/adapter-postgres";
import {
  AuthenticationService,
  CredentialEnrollmentService,
  DefaultProviderRegistry,
  IdentityResolver,
  IdentityService,
  ProfileService,
  SecurityPolicyService,
  SessionService,
  TokenService,
  UserService,
  type ChallengeStore,
  type Clock,
  type EventPublisher,
  type ProviderInstance,
  type ProviderInstanceId,
  type SecureRandom,
  type TokenDigester,
} from "@authen/core";
import {
  MemoryAuthorizationCodeStore,
  MemoryOAuthClientRegistry,
  type AuthorizationCodeStore,
  type OidcIdTokenSigner,
  type OAuthClient,
  type OAuthClientRegistry,
} from "@authen/protocol-oauth-oidc";
import { randomBytes } from "node:crypto";
import pg from "pg";
import {
  KeyRing,
  MemorySigningKeyStore,
  PostgresSigningKeyStore,
  RingAccessTokenSigner,
  RingIdTokenSigner,
} from "./keys/index.js";
import {
  PostgresAuthorizationCodeStore,
  PostgresOAuthClientRegistry,
} from "./oidc-stores.js";

export interface RuntimeOptions {
  issuer: string;
  databaseUrl?: string | undefined;
  /** Secret qui chiffre les clés de signature en base (requis avec Postgres). */
  signingSecret?: string | undefined;
  /** Rotation automatique de la clé de signature, en jours (défaut 90). */
  keyRotationDays?: number | undefined;
  events: EventPublisher;
}

/** Tout ce dont le serveur HTTP a besoin, quel que soit le stockage choisi. */
export interface Runtime {
  storage: "memory" | "postgres";
  clock: Clock;
  random: SecureRandom;
  digester: TokenDigester;
  challenges: ChallengeStore;
  idTokens: OidcIdTokenSigner;
  keys: KeyRing;
  services: ReturnType<typeof createMemoryCore>["services"];
  clients: OAuthClientRegistry;
  codes: AuthorizationCodeStore;
  ensureProviderInstance(input: {
    id: string;
    type: string;
    enabled?: boolean;
  }): Promise<ProviderInstance>;
  ensureClient(client: OAuthClient): Promise<void>;
  close(): Promise<void>;
}

const MIN_SECRET_LENGTH = 32;

/** Postgres si `DATABASE_URL` est défini, sinon mémoire (développement). */
export async function createRuntime(options: RuntimeOptions): Promise<Runtime> {
  assertIssuer(options.issuer);
  if (
    options.keyRotationDays !== undefined &&
    (!Number.isSafeInteger(options.keyRotationDays) || options.keyRotationDays <= 0)
  ) {
    throw new RangeError("AUTHEN_KEY_ROTATION_DAYS doit être un entier strictement positif");
  }
  return options.databaseUrl
    ? createPostgresRuntime(options, options.databaseUrl)
    : await createMemoryRuntime(options);
}

function assertIssuer(value: string): void {
  let issuer: URL;
  try {
    issuer = new URL(value);
  } catch {
    throw new TypeError("AUTHEN_ISSUER doit être une URL absolue valide");
  }
  if (!/^https?:$/.test(issuer.protocol) || issuer.username || issuer.password) {
    throw new TypeError("AUTHEN_ISSUER doit être une URL HTTP(S) sans identifiants");
  }
  if (issuer.pathname !== "/" || issuer.search || issuer.hash) {
    throw new TypeError("AUTHEN_ISSUER ne doit contenir ni chemin, ni query, ni fragment");
  }
}

async function createMemoryRuntime(options: RuntimeOptions): Promise<Runtime> {
  const clock = new SystemClock();
  const keys = new KeyRing({
    store: new MemorySigningKeyStore(),
    clock,
    encryptionSecret:
      options.signingSecret ?? randomBytes(32).toString("base64url"),
    ...rotation(options),
  });
  await keys.init();

  const core = createMemoryCore({
    clock,
    issuer: options.issuer,
    audience: `${options.issuer}/api`,
    signer: new RingAccessTokenSigner(keys, options.issuer),
  });
  const clients = new MemoryOAuthClientRegistry();

  return {
    storage: "memory",
    clock: core.clock,
    random: core.random,
    digester: core.digester,
    challenges: core.challenges,
    idTokens: new RingIdTokenSigner(keys),
    keys,
    services: core.services,
    clients,
    codes: new MemoryAuthorizationCodeStore(core.clock),
    ensureProviderInstance: (input) => core.addProviderInstance(input),
    async ensureClient(client) {
      clients.register(client);
    },
    async close() {},
  };
}

function rotation(options: RuntimeOptions) {
  return options.keyRotationDays
    ? { rotationIntervalMs: options.keyRotationDays * 24 * 60 * 60 * 1000 }
    : {};
}

async function createPostgresRuntime(
  options: RuntimeOptions,
  databaseUrl: string,
): Promise<Runtime> {
  // Sans secret stable, les clés de signature chiffrées en base seraient illisibles au redémarrage.
  if (
    !options.signingSecret ||
    options.signingSecret.length < MIN_SECRET_LENGTH
  ) {
    throw new Error(
      `AUTHEN_SIGNING_SECRET est requis avec DATABASE_URL (${MIN_SECRET_LENGTH} caractères minimum)`,
    );
  }

  const pool = new pg.Pool({ connectionString: databaseUrl });
  try {
    const clock = new SystemClock();
    const adapter = createPostgresAdapter(pool, { clock });
    await migratePostgres(adapter.database);

    const { repositories, unitOfWork, challenges } = adapter;
    const ids = new UuidIdGenerator();
    const random = new NodeSecureRandom();
    const digester = new Sha256TokenDigester();
    const keys = new KeyRing({
      store: new PostgresSigningKeyStore(adapter.database),
      clock,
      encryptionSecret: options.signingSecret,
      ...rotation(options),
    });
    await keys.init();
    const signer = new RingAccessTokenSigner(keys, options.issuer);
    const events = options.events;

    const users = new UserService({ users: repositories.users, ids, clock });
    const profiles = new ProfileService({
      profiles: repositories.profiles,
      clock,
    });
    const identities = new IdentityService({
      identities: repositories.identities,
      events,
      ids,
      clock,
    });
    const resolver = new IdentityResolver({ identities, users });
    const policy = new SecurityPolicyService({});
    const providers = new DefaultProviderRegistry({
      instances: repositories.providerInstances,
    });
    const auth = new AuthenticationService({
      providers,
      providerInstances: repositories.providerInstances,
      transactions: repositories.transactions,
      users,
      identities,
      profiles,
      resolver,
      policy,
      events,
      ids,
      clock,
      unitOfWork,
      options: {},
    });
    const enrollment = new CredentialEnrollmentService({
      providers,
      providerInstances: repositories.providerInstances,
      transactions: repositories.transactions,
      policy,
      clock,
    });
    const sessions = new SessionService({
      sessions: repositories.sessions,
      events,
      ids,
      clock,
      options: {},
    });
    const tokens = new TokenService({
      signer,
      digester,
      random,
      families: repositories.tokenFamilies,
      refreshTokens: repositories.refreshTokens,
      sessions,
      events,
      ids,
      clock,
      unitOfWork,
      options: { issuer: options.issuer, audience: `${options.issuer}/api` },
    });

    const clients = new PostgresOAuthClientRegistry(adapter.database, clock);

    return {
      storage: "postgres",
      clock,
      random,
      digester,
      challenges,
      idTokens: new RingIdTokenSigner(keys),
      keys,
      services: {
        users,
        profiles,
        identities,
        resolver,
        policy,
        providers,
        auth,
        enrollment,
        sessions,
        tokens,
      },
      clients,
      codes: new PostgresAuthorizationCodeStore(adapter.database, clock),
      async ensureProviderInstance(input) {
        const now = clock.now();
        const id = input.id as ProviderInstanceId;
        const existing = await repositories.providerInstances.findById(id);
        if (existing) {
          const updated: ProviderInstance = {
            ...existing,
            type: input.type,
            enabled: input.enabled ?? true,
            updatedAt: now,
          };
          await repositories.providerInstances.update(updated);
          return updated;
        }
        const created: ProviderInstance = {
          id,
          type: input.type,
          enabled: input.enabled ?? true,
          configurationRef: `postgres:${input.id}`,
          metadata: {},
          createdAt: now,
          updatedAt: now,
        };
        await repositories.providerInstances.create(created);
        return created;
      },
      ensureClient: (client) => clients.upsert(client),
      close: () => pool.end(),
    };
  } catch (error) {
    await pool.end();
    throw error;
  }
}
