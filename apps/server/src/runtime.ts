import { createMemoryCore } from "@authen/adapter-memory";
import {
  HmacTokenSigner,
  NodeSecureRandom,
  ScryptSecretHasher,
  Sha256TokenDigester,
  SystemClock,
  UuidIdGenerator,
} from "@authen/adapter-memory";
import { createPostgresAdapter, migratePostgres } from "@authen/adapter-postgres";
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
  type OAuthClient,
  type OAuthClientRegistry,
} from "@authen/protocol-oauth-oidc";
import pg from "pg";
import {
  PostgresAuthorizationCodeStore,
  PostgresOAuthClientRegistry,
} from "./oidc-stores.js";

export interface RuntimeOptions {
  issuer: string;
  databaseUrl?: string | undefined;
  signingSecret?: string | undefined;
  events: EventPublisher;
}

/** Tout ce dont le serveur HTTP a besoin, quel que soit le stockage choisi. */
export interface Runtime {
  storage: "memory" | "postgres";
  clock: Clock;
  random: SecureRandom;
  digester: TokenDigester;
  challenges: ChallengeStore;
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
  return options.databaseUrl
    ? createPostgresRuntime(options, options.databaseUrl)
    : createMemoryRuntime(options);
}

function createMemoryRuntime(options: RuntimeOptions): Runtime {
  const core = createMemoryCore({
    issuer: options.issuer,
    audience: `${options.issuer}/api`,
    ...(options.signingSecret ? { signingSecret: options.signingSecret } : {}),
  });
  const clients = new MemoryOAuthClientRegistry();

  return {
    storage: "memory",
    clock: core.clock,
    random: core.random,
    digester: core.digester,
    challenges: core.challenges,
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

async function createPostgresRuntime(
  options: RuntimeOptions,
  databaseUrl: string,
): Promise<Runtime> {
  // Sans secret stable, les access tokens émis avant un redémarrage deviendraient invalides.
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
    const signer = new HmacTokenSigner({
      secret: options.signingSecret,
      issuer: options.issuer,
      clock,
    });
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
