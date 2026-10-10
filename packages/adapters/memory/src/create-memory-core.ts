import {
  AuthenticationService,
  DefaultProviderRegistry,
  IdentityResolver,
  IdentityService,
  ProfileService,
  SecurityPolicyService,
  SessionService,
  TokenService,
  UserService,
  type AuthenticationOptions,
  type Clock,
  type ProviderInstance,
  type SecurityPolicyOptions,
  type SessionOptions,
  type TokenServiceOptions,
} from "@authen/core";
import {
  HmacTokenSigner,
  NodeSecureRandom,
  ScryptSecretHasher,
  Sha256TokenDigester,
} from "./dev-crypto.js";
import { MemoryDatabase } from "./database.js";
import {
  MemoryChallengeStore,
  MemoryEventPublisher,
  MemoryTransactionRunner,
  SystemClock,
  UuidIdGenerator,
} from "./infrastructure.js";
import {
  MemoryCredentialRepository,
  MemoryIdentityRepository,
  MemoryProfileRepository,
  MemoryProviderInstanceRepository,
  MemoryRefreshTokenRepository,
  MemorySessionRepository,
  MemoryTokenFamilyRepository,
  MemoryTransactionRepository,
  MemoryUserRepository,
} from "./repositories.js";

export interface MemoryCoreOptions {
  /** Horloge à utiliser (`ManualClock` pour tester les expirations). */
  clock?: Clock;
  issuer?: string;
  audience?: string;
  /** Secret de signature des access tokens (aléatoire par défaut). */
  signingSecret?: string;
  security?: Partial<SecurityPolicyOptions>;
  authentication?: Partial<AuthenticationOptions>;
  session?: Partial<SessionOptions>;
  token?: Partial<Omit<TokenServiceOptions, "issuer" | "audience">>;
}

export interface NewProviderInstance {
  id: string;
  type: string;
  enabled?: boolean;
}

/**
 * Assemble le core complet avec des adaptateurs en mémoire : aucune base de
 * données, aucun service externe. Pratique pour tester les flux de bout en
 * bout, ou pour développer un provider.
 *
 * C'est aussi un exemple de "composition root" : la seule place qui connaît à
 * la fois les services du core et leurs implémentations concrètes.
 */
export function createMemoryCore(options: MemoryCoreOptions = {}) {
  const db = new MemoryDatabase();
  const clock = options.clock ?? new SystemClock();
  const ids = new UuidIdGenerator();
  const events = new MemoryEventPublisher();
  const challenges = new MemoryChallengeStore(clock);
  const unitOfWork = new MemoryTransactionRunner(db);

  const random = new NodeSecureRandom();
  const digester = new Sha256TokenDigester();
  const hasher = new ScryptSecretHasher();

  const issuer = options.issuer ?? "https://authen.test";
  const audience = options.audience ?? "authen-api";
  const signer = new HmacTokenSigner({
    secret: options.signingSecret ?? random.token(32),
    issuer,
    clock,
  });

  const repositories = {
    users: new MemoryUserRepository(db),
    identities: new MemoryIdentityRepository(db),
    profiles: new MemoryProfileRepository(db),
    credentials: new MemoryCredentialRepository(db),
    sessions: new MemorySessionRepository(db),
    transactions: new MemoryTransactionRepository(db),
    providerInstances: new MemoryProviderInstanceRepository(db),
    tokenFamilies: new MemoryTokenFamilyRepository(db),
    refreshTokens: new MemoryRefreshTokenRepository(db),
  };

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
  const policy = new SecurityPolicyService(options.security ?? {});
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
    options: options.authentication ?? {},
  });

  const sessions = new SessionService({
    sessions: repositories.sessions,
    events,
    ids,
    clock,
    options: options.session ?? {},
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
    options: { issuer, audience, ...options.token },
  });

  /** Déclare une instance de provider (ligne en base) pour les tests. */
  async function addProviderInstance(
    input: NewProviderInstance,
  ): Promise<ProviderInstance> {
    const now = clock.now();
    const instance: ProviderInstance = {
      id: input.id as ProviderInstance["id"],
      type: input.type,
      enabled: input.enabled ?? true,
      configurationRef: `memory:${input.id}`,
      metadata: {},
      createdAt: now,
      updatedAt: now,
    };
    await repositories.providerInstances.save(instance);
    return instance;
  }

  return {
    db,
    clock,
    ids,
    events,
    challenges,
    unitOfWork,
    random,
    digester,
    hasher,
    signer,
    repositories,
    services: {
      users,
      profiles,
      identities,
      resolver,
      policy,
      providers,
      auth,
      sessions,
      tokens,
    },
    addProviderInstance,
  };
}

export type MemoryCore = ReturnType<typeof createMemoryCore>;
