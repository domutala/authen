import type {
  AuthenticationContext,
  AuthenticationTransaction,
  TransactionPurpose,
} from "../domain/index.js";
import type { Clock } from "../ports/clock.js";
import type { EventPublisher } from "../ports/event-publisher.js";
import type { IdGenerator } from "../ports/id-generator.js";
import type {
  AuthStep,
  ProviderContext,
  VerifiedProviderIdentity,
} from "../ports/providers/authentication-provider.js";
import type { AuthenticationProvider } from "../ports/providers/authentication-provider.js";
import type { ProviderRegistry } from "../ports/providers/provider-registry.js";
import type { ProviderInstanceRepository } from "../ports/repositories/provider-instance-repository.js";
import type { TransactionRepository } from "../ports/repositories/transaction-repository.js";
import type { TransactionRunner } from "../ports/transaction-runner.js";
import { AuthenticationError } from "../shared/errors.js";
import type {
  ClientId,
  EventId,
  Metadata,
  ProviderInstanceId,
  TransactionId,
  UserId,
} from "../shared/types.js";
import type {
  IdentityResolution,
  IdentityResolver,
} from "./identity-resolver.js";
import type { IdentityService } from "./identity.service.js";
import type { ProfileService } from "./profile.service.js";
import { SecurityEventType } from "./security-events.js";
import type { SecurityPolicyService } from "./security-policy.service.js";
import type { UserService } from "./user.service.js";

/* -------------------------------------------------------------------------- */
/*  Types publics                                                             */
/* -------------------------------------------------------------------------- */

/** Demande de démarrage d'une authentification. */
export interface BeginAuthenticationRequest {
  providerInstanceId: ProviderInstanceId;
  clientId: ClientId | null;
  purpose: TransactionPurpose;
  /** Obligatoire pour "link_identity" et "step_up" (l'utilisateur est déjà connu). */
  userId: UserId | null;
  /** Données brutes envoyées au provider (validées par le provider lui-même). */
  input: unknown;
}

/**
 * Résultat renvoyé à l'appelant (API HTTP, OIDC...).
 * Chaque variante contient le `transactionId` : c'est lui que le client
 * renvoie ensuite à `continue()`.
 *
 * Le core ne crée PAS de session ici : c'est le rôle du SessionService (étape 04),
 * qui utilisera `userId` et `context` d'un résultat "authenticated".
 */
export type AuthResult =
  | {
      type: "authenticated";
      transactionId: TransactionId;
      userId: UserId;
      isNewUser: boolean;
      context: AuthenticationContext;
    }
  | {
      type: "challenge";
      transactionId: TransactionId;
      challengeType: string;
      expiresAt: Date;
      publicData: Metadata;
    }
  | {
      type: "redirect";
      transactionId: TransactionId;
      url: string;
    }
  | {
      type: "rejected";
      transactionId: TransactionId;
      code: string;
      retryable: boolean;
    };

export interface AuthenticationOptions {
  /** Durée de vie d'une transaction (10 min par défaut). */
  transactionTtlMs: number;
  /** Nombre maximal de tentatives refusées avant échec définitif. */
  maxAttempts: number;
}

export interface AuthenticationServiceDeps {
  providers: ProviderRegistry;
  providerInstances: ProviderInstanceRepository;
  transactions: TransactionRepository;
  users: UserService;
  identities: IdentityService;
  profiles: ProfileService;
  resolver: IdentityResolver;
  policy: SecurityPolicyService;
  events: EventPublisher;
  ids: IdGenerator;
  clock: Clock;
  unitOfWork: TransactionRunner;
  options?: Partial<AuthenticationOptions>;
}

/* -------------------------------------------------------------------------- */
/*  Types internes                                                            */
/* -------------------------------------------------------------------------- */

/** Résultat de la règle métier appliquée à l'identité vérifiée. */
type ApplyOutcome =
  | { kind: "authenticated"; userId: UserId; isNewUser: boolean }
  | { kind: "rejected"; code: string };

type Phase = "begin" | "continue";

const DEFAULT_OPTIONS: AuthenticationOptions = {
  transactionTtlMs: 10 * 60 * 1000,
  maxAttempts: 5,
};

/* -------------------------------------------------------------------------- */
/*  Service                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Chef d'orchestre de la connexion.
 *
 * Il enchaîne : transaction -> provider -> résolution de l'identité -> règles
 * de sécurité -> résultat. Il n'implémente aucun provider (Google, OTP...) et
 * ne connaît ni HTTP, ni base de données : tout passe par les ports.
 */
export class AuthenticationService {
  private readonly d: AuthenticationServiceDeps;
  private readonly options: AuthenticationOptions;

  constructor(deps: AuthenticationServiceDeps) {
    this.d = deps;
    this.options = { ...DEFAULT_OPTIONS, ...deps.options };
    assertPositiveDuration(
      "authentication.transactionTtlMs",
      this.options.transactionTtlMs,
    );
    assertPositiveInteger(
      "authentication.maxAttempts",
      this.options.maxAttempts,
    );
  }

  /** Démarre une authentification : crée la transaction puis appelle `provider.begin`. */
  async begin(request: BeginAuthenticationRequest): Promise<AuthResult> {
    this.assertUserProvidedWhenRequired(request);

    const provider = await this.loadProvider(request.providerInstanceId);
    const now = this.d.clock.now();

    const transaction: AuthenticationTransaction = {
      id: this.d.ids.generate<TransactionId>(),
      providerInstanceId: request.providerInstanceId,
      clientId: request.clientId,
      userId: request.userId,
      purpose: request.purpose,
      status: "pending",
      currentStep: "begin",
      attempts: 0,
      maxAttempts: this.options.maxAttempts,
      stateHash: null,
      challengeRef: null,
      expiresAt: new Date(now.getTime() + this.options.transactionTtlMs),
      completedAt: null,
      metadata: {},
      createdAt: now,
      updatedAt: now,
    };
    await this.d.transactions.create(transaction);

    const step = await provider.begin(
      this.toProviderContext(transaction),
      request.input,
    );
    return this.handleStep(transaction, step, "begin");
  }

  /** Poursuit une authentification en cours (code OTP, callback OIDC...). */
  async continue(
    transactionId: TransactionId,
    input: unknown,
  ): Promise<AuthResult> {
    const transaction = await this.requireTransaction(transactionId);

    if (transaction.status !== "pending" && transaction.status !== "waiting") {
      throw new AuthenticationError(
        "transaction_not_active",
        `Transaction ${transactionId} : ${transaction.status}`,
      );
    }

    if (transaction.expiresAt.getTime() <= this.d.clock.now().getTime()) {
      await this.save({ ...transaction, status: "expired" });
      throw new AuthenticationError("transaction_expired");
    }

    const provider = await this.loadProvider(transaction.providerInstanceId);
    const step = await provider.continue(
      this.toProviderContext(transaction),
      input,
    );
    return this.handleStep(transaction, step, "continue");
  }

  /** Annule une transaction en cours (sans effet si elle est déjà terminée). */
  async cancel(transactionId: TransactionId): Promise<void> {
    const transaction = await this.requireTransaction(transactionId);
    if (transaction.status === "pending" || transaction.status === "waiting") {
      await this.save({ ...transaction, status: "cancelled" });
    }
  }

  /* ------------------------------------------------------------------------ */
  /*  Traitement de la réponse du provider                                    */
  /* ------------------------------------------------------------------------ */

  private async handleStep(
    transaction: AuthenticationTransaction,
    step: AuthStep,
    phase: Phase,
  ): Promise<AuthResult> {
    switch (step.type) {
      case "authenticated":
        return this.finalize(transaction, step.identity);

      case "challenge": {
        // Le challenge ne doit pas vivre plus longtemps que la transaction.
        const expiresAt = new Date(
          Math.min(transaction.expiresAt.getTime(), step.expiresAt.getTime()),
        );
        const updated = await this.save({
          ...transaction,
          status: "waiting",
          currentStep: step.challengeType,
          expiresAt,
        });
        return {
          type: "challenge",
          transactionId: updated.id,
          challengeType: step.challengeType,
          expiresAt: updated.expiresAt,
          publicData: step.publicData,
        };
      }

      case "redirect": {
        const updated = await this.save({
          ...transaction,
          status: "waiting",
          currentStep: "redirect",
        });
        return { type: "redirect", transactionId: updated.id, url: step.url };
      }

      case "rejected":
        return this.reject(transaction, step.code, step.retryable, phase);
    }
  }

  /**
   * Enregistre un refus. La transaction échoue définitivement si :
   * - le refus arrive dès `begin`,
   * - le provider indique que ce n'est pas réessayable,
   * - le nombre maximal de tentatives est atteint.
   */
  private async reject(
    transaction: AuthenticationTransaction,
    code: string,
    retryable: boolean,
    phase: Phase,
  ): Promise<AuthResult> {
    const attempts = transaction.attempts + 1;
    const final =
      phase === "begin" || !retryable || attempts >= transaction.maxAttempts;

    await this.save({
      ...transaction,
      attempts,
      status: final ? "failed" : "waiting",
    });

    await this.publish(
      SecurityEventType.AuthenticationFailed,
      transaction.userId,
      {
        transactionId: transaction.id,
        providerInstanceId: transaction.providerInstanceId,
        purpose: transaction.purpose,
        code,
      },
    );

    return {
      type: "rejected",
      transactionId: transaction.id,
      code,
      retryable: !final,
    };
  }

  /* ------------------------------------------------------------------------ */
  /*  Identité prouvée -> utilisateur                                         */
  /* ------------------------------------------------------------------------ */

  private async finalize(
    transaction: AuthenticationTransaction,
    verified: VerifiedProviderIdentity,
  ): Promise<AuthResult> {
    // Un provider ne doit jamais prouver une identité d'une autre instance.
    if (verified.providerInstanceId !== transaction.providerInstanceId) {
      await this.save({ ...transaction, status: "failed" });
      throw new AuthenticationError(
        "invalid_provider_response",
        "L'identité vérifiée ne correspond pas à l'instance de la transaction",
      );
    }

    const outcome = await this.applyWithRetry(transaction, verified);

    if (outcome.kind === "rejected") {
      return this.reject(transaction, outcome.code, false, "continue");
    }

    const now = this.d.clock.now();
    await this.save({
      ...transaction,
      status: "completed",
      userId: outcome.userId,
      completedAt: now,
    });

    if (outcome.isNewUser) {
      await this.publish(SecurityEventType.UserRegistered, outcome.userId, {
        transactionId: transaction.id,
        providerInstanceId: transaction.providerInstanceId,
      });
    }
    await this.publish(
      SecurityEventType.AuthenticationSucceeded,
      outcome.userId,
      {
        transactionId: transaction.id,
        providerInstanceId: transaction.providerInstanceId,
        purpose: transaction.purpose,
      },
    );

    return {
      type: "authenticated",
      transactionId: transaction.id,
      userId: outcome.userId,
      isNewUser: outcome.isNewUser,
      context: {
        providerInstanceId: verified.providerInstanceId,
        methods: verified.methods,
        assuranceLevel: this.d.policy.assuranceLevelFor(verified.methods),
        authenticatedAt: verified.authenticatedAt,
        verifiedAt: now,
      },
    };
  }

  /**
   * Exécute les règles métier dans une transaction de base de données.
   * Si deux requêtes créent la même identité en même temps, la base lève
   * "identity_conflict" : on réessaie une fois, et la 2e passe retrouve l'identité.
   */
  private async applyWithRetry(
    transaction: AuthenticationTransaction,
    verified: VerifiedProviderIdentity,
  ): Promise<ApplyOutcome> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.d.unitOfWork.run(() =>
          this.applyIdentity(transaction, verified),
        );
      } catch (error) {
        const isConflict =
          error instanceof AuthenticationError &&
          error.code === "identity_conflict";
        if (!isConflict || attempt >= 1) throw error;
      }
    }
  }

  /** Aiguillage selon l'objectif de la transaction. */
  private async applyIdentity(
    transaction: AuthenticationTransaction,
    verified: VerifiedProviderIdentity,
  ): Promise<ApplyOutcome> {
    const resolution = await this.d.resolver.resolve(verified);

    switch (transaction.purpose) {
      case "sign_in":
        return this.applySignIn(verified, resolution, true);
      case "recovery":
        // Même logique qu'une connexion, mais sans création de compte.
        return this.applySignIn(verified, resolution, false);
      case "sign_up":
        return this.applySignUp(verified, resolution);
      case "link_identity":
        return this.applyLink(transaction, verified, resolution);
      case "step_up":
        return this.applyStepUp(transaction, resolution);
    }
  }

  /** Connexion : identité connue -> on connecte ; inconnue -> inscription si la politique l'autorise. */
  private async applySignIn(
    verified: VerifiedProviderIdentity,
    resolution: IdentityResolution,
    mayRegister: boolean,
  ): Promise<ApplyOutcome> {
    switch (resolution.kind) {
      case "inactive":
        return rejected("identity_disabled");

      case "existing": {
        const { identity, user } = resolution;
        if (!this.d.policy.canAuthenticate(user)) {
          return rejected("account_not_allowed");
        }
        await this.d.identities.markUsed(identity);
        await this.d.users.markAuthenticated(user);
        return { kind: "authenticated", userId: user.id, isNewUser: false };
      }

      case "unknown":
        if (!mayRegister) return rejected("identity_not_found");
        if (!this.d.policy.canAutoRegisterOnSignIn(verified)) {
          return rejected("registration_required");
        }
        return this.register(verified);
    }
  }

  /** Inscription explicite : l'identité ne doit pas déjà exister. */
  private async applySignUp(
    verified: VerifiedProviderIdentity,
    resolution: IdentityResolution,
  ): Promise<ApplyOutcome> {
    if (resolution.kind !== "unknown") {
      return rejected("identity_already_registered");
    }
    if (!this.d.policy.canRegister(verified)) {
      return rejected("registration_closed");
    }
    return this.register(verified);
  }

  /** Ajoute une identité à un utilisateur déjà connecté. */
  private async applyLink(
    transaction: AuthenticationTransaction,
    verified: VerifiedProviderIdentity,
    resolution: IdentityResolution,
  ): Promise<ApplyOutcome> {
    const user = await this.d.users.findById(this.requireUserId(transaction));
    if (!user) return rejected("user_not_found");

    if (!this.d.policy.canLinkIdentity(user, verified)) {
      return rejected("link_not_allowed");
    }

    switch (resolution.kind) {
      case "inactive":
        return rejected("identity_disabled");

      case "existing":
        // Déjà liée au même utilisateur : opération idempotente.
        if (resolution.identity.userId !== user.id) {
          return rejected("identity_already_linked");
        }
        await this.d.identities.markUsed(resolution.identity);
        return { kind: "authenticated", userId: user.id, isNewUser: false };

      case "unknown":
        await this.d.identities.link(user.id, verified);
        return { kind: "authenticated", userId: user.id, isNewUser: false };
    }
  }

  /** Réauthentification : l'identité prouvée doit appartenir à l'utilisateur déjà connecté. */
  private async applyStepUp(
    transaction: AuthenticationTransaction,
    resolution: IdentityResolution,
  ): Promise<ApplyOutcome> {
    const userId = this.requireUserId(transaction);

    if (
      resolution.kind !== "existing" ||
      resolution.identity.userId !== userId
    ) {
      return rejected("identity_mismatch");
    }
    if (!this.d.policy.canAuthenticate(resolution.user)) {
      return rejected("account_not_allowed");
    }

    await this.d.identities.markUsed(resolution.identity);
    return { kind: "authenticated", userId, isNewUser: false };
  }

  /** Crée l'utilisateur, son identité et son profil (dans la même transaction DB). */
  private async register(
    verified: VerifiedProviderIdentity,
  ): Promise<ApplyOutcome> {
    const user = await this.d.users.create();
    await this.d.identities.link(user.id, verified);
    await this.d.profiles.createFromClaims(user.id, verified.claims);
    await this.d.users.markAuthenticated(user);

    // Les emails / téléphones fournis par le provider ne deviennent PAS
    // automatiquement des contacts vérifiés : leur niveau de confiance
    // doit être décidé par une politique dédiée.
    return { kind: "authenticated", userId: user.id, isNewUser: true };
  }

  /* ------------------------------------------------------------------------ */
  /*  Utilitaires                                                             */
  /* ------------------------------------------------------------------------ */

  /** Charge l'instance, vérifie qu'elle est active, puis retrouve son provider. */
  private async loadProvider(
    instanceId: ProviderInstanceId,
  ): Promise<AuthenticationProvider> {
    const instance = await this.d.providerInstances.findById(instanceId);
    if (!instance) {
      throw new AuthenticationError(
        "provider_not_found",
        `Instance ${instanceId}`,
      );
    }
    if (!instance.enabled) {
      throw new AuthenticationError(
        "provider_disabled",
        `Instance ${instanceId}`,
      );
    }
    return this.d.providers.resolve(instanceId);
  }

  private async requireTransaction(
    id: TransactionId,
  ): Promise<AuthenticationTransaction> {
    const transaction = await this.d.transactions.findById(id);
    if (!transaction) {
      throw new AuthenticationError(
        "transaction_not_found",
        `Transaction ${id}`,
      );
    }
    return transaction;
  }

  private assertUserProvidedWhenRequired(
    request: BeginAuthenticationRequest,
  ): void {
    const needsUser =
      request.purpose === "link_identity" || request.purpose === "step_up";
    if (needsUser && request.userId === null) {
      throw new AuthenticationError(
        "user_required",
        `Le purpose "${request.purpose}" exige un userId`,
      );
    }
  }

  private requireUserId(transaction: AuthenticationTransaction): UserId {
    if (transaction.userId === null) {
      throw new AuthenticationError(
        "user_required",
        `Transaction ${transaction.id}`,
      );
    }
    return transaction.userId;
  }

  private toProviderContext(
    transaction: AuthenticationTransaction,
  ): ProviderContext {
    return {
      transactionId: transaction.id,
      providerInstanceId: transaction.providerInstanceId,
      clientId: transaction.clientId,
      purpose: transaction.purpose,
    };
  }

  private async save(
    transaction: AuthenticationTransaction,
  ): Promise<AuthenticationTransaction> {
    const updated = { ...transaction, updatedAt: this.d.clock.now() };
    await this.d.transactions.update(updated);
    return updated;
  }

  private publish(
    eventType: SecurityEventType,
    userId: UserId | null,
    metadata: Metadata,
  ): Promise<void> {
    return this.d.events.publish({
      id: this.d.ids.generate<EventId>(),
      userId,
      eventType,
      occurredAt: this.d.clock.now(),
      metadata,
    });
  }
}

function rejected(code: string): ApplyOutcome {
  return { kind: "rejected", code };
}

function assertPositiveDuration(name: string, value: number): void {
  if (!Number.isFinite(value) || value <= 0) {
    throw new RangeError(`${name} doit être un nombre fini strictement positif`);
  }
}

function assertPositiveInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${name} doit être un entier strictement positif`);
  }
}
