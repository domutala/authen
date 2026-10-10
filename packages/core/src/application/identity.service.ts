import type { Identity } from "../domain/user/identity.js";
import type { Clock } from "../ports/clock.js";
import type { EventPublisher } from "../ports/event-publisher.js";
import type { IdGenerator } from "../ports/id-generator.js";
import type { IdentityRepository } from "../ports/repositories/identity-repository.js";
import type { VerifiedProviderIdentity } from "../ports/providers/authentication-provider.js";
import { AuthenticationError } from "../shared/errors.js";
import type {
  EventId,
  IdentityId,
  ProviderInstanceId,
  UserId,
} from "../shared/types.js";
import { SecurityEventType } from "./security-events.js";

export interface IdentityServiceDeps {
  identities: IdentityRepository;
  events: EventPublisher;
  ids: IdGenerator;
  clock: Clock;
}

/**
 * Gère les identités (lien entre un User Authen et un compte chez un provider).
 * Il ne crée pas de tokens et ne décide pas des politiques de sécurité.
 */
export class IdentityService {
  private readonly deps: IdentityServiceDeps;

  constructor(deps: IdentityServiceDeps) {
    this.deps = deps;
  }

  /** Recherche par (instance, subject) : jamais par email seul. */
  findByProviderSubject(
    instanceId: ProviderInstanceId,
    subject: string,
  ): Promise<Identity | null> {
    return this.deps.identities.findByProviderSubject(instanceId, subject);
  }

  listByUser(userId: UserId): Promise<Identity[]> {
    return this.deps.identities.findByUserId(userId);
  }

  /** Rattache une identité vérifiée par un provider à un utilisateur. */
  async link(
    userId: UserId,
    verified: VerifiedProviderIdentity,
  ): Promise<Identity> {
    const now = this.deps.clock.now();

    const identity: Identity = {
      id: this.deps.ids.generate<IdentityId>(),
      userId,
      providerInstanceId: verified.providerInstanceId,
      providerSubject: verified.subject,
      status: "active",
      verifiedAt: verified.authenticatedAt,
      lastUsedAt: now,
      metadata: {},
      createdAt: now,
      updatedAt: now,
    };

    // Lève "identity_conflict" si (instance, subject) existe déjà.
    await this.deps.identities.create(identity);

    await this.publish(SecurityEventType.IdentityLinked, userId, {
      identityId: identity.id,
      providerInstanceId: identity.providerInstanceId,
    });

    return identity;
  }

  /**
   * Détache une identité. On refuse de supprimer la dernière identité active :
   * l'utilisateur ne pourrait plus se connecter.
   */
  async unlink(identityId: IdentityId): Promise<Identity> {
    const identity = await this.deps.identities.findById(identityId);
    if (!identity) {
      throw new AuthenticationError("identity_not_found", `Identity ${identityId}`);
    }
    if (identity.status === "unlinked") return identity;

    if (identity.status === "active") {
      const all = await this.deps.identities.findByUserId(identity.userId);
      const activeCount = all.filter((i) => i.status === "active").length;
      if (activeCount <= 1) {
        throw new AuthenticationError(
          "last_identity",
          "Impossible de détacher la dernière identité active",
        );
      }
    }

    const updated: Identity = {
      ...identity,
      status: "unlinked",
      updatedAt: this.deps.clock.now(),
    };
    await this.deps.identities.update(updated);

    await this.publish(SecurityEventType.IdentityUnlinked, identity.userId, {
      identityId: identity.id,
    });

    return updated;
  }

  /** Met à jour la date de dernier usage après une connexion réussie. */
  async markUsed(identity: Identity): Promise<Identity> {
    const now = this.deps.clock.now();
    const updated: Identity = { ...identity, lastUsedAt: now, updatedAt: now };
    await this.deps.identities.update(updated);
    return updated;
  }

  private publish(
    eventType: SecurityEventType,
    userId: UserId,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    return this.deps.events.publish({
      id: this.deps.ids.generate<EventId>(),
      userId,
      eventType,
      occurredAt: this.deps.clock.now(),
      metadata,
    });
  }
}
