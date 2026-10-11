import type { Identity } from "../../domain/user/identity.js";
import type {
  IdentityId,
  ProviderInstanceId,
  UserId,
} from "../../shared/types.js";

export interface IdentityRepository {
  findById(id: IdentityId): Promise<Identity | null>;

  /**
   * La clé d'unicité est `(providerInstanceId, providerSubject)`, jamais
   * l'email. L'index correspondant est obligatoire dans le stockage.
   */
  findByProviderSubject(
    instanceId: ProviderInstanceId,
    subject: string,
  ): Promise<Identity | null>;

  findByUserId(userId: UserId): Promise<Identity[]>;

  /**
   * Doit lever `AuthenticationError("identity_conflict")` si la contrainte
   * d'unicité (instance, subject) est violée (deux requêtes simultanées).
   */
  create(identity: Identity): Promise<void>;

  update(identity: Identity): Promise<void>;
}
