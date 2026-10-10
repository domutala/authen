import type { Identity } from "../domain/user/identity.js";
import type { User } from "../domain/user/user.js";
import type { VerifiedProviderIdentity } from "../ports/providers/authentication-provider.js";
import { AuthenticationError } from "../shared/errors.js";
import type { IdentityService } from "./identity.service.js";
import type { UserService } from "./user.service.js";

/**
 * Résultat de la recherche d'une identité vérifiée :
 * - existing : identité connue et active, avec son utilisateur
 * - inactive : identité connue mais désactivée ou détachée
 * - unknown  : première fois qu'on voit ce (provider, subject)
 */
export type IdentityResolution =
  | { kind: "existing"; identity: Identity; user: User }
  | { kind: "inactive"; identity: Identity }
  | { kind: "unknown" };

export interface IdentityResolverDeps {
  identities: IdentityService;
  users: UserService;
}

/**
 * Répond à une seule question : "à quel utilisateur appartient cette identité ?"
 * Il ne crée rien et ne décide pas de la politique (inscription, liaison...).
 *
 * La recherche se fait par (instance du provider, subject vérifié).
 * On ne rapproche JAMAIS deux comptes sur l'email seul : ce serait une faille
 * de prise de contrôle de compte.
 */
export class IdentityResolver {
  private readonly deps: IdentityResolverDeps;

  constructor(deps: IdentityResolverDeps) {
    this.deps = deps;
  }

  async resolve(verified: VerifiedProviderIdentity): Promise<IdentityResolution> {
    const identity = await this.deps.identities.findByProviderSubject(
      verified.providerInstanceId,
      verified.subject,
    );

    if (!identity) return { kind: "unknown" };
    if (identity.status !== "active") return { kind: "inactive", identity };

    const user = await this.deps.users.findById(identity.userId);
    if (!user) {
      // Identité orpheline : incohérence de données, pas un cas métier normal.
      throw new AuthenticationError(
        "user_not_found",
        `Identité ${identity.id} sans utilisateur`,
      );
    }

    return { kind: "existing", identity, user };
  }
}
