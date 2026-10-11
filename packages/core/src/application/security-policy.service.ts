import type { AuthenticationContext } from "../domain/authentication/auth-context.js";
import type { User } from "../domain/user/user.js";
import type { VerifiedProviderIdentity } from "../ports/providers/authentication-provider.js";

export interface SecurityPolicyOptions {
  /** Autorise la création de nouveaux comptes. */
  allowSelfRegistration: boolean;
  /** Une connexion avec une identité inconnue crée le compte automatiquement. */
  autoRegisterOnSignIn: boolean;
  /** Au-delà de cette durée depuis l'authentification, une action sensible demande une réauthentification. */
  stepUpMaxAgeMs: number;
}

const DEFAULT_OPTIONS: SecurityPolicyOptions = {
  allowSelfRegistration: true,
  autoRegisterOnSignIn: true,
  stepUpMaxAgeMs: 15 * 60 * 1000,
};

/**
 * Regroupe les règles de sécurité : QUI a le droit de faire QUOI.
 * Ce service ne lit ni n'écrit rien : il répond seulement oui / non.
 * Pour changer une règle, on remplace ou on étend cette classe, pas l'orchestration.
 */
export class SecurityPolicyService {
  private readonly options: SecurityPolicyOptions;

  constructor(options: Partial<SecurityPolicyOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    if (
      !Number.isFinite(this.options.stepUpMaxAgeMs) ||
      this.options.stepUpMaxAgeMs < 0
    ) {
      throw new RangeError(
        "security.stepUpMaxAgeMs doit être un nombre fini positif ou nul",
      );
    }
  }

  /** Seul un compte actif peut se connecter. */
  canAuthenticate(user: User): boolean {
    return user.status === "active";
  }

  /** Inscription explicite (purpose "sign_up"). */
  canRegister(_identity: VerifiedProviderIdentity): boolean {
    return this.options.allowSelfRegistration;
  }

  /** Inscription implicite lors d'un "sign_in" avec une identité inconnue. */
  canAutoRegisterOnSignIn(identity: VerifiedProviderIdentity): boolean {
    return this.canRegister(identity) && this.options.autoRegisterOnSignIn;
  }

  /** Un compte non actif ne peut pas recevoir de nouvelle identité. */
  canLinkIdentity(user: User, _identity: VerifiedProviderIdentity): boolean {
    return user.status === "active";
  }

  /** Vrai si l'authentification est trop ancienne pour une action sensible. */
  requiresStepUp(context: AuthenticationContext, now: Date): boolean {
    return (
      now.getTime() - context.authenticatedAt.getTime() >
      this.options.stepUpMaxAgeMs
    );
  }

  /** "high" si au moins deux méthodes ont été utilisées (MFA), sinon "standard". */
  assuranceLevelFor(methods: readonly string[]): string {
    return methods.length >= 2 ? "high" : "standard";
  }
}
