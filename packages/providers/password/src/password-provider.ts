import {
  AuthenticationError,
  readStringField,
  type AuthenticationProvider,
  type AuthStep,
  type Clock,
  type Credential,
  type CredentialEnrollmentProvider,
  type CredentialId,
  type CredentialRepository,
  type CredentialRevocationProvider,
  type IdentityRepository,
  type IdentityService,
  type IdGenerator,
  type ProviderContext,
  type ProviderInstanceId,
  type ProviderManifest,
  type SecretHasher,
  type TransactionRunner,
  type UserId,
  type VerifiedEnrollmentContext,
} from "@authen/core";

export interface PasswordProviderOptions {
  minLength: number;
  maxLength: number;
}

const DEFAULT_OPTIONS: PasswordProviderOptions = {
  minLength: 10,
  // Plafond : évite qu'un mot de passe gigantesque ne serve à saturer le serveur.
  maxLength: 128,
};

export interface PasswordProviderDeps {
  identities: IdentityRepository;
  identityService: IdentityService;
  credentials: CredentialRepository;
  hasher: SecretHasher;
  ids: IdGenerator;
  clock: Clock;
  unitOfWork: TransactionRunner;
  options?: Partial<PasswordProviderOptions>;
}

/** Levée par `enroll` quand le mot de passe ne respecte pas la politique. */
export class PasswordPolicyError extends Error {
  readonly code:
    "password_too_short" | "password_too_long" | "invalid_identifier";

  constructor(code: PasswordPolicyError["code"], message: string) {
    super(message);
    this.name = "PasswordPolicyError";
    this.code = code;
  }
}

/**
 * Provider "identifiant + mot de passe".
 *
 * - Connexion (`begin`) : une seule étape, pas de `continue`.
 * - Création du mot de passe : via `enroll`, pour un utilisateur DÉJÀ authentifié
 *   (par un autre provider, ex. Email OTP). Le provider ne crée pas de compte
 *   lui-même : l'inscription directe par mot de passe n'est pas supportée,
 *   car l'identifiant (email) ne serait pas vérifié.
 *
 * Le hash du mot de passe est conservé dans `Credential.secretRef`.
 */
export class PasswordProvider
  implements
    AuthenticationProvider,
    CredentialEnrollmentProvider,
    CredentialRevocationProvider
{
  readonly manifest: ProviderManifest = {
    type: "password",
    name: "Password",
    version: "0.0.1",
    capabilities: ["password", "enrollment"],
  };

  private readonly d: PasswordProviderDeps;
  private readonly options: PasswordProviderOptions;
  private dummyHash: Promise<string> | null = null;

  constructor(deps: PasswordProviderDeps) {
    this.d = deps;
    this.options = { ...DEFAULT_OPTIONS, ...deps.options };
    if (
      !Number.isSafeInteger(this.options.minLength) ||
      this.options.minLength <= 0
    ) {
      throw new RangeError(
        "password.minLength doit être un entier strictement positif",
      );
    }
    if (
      !Number.isSafeInteger(this.options.maxLength) ||
      this.options.maxLength < this.options.minLength
    ) {
      throw new RangeError(
        "password.maxLength doit être un entier supérieur ou égal à minLength",
      );
    }
  }

  async begin(context: ProviderContext, input: unknown): Promise<AuthStep> {
    if (context.purpose === "sign_up")
      return reject("enrollment_required", false);
    if (context.purpose !== "sign_in" && context.purpose !== "step_up") {
      return reject("unsupported_purpose", false);
    }

    const identifier = readStringField(input, "identifier");
    const password = readStringField(input, "password");
    if (identifier === null || password === null) {
      return reject("invalid_input", true);
    }

    const subject = normalizeIdentifier(identifier);
    const identity = await this.d.identities.findByProviderSubject(
      context.providerInstanceId,
      subject,
    );

    const credential = identity
      ? await this.findActivePassword(
          identity.userId,
          context.providerInstanceId,
        )
      : null;

    // On vérifie TOUJOURS un hash, même si le compte n'existe pas :
    // le temps de réponse ne révèle pas si l'identifiant est connu.
    const hash = credential?.secretRef ?? (await this.getDummyHash());
    const passwordOk =
      password.length <= this.options.maxLength &&
      (await this.d.hasher.verify(password, hash));

    const now = this.d.clock.now();
    const usable =
      identity !== null &&
      identity.status === "active" &&
      credential !== null &&
      (credential.expiresAt === null || credential.expiresAt > now);

    // Même réponse pour "inconnu" et "mauvais mot de passe" : pas d'énumération de comptes.
    if (!passwordOk || !usable) return reject("invalid_credentials", true);

    await this.d.credentials.update({
      ...credential,
      lastUsedAt: now,
      updatedAt: now,
    });

    return {
      type: "authenticated",
      identity: {
        providerInstanceId: context.providerInstanceId,
        subject: identity.providerSubject,
        claims: {},
        methods: ["password"],
        authenticatedAt: now,
      },
    };
  }

  /** Pas de seconde étape pour ce provider. */
  async continue(): Promise<AuthStep> {
    return reject("unsupported_operation", false);
  }

  /**
   * Crée l'identité "mot de passe" ET son credential, pour un utilisateur existant.
   * Le contexte est produit après vérification du step-up par le core.
   * `input` : `{ identifier, password }`.
   */
  async enroll(
    context: VerifiedEnrollmentContext,
    input: unknown,
  ): Promise<Credential> {
    const identifier = readStringField(input, "identifier");
    const password = readStringField(input, "password");

    if (identifier === null || password === null) {
      throw new PasswordPolicyError("invalid_identifier", "Entrée invalide");
    }

    const subject = normalizeIdentifier(identifier);
    if (subject.length === 0) {
      throw new PasswordPolicyError("invalid_identifier", "Identifiant vide");
    }
    if (password.length < this.options.minLength) {
      throw new PasswordPolicyError(
        "password_too_short",
        `Minimum ${this.options.minLength} caractères`,
      );
    }
    if (password.length > this.options.maxLength) {
      throw new PasswordPolicyError(
        "password_too_long",
        `Maximum ${this.options.maxLength} caractères`,
      );
    }

    const instanceId = context.providerInstanceId;
    const secretRef = await this.d.hasher.hash(password);
    const now = this.d.clock.now();

    // Identité + credential : tout ou rien.
    return this.d.unitOfWork.run(async () => {
      // Lève "identity_conflict" si cet identifiant est déjà pris.
      const identity = await this.d.identityService.link(context.userId, {
        providerInstanceId: instanceId,
        subject,
        claims: {},
        methods: ["password"],
        authenticatedAt: now,
      });

      const credential: Credential = {
        id: this.d.ids.generate<CredentialId>(),
        userId: context.userId,
        identityId: identity.id,
        providerInstanceId: instanceId,
        type: "password",
        status: "active",
        secretRef,
        publicData: {},
        expiresAt: null,
        lastUsedAt: null,
        revokedAt: null,
        createdAt: now,
        updatedAt: now,
      };

      await this.d.credentials.create(credential);
      return credential;
    });
  }

  async revokeCredential(credentialId: CredentialId): Promise<void> {
    const credential = await this.d.credentials.findById(credentialId);
    if (!credential) {
      throw new AuthenticationError(
        "credential_not_found",
        `Credential ${credentialId}`,
      );
    }
    if (credential.status === "revoked") return;

    const now = this.d.clock.now();
    await this.d.credentials.update({
      ...credential,
      status: "revoked",
      revokedAt: now,
      updatedAt: now,
    });
  }

  private async findActivePassword(
    userId: UserId,
    instanceId: ProviderInstanceId,
  ): Promise<Credential | null> {
    const credentials = await this.d.credentials.findByUserId(userId);
    return (
      credentials.find(
        (c) =>
          c.type === "password" &&
          c.status === "active" &&
          c.providerInstanceId === instanceId &&
          c.secretRef !== null,
      ) ?? null
    );
  }

  /** Hash factice, calculé une fois, pour égaliser le temps de réponse. */
  private getDummyHash(): Promise<string> {
    this.dummyHash ??= this.d.hasher.hash("authen-dummy-password");
    return this.dummyHash;
  }
}

export function createPasswordProvider(
  deps: PasswordProviderDeps,
): PasswordProvider {
  return new PasswordProvider(deps);
}

/** Normalisation de l'identifiant : Unicode NFKC, sans espaces autour, en minuscules. */
function normalizeIdentifier(identifier: string): string {
  return identifier.normalize("NFKC").trim().toLowerCase();
}

function reject(code: string, retryable: boolean): AuthStep {
  return { type: "rejected", code, retryable };
}
