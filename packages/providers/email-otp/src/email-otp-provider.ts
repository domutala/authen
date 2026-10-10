import {
  constantTimeEqual,
  readStringField,
  type AuthenticationProvider,
  type AuthStep,
  type ChallengeStore,
  type Clock,
  type ProviderContext,
  type ProviderManifest,
  type SecureRandom,
  type TokenDigester,
} from "@authen/core";
import type { OtpSender } from "./otp-sender.js";

export interface EmailOtpOptions {
  /** Nombre de chiffres du code. */
  codeLength: number;
  /** Durée de validité du code. */
  codeTtlMs: number;
}

const DEFAULT_OPTIONS: EmailOtpOptions = {
  codeLength: 6,
  codeTtlMs: 10 * 60 * 1000,
};

export interface EmailOtpProviderDeps {
  challenges: ChallengeStore;
  digester: TokenDigester;
  random: SecureRandom;
  sender: OtpSender;
  clock: Clock;
  options?: Partial<EmailOtpOptions>;
}

/** Ce qu'on garde côté serveur entre `begin` et `continue`. */
interface StoredChallenge {
  email: string;
  /** Condensat de "transactionId:code" : le code lui-même n'est jamais stocké. */
  digest: string;
  expiresAt: string;
}

/**
 * Connexion par code reçu par email, en deux étapes :
 *  1. `begin`    : génère le code, l'envoie, renvoie un "challenge".
 *  2. `continue` : vérifie le code saisi.
 *
 * L'identité est (instance, adresse email normalisée) : prouver le code prouve
 * le contrôle de l'adresse, donc l'email est renvoyé comme vérifié.
 */
export class EmailOtpProvider implements AuthenticationProvider {
  readonly manifest: ProviderManifest = {
    type: "email-otp",
    name: "Email OTP",
    version: "0.0.1",
    capabilities: ["challenge"],
  };

  private readonly d: EmailOtpProviderDeps;
  private readonly options: EmailOtpOptions;

  constructor(deps: EmailOtpProviderDeps) {
    this.d = deps;
    this.options = { ...DEFAULT_OPTIONS, ...deps.options };
  }

  async begin(context: ProviderContext, input: unknown): Promise<AuthStep> {
    const rawEmail = readStringField(input, "email");
    const email = rawEmail === null ? null : normalizeEmail(rawEmail);
    if (email === null || !isValidEmail(email))
      return reject("invalid_email", true);

    // La réponse est identique que l'adresse soit connue ou non : pas d'énumération.
    const code = this.d.random.digits(this.options.codeLength);
    const expiresAt = new Date(
      this.d.clock.now().getTime() + this.options.codeTtlMs,
    );

    const stored: StoredChallenge = {
      email,
      digest: await this.digest(context, code),
      expiresAt: expiresAt.toISOString(),
    };
    await this.d.challenges.save(
      challengeKey(context),
      JSON.stringify(stored),
      expiresAt,
    );

    await this.d.sender.send({
      to: email,
      code,
      expiresAt,
      transactionId: context.transactionId,
    });

    return {
      type: "challenge",
      challengeType: "email_otp",
      expiresAt,
      publicData: {
        destination: maskEmail(email),
        codeLength: this.options.codeLength,
      },
    };
  }

  async continue(context: ProviderContext, input: unknown): Promise<AuthStep> {
    const code = readStringField(input, "code")?.trim() ?? null;
    if (code === null || !isCodeFormat(code, this.options.codeLength)) {
      // On ne touche pas au challenge : un code mal formé ne compte pas comme essai consommé.
      return reject("invalid_code", true);
    }

    // `consume` lit ET supprime : deux essais simultanés ne peuvent pas lire le même challenge.
    const raw = await this.d.challenges.consume(challengeKey(context));
    const stored = raw === null ? null : parseStored(raw);
    const now = this.d.clock.now();

    if (stored === null || new Date(stored.expiresAt) <= now) {
      return reject("challenge_expired", false);
    }

    const expected = stored.digest;
    const actual = await this.digest(context, code);

    if (!constantTimeEqual(expected, actual)) {
      // Mauvais code : on remet le challenge en place (même échéance) pour permettre
      // un nouvel essai. Le nombre d'essais est plafonné par la transaction du core.
      await this.d.challenges.save(
        challengeKey(context),
        raw!,
        new Date(stored.expiresAt),
      );
      return reject("invalid_code", true);
    }

    return {
      type: "authenticated",
      identity: {
        providerInstanceId: context.providerInstanceId,
        subject: stored.email,
        claims: { email: stored.email, emailVerified: true },
        methods: ["email_otp"],
        authenticatedAt: now,
      },
    };
  }

  /** Le code est lié à la transaction : un code d'une autre transaction est refusé. */
  private digest(context: ProviderContext, code: string): Promise<string> {
    return this.d.digester.digest(`${context.transactionId}:${code}`);
  }
}

export function createEmailOtpProvider(
  deps: EmailOtpProviderDeps,
): EmailOtpProvider {
  return new EmailOtpProvider(deps);
}

function challengeKey(context: ProviderContext): string {
  return `email-otp:${context.transactionId}`;
}

function normalizeEmail(email: string): string {
  return email.normalize("NFKC").trim().toLowerCase();
}

function isValidEmail(email: string): boolean {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isCodeFormat(code: string, length: number): boolean {
  return code.length === length && /^\d+$/.test(code);
}

/** "mamadou@example.com" -> "m***@example.com" (affiché au client, sans révéler l'adresse). */
function maskEmail(email: string): string {
  const at = email.indexOf("@");
  return `${email.slice(0, 1)}***${email.slice(at)}`;
}

function parseStored(raw: string): StoredChallenge | null {
  try {
    const value: unknown = JSON.parse(raw);
    if (
      typeof value === "object" &&
      value !== null &&
      typeof (value as StoredChallenge).email === "string" &&
      typeof (value as StoredChallenge).digest === "string" &&
      typeof (value as StoredChallenge).expiresAt === "string"
    ) {
      return value as StoredChallenge;
    }
  } catch {
    // contenu illisible : traité comme un challenge expiré
  }
  return null;
}

function reject(code: string, retryable: boolean): AuthStep {
  return { type: "rejected", code, retryable };
}
