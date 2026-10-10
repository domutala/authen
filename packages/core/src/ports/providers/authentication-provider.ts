import type { TransactionPurpose } from "../../domain/authentication/transaction.js";
import type {
  ClientId,
  Metadata,
  ProviderInstanceId,
  TransactionId,
} from "../../shared/types.js";
import type { ProviderManifest } from "./provider-manifest.js";

/** Ce que le core transmet au provider à chaque appel. */
export interface ProviderContext {
  transactionId: TransactionId;
  providerInstanceId: ProviderInstanceId;

  clientId: ClientId | null;
  purpose: TransactionPurpose;
}

/** Identité prouvée par le provider (subject + claims déjà vérifiés). */
export interface VerifiedProviderIdentity {
  providerInstanceId: ProviderInstanceId;
  subject: string;

  claims: {
    email?: string;
    emailVerified?: boolean;
    phoneNumber?: string;
    phoneVerified?: boolean;
    name?: string;
    picture?: string;
  };

  methods: string[];
  authenticatedAt: Date;
}

/** Résultat d'une étape d'authentification côté provider. */
export type AuthStep =
  | {
      type: "authenticated";
      identity: VerifiedProviderIdentity;
    }
  | {
      type: "challenge";
      challengeType: string;
      expiresAt: Date;
      publicData: Metadata;
    }
  | {
      type: "redirect";
      url: string;
    }
  | {
      type: "rejected";
      code: string;
      retryable: boolean;
    };

export interface AuthenticationProvider {
  readonly manifest: ProviderManifest;

  /** Première étape : démarre l'authentification. */
  begin(context: ProviderContext, input: unknown): Promise<AuthStep>;

  /** Étapes suivantes : réponse au challenge, callback OIDC, etc. */
  continue(context: ProviderContext, input: unknown): Promise<AuthStep>;
}
