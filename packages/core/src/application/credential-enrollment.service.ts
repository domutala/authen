import type { Credential } from "../domain/user/credential.js";
import type { Clock } from "../ports/clock.js";
import {
  supportsEnrollment,
  type VerifiedEnrollmentContext,
} from "../ports/providers/optional-capabilities.js";
import type { ProviderRegistry } from "../ports/providers/provider-registry.js";
import type { ProviderInstanceRepository } from "../ports/repositories/provider-instance-repository.js";
import type { TransactionRepository } from "../ports/repositories/transaction-repository.js";
import { AuthenticationError } from "../shared/errors.js";
import type {
  ProviderInstanceId,
  TransactionId,
  UserId,
} from "../shared/types.js";
import type { SecurityPolicyService } from "./security-policy.service.js";

export interface EnrollCredentialRequest {
  userId: UserId;
  providerInstanceId: ProviderInstanceId;
  stepUpTransactionId: TransactionId;
  input: unknown;
}

export interface CredentialEnrollmentServiceDeps {
  providers: ProviderRegistry;
  providerInstances: ProviderInstanceRepository;
  transactions: TransactionRepository;
  policy: SecurityPolicyService;
  clock: Clock;
}

/**
 * Point d'entrée sécurisé pour ajouter un credential à un compte.
 *
 * Le client ne peut pas fournir lui-même un `AuthenticationContext` fiable :
 * le service relit donc une transaction de step-up persistée par le serveur.
 */
export class CredentialEnrollmentService {
  private readonly d: CredentialEnrollmentServiceDeps;

  constructor(deps: CredentialEnrollmentServiceDeps) {
    this.d = deps;
  }

  async enroll(request: EnrollCredentialRequest): Promise<Credential> {
    const transaction = await this.d.transactions.findById(
      request.stepUpTransactionId,
    );
    if (!transaction || transaction.purpose !== "step_up") {
      throw new AuthenticationError("step_up_required");
    }
    if (
      transaction.status !== "completed" ||
      transaction.completedAt === null ||
      transaction.userId !== request.userId
    ) {
      throw new AuthenticationError("step_up_invalid");
    }
    if (
      !this.d.policy.acceptsStepUp(transaction.completedAt, this.d.clock.now())
    ) {
      throw new AuthenticationError("step_up_expired");
    }

    const instance = await this.d.providerInstances.findById(
      request.providerInstanceId,
    );
    if (!instance) throw new AuthenticationError("provider_not_found");
    if (!instance.enabled) throw new AuthenticationError("provider_disabled");

    const provider = await this.d.providers.resolve(instance.id);
    if (!supportsEnrollment(provider)) {
      throw new AuthenticationError(
        "invalid_provider_response",
        `Le provider ${instance.type} ne supporte pas l'enrôlement`,
      );
    }

    const context: VerifiedEnrollmentContext = {
      userId: request.userId,
      providerInstanceId: instance.id,
      stepUpTransactionId: transaction.id,
    };
    return provider.enroll(context, request.input);
  }
}
