import type { AuthenticationTransaction } from "../../domain/authentication/transaction.js";
import type { TransactionId } from "../../shared/types.js";

export interface TransactionRepository {
  findById(id: TransactionId): Promise<AuthenticationTransaction | null>;
  create(transaction: AuthenticationTransaction): Promise<void>;

  /**
   * L'implémentation devrait être optimiste (ex. `WHERE updated_at = ancienne valeur`)
   * pour éviter que deux `continue()` simultanés écrasent le même état.
   */
  update(
    transaction: AuthenticationTransaction,
    expected: Pick<AuthenticationTransaction, "status" | "attempts" | "updatedAt">,
  ): Promise<boolean>;
}
