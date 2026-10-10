import type { ProviderInstance } from "../../domain/provider/provider-instance.js";
import type { ProviderInstanceId } from "../../shared/types.js";

export interface ProviderInstanceRepository {
  findById(id: ProviderInstanceId): Promise<ProviderInstance | null>;
}
