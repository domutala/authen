import type { ProviderInstanceId } from "../../shared/types.js";
import type { AuthenticationProvider } from "./authentication-provider.js";
import type { ProviderManifest } from "./provider-manifest.js";

/** Annuaire des providers disponibles (types enregistrés au démarrage). */
export interface ProviderRegistry {
  register(provider: AuthenticationProvider): void;

  unregister(type: string): void;

  /**
   * Retrouve le provider qui gère une instance configurée.
   * Asynchrone car il faut lire l'instance en base pour connaître son type.
   */
  resolve(instanceId: ProviderInstanceId): Promise<AuthenticationProvider>;

  list(): ProviderManifest[];
}
