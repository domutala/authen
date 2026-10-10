import type { AuthenticationProvider } from "../ports/providers/authentication-provider.js";
import type { ProviderManifest } from "../ports/providers/provider-manifest.js";
import type { ProviderRegistry } from "../ports/providers/provider-registry.js";
import type { ProviderInstanceRepository } from "../ports/repositories/provider-instance-repository.js";
import { AuthenticationError } from "../shared/errors.js";
import type { ProviderInstanceId } from "../shared/types.js";

export interface DefaultProviderRegistryDeps {
  instances: ProviderInstanceRepository;
}

/**
 * Registre standard : une implémentation de provider par TYPE ("google", "password"...),
 * et autant d'INSTANCES configurées que nécessaire (ex. une instance Microsoft par organisation).
 *
 * `resolve` part de l'instance (lue en base), retrouve son type, puis renvoie
 * l'implémentation correspondante.
 */
export class DefaultProviderRegistry implements ProviderRegistry {
  private readonly providers = new Map<string, AuthenticationProvider>();
  private readonly instances: ProviderInstanceRepository;

  constructor(deps: DefaultProviderRegistryDeps) {
    this.instances = deps.instances;
  }

  register(provider: AuthenticationProvider): void {
    const { type } = provider.manifest;
    if (this.providers.has(type)) {
      throw new AuthenticationError(
        "provider_conflict",
        `Un provider de type "${type}" est déjà enregistré`,
      );
    }
    this.providers.set(type, provider);
  }

  unregister(type: string): void {
    this.providers.delete(type);
  }

  async resolve(
    instanceId: ProviderInstanceId,
  ): Promise<AuthenticationProvider> {
    const instance = await this.instances.findById(instanceId);
    if (!instance) {
      throw new AuthenticationError(
        "provider_not_found",
        `Instance ${instanceId}`,
      );
    }

    const provider = this.providers.get(instance.type);
    if (!provider) {
      throw new AuthenticationError(
        "provider_not_found",
        `Aucun provider enregistré pour le type "${instance.type}"`,
      );
    }
    return provider;
  }

  list(): ProviderManifest[] {
    return [...this.providers.values()].map((provider) => provider.manifest);
  }
}
