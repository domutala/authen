import type {
  Metadata,
  ProviderInstanceId,
  Timestamps,
} from "../../shared/types.js";

export interface ProviderInstance extends Timestamps {
  id: ProviderInstanceId;
  type: string;

  enabled: boolean;
  configurationRef: string;

  metadata: Metadata;
}
