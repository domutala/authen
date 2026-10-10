import type { ProviderInstanceId } from "../../shared/types.js";

export interface AuthenticationContext {
  providerInstanceId: ProviderInstanceId;

  methods: string[];
  assuranceLevel: string;

  authenticatedAt: Date;
  verifiedAt: Date;
}
