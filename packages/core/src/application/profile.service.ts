import type { UserProfile } from "../domain/user/profile.js";
import type { Clock } from "../ports/clock.js";
import type { ProfileRepository } from "../ports/repositories/profile-repository.js";
import type { VerifiedProviderIdentity } from "../ports/providers/authentication-provider.js";
import { AuthenticationError } from "../shared/errors.js";
import type { UserId } from "../shared/types.js";

export interface ProfileServiceDeps {
  profiles: ProfileRepository;
  clock: Clock;
}

/** Champs modifiables du profil (tous facultatifs). */
export type ProfileUpdate = Partial<
  Pick<
    UserProfile,
    "displayName" | "givenName" | "familyName" | "avatarUrl" | "locale" | "timezone"
  >
>;

/** Gère les données du profil. Ne décide jamais de l'authentification. */
export class ProfileService {
  private readonly deps: ProfileServiceDeps;

  constructor(deps: ProfileServiceDeps) {
    this.deps = deps;
  }

  get(userId: UserId): Promise<UserProfile | null> {
    return this.deps.profiles.findByUserId(userId);
  }

  /**
   * Crée le profil initial à la première connexion.
   * Les claims du provider ne servent que de valeurs de départ pour l'affichage.
   */
  async createFromClaims(
    userId: UserId,
    claims: VerifiedProviderIdentity["claims"],
  ): Promise<UserProfile> {
    const now = this.deps.clock.now();

    const profile: UserProfile = {
      userId,
      displayName: claims.name ?? null,
      givenName: null,
      familyName: null,
      avatarUrl: claims.picture ?? null,
      locale: null,
      timezone: null,
      createdAt: now,
      updatedAt: now,
    };

    await this.deps.profiles.create(profile);
    return profile;
  }

  async update(userId: UserId, input: ProfileUpdate): Promise<UserProfile> {
    const current = await this.deps.profiles.findByUserId(userId);
    if (!current) {
      throw new AuthenticationError("profile_not_found", `Profile ${userId}`);
    }

    const updated: UserProfile = {
      ...current,
      ...input,
      updatedAt: this.deps.clock.now(),
    };

    await this.deps.profiles.update(updated);
    return updated;
  }
}
