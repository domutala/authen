import type { UserProfile } from "../../domain/user/profile.js";
import type { UserId } from "../../shared/types.js";

export interface ProfileRepository {
  /** `userId` est à la fois clé primaire et clé étrangère vers l'utilisateur. */
  findByUserId(userId: UserId): Promise<UserProfile | null>;
  create(profile: UserProfile): Promise<void>;
  update(profile: UserProfile): Promise<void>;
}
