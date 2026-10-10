import type { UserProfile } from "../../domain/user/profile.js";
import type { UserId } from "../../shared/types.js";

export interface ProfileRepository {
  findByUserId(userId: UserId): Promise<UserProfile | null>;
  create(profile: UserProfile): Promise<void>;
  update(profile: UserProfile): Promise<void>;
}
