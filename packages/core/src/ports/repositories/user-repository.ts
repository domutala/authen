import type { User } from "../../domain/user/user.js";
import type { UserId } from "../../shared/types.js";

export interface UserRepository {
  findById(id: UserId): Promise<User | null>;
  create(user: User): Promise<void>;
  update(user: User): Promise<void>;
}
