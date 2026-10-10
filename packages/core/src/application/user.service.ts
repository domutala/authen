import type { User, UserStatus } from "../domain/user/user.js";
import type { Clock } from "../ports/clock.js";
import type { IdGenerator } from "../ports/id-generator.js";
import type { UserRepository } from "../ports/repositories/user-repository.js";
import { AuthenticationError } from "../shared/errors.js";
import type { UserId } from "../shared/types.js";

export interface UserServiceDeps {
  users: UserRepository;
  ids: IdGenerator;
  clock: Clock;
}

export interface CreateUserInput {
  /** "active" par défaut. */
  status?: UserStatus;
}

/**
 * Gère uniquement le cycle de vie du compte (créer, activer, suspendre, désactiver).
 * Il ne vérifie jamais de mot de passe et n'émet pas de token.
 */
export class UserService {
  private readonly deps: UserServiceDeps;

  constructor(deps: UserServiceDeps) {
    this.deps = deps;
  }

  async create(input: CreateUserInput = {}): Promise<User> {
    const now = this.deps.clock.now();
    const status = input.status ?? "active";

    const user: User = {
      id: this.deps.ids.generate<UserId>(),
      status,
      lastAuthenticatedAt: null,
      disabledAt: status === "disabled" ? now : null,
      createdAt: now,
      updatedAt: now,
    };

    await this.deps.users.create(user);
    return user;
  }

  findById(id: UserId): Promise<User | null> {
    return this.deps.users.findById(id);
  }

  /** pending | suspended -> active */
  async activate(id: UserId): Promise<User> {
    const user = await this.requireById(id);
    if (user.status !== "pending" && user.status !== "suspended") {
      throw invalidTransition(user.status, "active");
    }
    return this.save({ ...user, status: "active", disabledAt: null });
  }

  /** active -> suspended */
  async suspend(id: UserId): Promise<User> {
    const user = await this.requireById(id);
    if (user.status !== "active") {
      throw invalidTransition(user.status, "suspended");
    }
    return this.save({ ...user, status: "suspended" });
  }

  /** Tout statut -> disabled (idempotent). */
  async disable(id: UserId): Promise<User> {
    const user = await this.requireById(id);
    if (user.status === "disabled") return user;
    return this.save({
      ...user,
      status: "disabled",
      disabledAt: this.deps.clock.now(),
    });
  }

  /** Appelé après une connexion réussie. */
  markAuthenticated(user: User): Promise<User> {
    return this.save({ ...user, lastAuthenticatedAt: this.deps.clock.now() });
  }

  private async requireById(id: UserId): Promise<User> {
    const user = await this.deps.users.findById(id);
    if (!user) throw new AuthenticationError("user_not_found", `User ${id}`);
    return user;
  }

  private async save(user: User): Promise<User> {
    const updated: User = { ...user, updatedAt: this.deps.clock.now() };
    await this.deps.users.update(updated);
    return updated;
  }
}

function invalidTransition(from: UserStatus, to: UserStatus) {
  return new AuthenticationError(
    "invalid_user_transition",
    `Transition interdite : ${from} -> ${to}`,
  );
}
