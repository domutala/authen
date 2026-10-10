import type { Session } from "../../domain/session/session.js";
import type { SessionId, UserId } from "../../shared/types.js";

export interface SessionRepository {
  findById(id: SessionId): Promise<Session | null>;
  findByUserId(userId: UserId): Promise<Session[]>;
  create(session: Session): Promise<void>;
  update(session: Session): Promise<void>;
}
