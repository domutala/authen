import type { EventId, Metadata, UserId } from "../../shared/types.js";

export interface SecurityEvent {
  id: EventId;
  userId: UserId | null;

  eventType: string;
  occurredAt: Date;

  metadata: Metadata;
}
