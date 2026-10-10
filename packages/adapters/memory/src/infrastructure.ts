import type {
  ChallengeStore,
  Clock,
  EventPublisher,
  IdGenerator,
  SecurityEvent,
  TransactionRunner,
} from "@authen/core";
import { randomUUID } from "node:crypto";
import type { MemoryDatabase } from "./database.js";

/** Horloge réelle. */
export class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }
}

/**
 * Horloge contrôlée : le temps n'avance que si on le demande.
 * Idéale pour tester les expirations (OTP, sessions, refresh tokens).
 */
export class ManualClock implements Clock {
  private current: Date;

  constructor(start: Date = new Date()) {
    this.current = start;
  }

  now(): Date {
    return new Date(this.current);
  }

  advance(ms: number): void {
    this.current = new Date(this.current.getTime() + ms);
  }

  set(date: Date): void {
    this.current = date;
  }
}

/** Identifiants UUID v4. */
export class UuidIdGenerator implements IdGenerator {
  generate<T extends string = string>(): T {
    return randomUUID() as T;
  }
}

/** Garde les événements de sécurité en mémoire, pour les inspecter dans les tests. */
export class MemoryEventPublisher implements EventPublisher {
  private readonly published: SecurityEvent[] = [];

  async publish(event: SecurityEvent): Promise<void> {
    this.published.push(structuredClone(event));
  }

  get events(): readonly SecurityEvent[] {
    return this.published;
  }

  ofType(eventType: string): SecurityEvent[] {
    return this.published.filter((event) => event.eventType === eventType);
  }

  clear(): void {
    this.published.length = 0;
  }
}

/** Stockage temporaire à usage unique (codes OTP, state, nonce...), avec expiration. */
export class MemoryChallengeStore implements ChallengeStore {
  private readonly entries = new Map<
    string,
    { value: string; expiresAt: Date }
  >();
  private readonly clock: Clock;

  constructor(clock: Clock) {
    this.clock = clock;
  }

  async save(key: string, value: string, expiresAt: Date): Promise<void> {
    this.entries.set(key, { value, expiresAt });
  }

  async consume(key: string): Promise<string | null> {
    const entry = this.entries.get(key);
    if (!entry) return null;

    // Lecture ET suppression en une seule étape : usage unique garanti.
    this.entries.delete(key);
    return entry.expiresAt.getTime() > this.clock.now().getTime()
      ? entry.value
      : null;
  }
}

/**
 * Transaction "tout ou rien" : si le bloc échoue, toutes les écritures faites
 * depuis le début sont annulées (restauration de la photo de la base).
 *
 * Limite : conçu pour des scénarios séquentiels. Deux transactions qui
 * s'entrelacent en parallèle pourraient s'annuler mutuellement.
 */
export class MemoryTransactionRunner implements TransactionRunner {
  private readonly db: MemoryDatabase;
  private depth = 0;

  constructor(db: MemoryDatabase) {
    this.db = db;
  }

  async run<T>(work: () => Promise<T>): Promise<T> {
    // Transaction imbriquée : la transaction externe gère déjà l'annulation.
    if (this.depth > 0) return work();

    const snapshot = this.db.snapshot();
    this.depth++;
    try {
      return await work();
    } catch (error) {
      this.db.restore(snapshot);
      throw error;
    } finally {
      this.depth--;
    }
  }
}
