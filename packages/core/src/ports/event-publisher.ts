import type { SecurityEvent } from "../domain/security/security-event.js";

/**
 * Publie les événements de sécurité (audit, alertes...).
 * Une implémentation ne devrait pas lever d'exception : elle gère
 * elle-même ses échecs pour ne pas bloquer une connexion.
 */
export interface EventPublisher {
  publish(event: SecurityEvent): Promise<void>;
}
