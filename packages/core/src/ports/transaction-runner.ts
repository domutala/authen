/**
 * Exécute un bloc dans une transaction de base de données :
 * tout réussit ou tout est annulé (ex. création user + identité + profil).
 *
 * L'adaptateur (Drizzle, etc.) décide comment les repositories partagent
 * la transaction en cours (ex. AsyncLocalStorage).
 */
export interface TransactionRunner {
  run<T>(work: () => Promise<T>): Promise<T>;
}
