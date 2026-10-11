/**
 * Contrat commun des repositories :
 *
 * - une lecture absente renvoie `null` (ou `[]` pour une collection) ;
 * - les valeurs lues sont des snapshots, jamais des objets vivants mutables ;
 * - `create` est un INSERT et lève `RepositoryError("duplicate_key")` si la
 *   clé primaire existe déjà ;
 * - `update` remplace une ligne existante et lève
 *   `RepositoryError("record_not_found")` lorsqu'elle n'existe pas ;
 * - chaque appel est atomique et rejoint la transaction active du
 *   `TransactionRunner` ;
 * - les contraintes uniques documentées par un port doivent être garanties
 *   par le stockage lui-même, y compris entre deux requêtes concurrentes.
 *
 * Une méthode explicitement conditionnelle, comme `markConsumed`, signale une
 * condition perdue par sa valeur de retour et non par une exception.
 */
export * from "./user-repository.js";
export * from "./identity-repository.js";
export * from "./profile-repository.js";
export * from "./credential-repository.js";
export * from "./session-repository.js";
export * from "./transaction-repository.js";
export * from "./provider-instance-repository.js";
export * from "./token-family-repository.js";
export * from "./refresh-token-repository.js";
