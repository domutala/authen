/**
 * Frontière transactionnelle commune à tous les repositories.
 *
 * Garanties obligatoires pour chaque adaptateur :
 * - atomicité : toutes les écritures sont validées, ou toutes sont annulées ;
 * - read-your-writes : le bloc relit immédiatement ses propres écritures ;
 * - propagation : les repositories utilisent automatiquement la transaction
 *   active dans la chaîne asynchrone courante ;
 * - imbrication : un `run` imbriqué rejoint la transaction externe ;
 * - isolation : deux blocs concurrents ne peuvent ni perdre une mise à jour
 *   conditionnelle, ni observer un état partiellement validé.
 *
 * Une exception annule le bloc puis est retransmise sans transformation.
 * Les effets externes non transactionnels (email, webhook, event bus...) ne
 * sont pas annulés : utiliser un outbox lorsqu'ils doivent suivre le commit.
 */
export interface TransactionRunner {
  run<T>(work: () => Promise<T>): Promise<T>;
}
