/**
 * Condensat DÉTERMINISTE d'un jeton aléatoire à forte entropie (refresh token).
 * Même entrée = même sortie, ce qui permet de retrouver le token en base
 * à partir de la valeur reçue (SHA-256, ou HMAC-SHA-256 avec une clé serveur).
 * Un algorithme lent et salé comme argon2 ne conviendrait pas ici.
 */
export interface TokenDigester {
  digest(token: string): Promise<string>;
}
