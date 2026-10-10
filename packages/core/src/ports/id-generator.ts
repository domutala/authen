/**
 * Génère des identifiants uniques (UUID v7, ULID...).
 * Le générique permet de récupérer directement un id typé : `ids.generate<UserId>()`.
 */
export interface IdGenerator {
  generate<T extends string = string>(): T;
}
