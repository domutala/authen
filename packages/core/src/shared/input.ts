/**
 * Lit un champ texte dans une entrée `unknown` (corps de requête, etc.).
 * Retourne `null` si l'entrée n'est pas un objet ou si le champ n'est pas une chaîne.
 * Les providers reçoivent des données non fiables : on ne suppose jamais leur forme.
 */
export function readStringField(input: unknown, key: string): string | null {
  if (typeof input !== "object" || input === null) return null;
  const value = (input as Record<string, unknown>)[key];
  return typeof value === "string" ? value : null;
}
