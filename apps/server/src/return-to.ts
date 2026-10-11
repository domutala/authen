/**
 * Valide l'URL de retour après connexion. Seule une requête `/authorize` de ce
 * même serveur est acceptée : toute autre valeur (autre domaine, autre chemin,
 * `//evil.com`, `javascript:`...) est ignorée, ce qui évite l'open redirect.
 * Retourne un chemin relatif (`/authorize?...`) ou `null`.
 */
export function safeReturnTo(
  value: string | null | undefined,
  issuer: string,
): string | null {
  if (!value || value.length > 4096) return null;
  try {
    const base = new URL(issuer);
    const url = new URL(value, base);
    if (url.origin !== base.origin) return null;
    // Un chemin relatif doit rester relatif : refuse `//host` et `/\host`.
    if (value.startsWith("//") || value.startsWith("/\\")) return null;
    const prefix = base.pathname.replace(/\/$/, "");
    if (url.pathname !== `${prefix}/authorize`) return null;
    return `${url.pathname}${url.search}`;
  } catch {
    return null;
  }
}
