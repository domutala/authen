/**
 * Compare deux chaînes en temps constant (indépendant du premier caractère différent).
 * À utiliser pour comparer des secrets : codes OTP, `state`, `nonce`...
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const length = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;

  for (let i = 0; i < length; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }

  return diff === 0;
}
