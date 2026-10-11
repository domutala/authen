export interface RateLimiterOptions {
  /** Nombre de requêtes autorisées par fenêtre. */
  limit: number;
  windowMs: number;
  now: () => number;
}

export type RateLimitResult =
  | { allowed: true }
  | { allowed: false; retryAfterSeconds: number };

/**
 * Limiteur à fenêtre fixe, en mémoire du process. Suffisant pour une instance
 * unique ; avec plusieurs instances, mettre un limiteur partagé (Redis,
 * proxy) devant ou à la place.
 */
export class RateLimiter {
  private readonly windows = new Map<string, { count: number; resetAt: number }>();
  private hits = 0;

  constructor(private readonly o: RateLimiterOptions) {}

  hit(key: string): RateLimitResult {
    const now = this.o.now();
    if (++this.hits % 500 === 0) this.sweep(now);

    let window = this.windows.get(key);
    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + this.o.windowMs };
      this.windows.set(key, window);
    }
    window.count += 1;
    if (window.count <= this.o.limit) return { allowed: true };
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((window.resetAt - now) / 1000)),
    };
  }

  private sweep(now: number): void {
    for (const [key, window] of this.windows) {
      if (window.resetAt <= now) this.windows.delete(key);
    }
  }
}
