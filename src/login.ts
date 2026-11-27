import { RateLimiterMemory, RateLimiterRes } from 'rate-limiter-flexible';
import { allowed, normalizeEmail, type Runtime } from './config.js';
import { BusyError, verifyPassword } from './password.js';

export class LoginLimiter {
  private failures = new RateLimiterMemory({ points: 5, duration: 3600, blockDuration: 900 });
  private keys = new Map<string, number>();
  private queues = new Map<string, Promise<void>>();
  private queued = 0;

  async attempt(runtime: Runtime, clientID: string, email: string, password: string) {
    const key = normalizeEmail(email);
    if (this.queued >= 32) throw new BusyError();
    this.queued++;
    const previous = this.queues.get(key) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>(resolve => { release = resolve; });
    this.queues.set(key, current);
    await previous;
    try {
      for (const [k, expiry] of this.keys) if (expiry <= Date.now()) this.keys.delete(k);
      if (!this.keys.has(key) && this.keys.size >= 10000) throw new BusyError();
      const count = await this.failures.get(key);
      if (count && count.msBeforeNext > 0 && count.consumedPoints >= 5) {
        return { outcome: 'rate_limited' as const, retryAfter: Math.ceil(count.msBeforeNext / 1000) };
      }
      const user = runtime.config.users.find(u => u.email === key);
      const correct = await verifyPassword(user?.password_hash ?? runtime.dummyHash, password);
      if (user && correct) {
        const client = runtime.clients.get(clientID);
        if (client && allowed(client, user)) {
          await this.failures.delete(key);
          this.keys.delete(key);
          return { outcome: 'success' as const, user };
        }
        return { outcome: 'failed' as const };
      }
      // Other emails may have filled the table while Argon2 was running.
      if (!this.keys.has(key)) {
        if (this.keys.size >= 10000) throw new BusyError();
        this.keys.set(key, Date.now() + 3600000);
      }
      let result: RateLimiterRes;
      try { result = await this.failures.consume(key); }
      catch (error) {
        if (!(error instanceof RateLimiterRes)) throw error;
        result = error;
      }
      if (result.consumedPoints >= 5) {
        await this.failures.block(key, 900);
        this.keys.set(key, Date.now() + 900000);
      } else {
        this.keys.set(key, Date.now() + result.msBeforeNext);
      }
      return { outcome: 'failed' as const };
    } finally {
      release();
      this.queued--;
      if (this.queues.get(key) === current) this.queues.delete(key);
    }
  }
}
