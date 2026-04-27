import { logger } from '@/configs/logger.configs'
import { redisClient } from '@/configs/redis.configs'

interface MemoryEntry {
  value: string
  expiresAt: number
}

/**
 * SessionStore
 *
 * Unified key-value store with TTL support. Automatically uses Redis when
 * available and transparently falls back to an in-memory Map when Redis is
 * disabled (`REDIS_ENABLED=false`) or unreachable (connection failure).
 *
 * Behaviour:
 * - Each operation checks Redis availability at call time, so recovery is
 *   automatic — if Redis comes back up, the next call switches back to it.
 * - In-memory entries are cleaned up every 60 seconds.
 * - A single warning is logged the first time the memory fallback is used;
 *   subsequent requests are silent to avoid log spam.
 *
 * @remarks
 * The in-memory fallback is suitable for single-instance deployments. In a
 * multi-instance (load-balanced) setup OPAQUE state stored in memory will not
 * be visible to other instances, which means sign-in requests must be routed
 * to the same instance that handled signInAlpha (sticky sessions) when Redis
 * is down.
 */
class SessionStore {
  private readonly store: Map<string, MemoryEntry> = new Map()
  private fallbackWarned: boolean = false

  constructor() {
    setInterval((): void => this.cleanup(), 60_000).unref()
  }

  private isRedisAvailable(): boolean {
    return !!redisClient?.isOpen
  }

  /**
   * Returns true when the session store is backed by Redis (i.e. Redis is
   * currently connected). Callers can use this to distinguish between
   * "key not found" (session invalidated) and "Redis unavailable" (fallback).
   */
  public get isRedisConnected(): boolean {
    return this.isRedisAvailable()
  }

  private warnFallback(): void {
    if (!this.fallbackWarned) {
      this.fallbackWarned = true
      logger.warning('Redis unavailable — session store is using in-memory fallback. Data will not persist across restarts or be shared across instances.')
    }
  }

  /**
   * Store a value with a TTL.
   */
  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    if (this.isRedisAvailable() && redisClient) {
      this.fallbackWarned = false
      await redisClient.set(key, value, { EX: ttlSeconds })
      return
    }
    this.warnFallback()
    this.store.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1_000 })
  }

  /**
   * Retrieve a value. Returns `null` if the key does not exist or has expired.
   */
  async get(key: string): Promise<string | null> {
    if (this.isRedisAvailable() && redisClient) {
      return redisClient.get(key)
    }
    const entry: MemoryEntry | undefined = this.store.get(key)
    if (!entry) return null
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key)
      return null
    }
    return entry.value
  }

  /**
   * Delete a key (no-op if key does not exist).
   */
  async del(key: string): Promise<void> {
    if (this.isRedisAvailable() && redisClient) {
      await redisClient.del(key)
      return
    }
    this.store.delete(key)
  }

  private cleanup(): void {
    const now: number = Date.now()
    for (const [key, entry] of this.store.entries()) {
      if (now > entry.expiresAt) {
        this.store.delete(key)
      }
    }
  }
}

export const sessionStore: SessionStore = new SessionStore()
