import httpResponse from '@/shared/utils/http-response.utils'

import type { RedisClientType } from 'redis'
import type { Context, MiddlewareHandler, Next } from 'hono'

import { createMiddleware } from 'hono/factory'
import { logger } from '@/configs/logger.configs'
import { redisClient } from '@/configs/redis.configs'
import { remoteAddr } from '@/shared/utils/remote-addr.utils'

export interface RateLimitOptions {
  windowMs?: number // Time window in milliseconds (default: 15 minutes)
  max?: number // Max requests per window (default: 100)
  message?: string // Custom error message
  statusCode?: number // HTTP status code (default: 429)
  skipSuccessfulRequests?: boolean // Don't count successful requests
  skipFailedRequests?: boolean // Don't count failed requests
  keyGenerator?: (ctx: Context<Generics>) => string // Custom key generator
  handler?: (ctx: Context<Generics>, next: Next) => Response | Promise<Response> // Custom handler
  skip?: (ctx: Context<Generics>) => boolean | Promise<boolean> // Skip middleware for certain requests
  onLimitReached?: (ctx: Context<Generics>) => void | Promise<void> // Callback when limit is reached
  standardHeaders?: boolean // Add standard rate limit headers (default: true)
  legacyHeaders?: boolean // Add legacy X-RateLimit headers (default: true)
  store?: 'memory' | 'redis' // Storage backend (default: redis if available, else memory)
}

interface RateLimitInfo {
  limit: number
  remaining: number
  reset: number
  resetTime: Date
}

interface RateLimitStore {
  increment(key: string): Promise<number>
  decrement(key: string): Promise<void>
  resetKey(key: string): Promise<void>
  get(key: string): Promise<number>
}

class MemoryStore implements RateLimitStore {
  private hits: Map<string, { count: number; resetTime: number }> = new Map()
  private windowMs: number

  constructor(windowMs: number) {
    this.windowMs = windowMs
    this.startCleanupInterval()
  }

  async increment(key: string): Promise<number> {
    const now: number = Date.now()
    const record = this.hits.get(key)

    if (!record || now > record.resetTime) {
      this.hits.set(key, {
        count: 1,
        resetTime: now + this.windowMs
      })
      return 1
    }

    record.count++
    return record.count
  }

  async decrement(key: string): Promise<void> {
    const record = this.hits.get(key)
    if (record && record.count > 0) {
      record.count--
    }
  }

  async resetKey(key: string): Promise<void> {
    this.hits.delete(key)
  }

  async get(key: string): Promise<number> {
    const now: number = Date.now()
    const record = this.hits.get(key)

    if (!record || now > record.resetTime) {
      return 0
    }
    return record.count
  }

  private startCleanupInterval(): void {
    // Clean up expired entries every minute
    setInterval((): void => {
      const now = Date.now()
      for (const [key, record] of this.hits.entries()) {
        if (now > record.resetTime) {
          this.hits.delete(key)
        }
      }
    }, 60000)
  }
}

class RedisStore implements RateLimitStore {
  private client: RedisClientType
  private windowMs: number

  constructor(client: RedisClientType, windowMs: number) {
    this.client = client
    this.windowMs = windowMs
  }

  async increment(key: string): Promise<number> {
    const prefixedKey: string = `ratelimit:${key}`

    try {
      const current: number = await this.client.incr(prefixedKey)

      // Set expiration on first request
      if (current === 1) {
        await this.client.pExpire(prefixedKey, this.windowMs)
      }

      return current
    } catch (error: unknown) {
      logger.error('Redis rate limit increment error:', error)
      // Fallback: allow request if Redis fails
      return 0
    }
  }

  async decrement(key: string): Promise<void> {
    const prefixedKey: string = `ratelimit:${key}`

    try {
      const current: string | null = await this.client.get(prefixedKey)
      if (current && parseInt(current) > 0) {
        await this.client.decr(prefixedKey)
      }
    } catch (error: unknown) {
      logger.error('Redis rate limit decrement error:', error)
    }
  }

  async resetKey(key: string): Promise<void> {
    const prefixedKey: string = `ratelimit:${key}`

    try {
      await this.client.del(prefixedKey)
    } catch (error: unknown) {
      logger.error('Redis rate limit reset error:', error)
    }
  }

  async get(key: string): Promise<number> {
    const prefixedKey: string = `ratelimit:${key}`

    try {
      const value: string | null = await this.client.get(prefixedKey)
      return value ? parseInt(value) : 0
    } catch (error: unknown) {
      logger.error('Redis rate limit get error:', error)
      return 0
    }
  }
}

function defaultKeyGenerator(ctx: Context<Generics>): string {
  const ip: string = remoteAddr(ctx)
  const path: string = ctx.req.path
  const method: string = ctx.req.method
  // Include user ID if authenticated
  try {
    const userId: string = ctx.get('session')._id
    if (userId) {
      return `${userId}:${method}:${path}`
    }
  } catch (_error) {
    //
  }
  return `${ip}:${method}:${path}`
}

function addRateLimitHeaders(ctx: Context<Generics>, info: RateLimitInfo, standardHeaders: boolean, legacyHeaders: boolean): void {
  if (standardHeaders) {
    ctx.header('RateLimit-Limit', info.limit.toString())
    ctx.header('RateLimit-Remaining', Math.max(0, info.remaining).toString())
    ctx.header('RateLimit-Reset', info.reset.toString())
  }

  if (legacyHeaders) {
    ctx.header('X-RateLimit-Limit', info.limit.toString())
    ctx.header('X-RateLimit-Remaining', Math.max(0, info.remaining).toString())
    ctx.header('X-RateLimit-Reset', info.resetTime.toISOString())
  }

  if (info.remaining <= 0) {
    const retryAfter: number = Math.ceil((info.resetTime.getTime() - Date.now()) / 1000)
    ctx.header('Retry-After', Math.max(0, retryAfter).toString())
  }
}

const storeCache = new Map<string, RateLimitStore>()
let storeInitialized: boolean = false

function getOrCreateStore(storeType: 'memory' | 'redis', windowMs: number): RateLimitStore {
  const key: string = `${storeType}:${windowMs}`
  const existing: RateLimitStore | undefined = storeCache.get(key)

  if (existing) {
    return existing
  }

  let store: RateLimitStore

  if (storeType === 'redis' && redisClient?.isOpen) {
    store = new RedisStore(redisClient as RedisClientType, windowMs)
    if (!storeInitialized) {
      logger.info('Rate limiter using Redis store')
      storeInitialized = true
    }
  } else {
    store = new MemoryStore(windowMs)
    if (!storeInitialized) {
      logger.info('Rate limiter using memory store')
      storeInitialized = true
    }
  }

  storeCache.set(key, store)
  return store
}

export function rateLimitMiddleware(options: RateLimitOptions = {}) {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    max = 100,
    message = 'Too many requests, please try again later',
    skipSuccessfulRequests = false,
    skipFailedRequests = false,
    keyGenerator = defaultKeyGenerator,
    handler,
    skip,
    onLimitReached,
    standardHeaders = true,
    legacyHeaders = true,
    store: storeType = 'redis'
  } = options
  // Get or create store (singleton)
  const store: RateLimitStore = getOrCreateStore(storeType, windowMs)

  return createMiddleware(async (ctx: Context<Generics>, next: Next) => {
    // Check if middleware should be skipped
    if (skip && (await skip(ctx))) {
      return next()
    }

    // Generate unique key for this request
    const key: string = keyGenerator(ctx)
    // Get current count
    const currentCount: number = await store.increment(key)
    // Calculate rate limit info
    const resetTime: Date = new Date(Date.now() + windowMs)
    const rateLimitInfo: RateLimitInfo = {
      limit: max,
      remaining: max - currentCount,
      reset: Math.ceil(resetTime.getTime() / 1000),
      resetTime
    }

    // Add rate limit headers
    addRateLimitHeaders(ctx, rateLimitInfo, standardHeaders, legacyHeaders)

    // Check if limit exceeded
    if (currentCount > max) {
      // Call callback if provided
      if (onLimitReached) {
        await onLimitReached(ctx)
      }
      // Log rate limit hit
      logger.warning('Rate limit exceeded', {
        key,
        count: currentCount,
        limit: max,
        ip: remoteAddr(ctx),
        path: ctx.req.path,
        method: ctx.req.method
      })
      // Custom handler or default response
      if (handler) {
        return handler(ctx, next)
      }
      return httpResponse.tooManyRequests(ctx, message)
    }
    // Proceed with request
    await next()
    // Handle conditional request counting
    const responseStatus: number = ctx.res.status
    const shouldSkip: boolean = (skipSuccessfulRequests && responseStatus < 400) || (skipFailedRequests && responseStatus >= 400)

    if (shouldSkip) {
      // Decrement counter if we should skip this request
      await store.decrement(key)
    }
  })
}

// Strict rate limiter for authentication endpoints
export const authRateLimiter: MiddlewareHandler = rateLimitMiddleware({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per 15 minutes
  message: 'Too many authentication attempts, please try again later',
  skipSuccessfulRequests: true, // Only count failed sign in attempts
  keyGenerator: (ctx: Context<Generics>): string => {
    const ip: string = remoteAddr(ctx)
    return `auth:${ip}`
  }
})

// General API rate limiter
export const apiRateLimiter: MiddlewareHandler = rateLimitMiddleware({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: 'API rate limit exceeded'
})

// Strict rate limiter for write operations
export const writeRateLimiter: MiddlewareHandler = rateLimitMiddleware({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // 10 write operations per minute
  keyGenerator: (ctx: Context<Generics>): string => {
    const _id = ctx.get('session')._id || remoteAddr(ctx)
    return `write:${_id}`
  }
})

// Lenient rate limiter for read operations
export const readRateLimiter: MiddlewareHandler = rateLimitMiddleware({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100 // 100 read operations per minute
})

// File upload rate limiter
export const uploadRateLimiter: MiddlewareHandler = rateLimitMiddleware({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 uploads per hour
  message: 'Upload limit exceeded, please try again later',
  keyGenerator: (ctx: Context<Generics>): string => {
    const userId: string = ctx.get('session')._id || remoteAddr(ctx)
    return `upload:${userId}`
  }
})

// Export store classes for testing
export { MemoryStore, RedisStore }
