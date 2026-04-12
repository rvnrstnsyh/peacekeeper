import type { RedisClientType } from 'redis'

import { createClient } from 'redis'
import { logger } from '@/configs/logger.configs'
import { env } from '@/configs/environment.configs'

interface CacheOptions {
  ttl?: number
  nx?: boolean // Set only if not exists
  xx?: boolean // Set only if exists
}

interface RedisConfig {
  enabled: boolean
  host: string
  port: number
  password?: string
  db: number
  ttl: number
  maxRetries: number
  retryDelay: number
  connectionTimeout?: number
  enableOfflineQueue?: boolean
}

// Singleton Redis client
let redisClient: RedisClientType | null = null
let isConnecting = false
let lastReconnectAttempt = 0

/**
 * Get Redis configuration from environment
 */
function getRedisConfig(): RedisConfig {
  return {
    enabled: env.REDIS_ENABLED,
    host: env.REDIS_HOST,
    port: env.REDIS_PORT,
    password: env.REDIS_PASSWORD,
    db: env.REDIS_DB,
    ttl: env.REDIS_TTL,
    maxRetries: env.REDIS_MAX_RETRIES,
    retryDelay: env.REDIS_RETRY_DELAY,
    connectionTimeout: env.REDIS_CONNECTION_TIMEOUT,
    enableOfflineQueue: env.REDIS_ENABLE_OFFLINE_QUEUE
  }
}

/**
 * Connect to Redis with retry logic
 */
export async function connectRedis(): Promise<RedisClientType | null> {
  const config: RedisConfig = getRedisConfig()

  if (!config.enabled) return null
  if (redisClient?.isOpen) return redisClient
  if (isConnecting) {
    await waitForConnection()
    return redisClient
  }

  isConnecting = true

  try {
    redisClient = createClient({
      socket: {
        host: config.host,
        port: config.port,
        connectTimeout: config.connectionTimeout,
        reconnectStrategy: createReconnectStrategy(config)
      },
      password: config.password || undefined,
      database: config.db,
      disableOfflineQueue: !config.enableOfflineQueue
    })

    setupEventHandlers(redisClient, config)

    // Connect with timeout
    await Promise.race([redisClient.connect(), new Promise((_, reject) => setTimeout(() => reject(new Error('Redis connection timeout')), config.connectionTimeout))])

    isConnecting = false
    lastReconnectAttempt = 0

    logger.info('Redis connection established successfully', {
      host: config.host,
      port: config.port,
      db: config.db
    })

    return redisClient
  } catch (error) {
    isConnecting = false

    logger.error('Failed to connect to Redis', {
      error,
      lastReconnectAttempt,
      maxAttempts: config.maxRetries
    })

    return null
  }
}

function createReconnectStrategy(config: RedisConfig) {
  return function (retries: number): number | Error {
    lastReconnectAttempt = retries

    if (retries >= config.maxRetries) {
      logger.error(`Max Redis reconnection attempts reached (${config.maxRetries}/${config.maxRetries})`)
      return new Error('Max reconnection attempts exceeded')
    }

    // Delay (exponential capped)
    const delay: number = Math.min(
      config.retryDelay * retries,
      30000 // hard cap
    )

    logger.warning(`Redis reconnecting in ${delay}ms (attempt ${retries}/${config.maxRetries})`)
    return delay
  }
}

/**
 * Setup Redis event handlers
 */
function setupEventHandlers(client: RedisClientType, config: RedisConfig): void {
  client.on('error', (error: Error): void => {
    logger.error('Redis Client Error', { error: error.message })
  })

  client.on('connect', (): void => {
    logger.info('Redis client connecting...', {
      host: config.host,
      port: config.port
    })
  })

  client.on('ready', (): void => {
    logger.info('Redis client ready for commands')
    lastReconnectAttempt = 0
  })

  client.on('reconnecting', (): void => {
    logger.warning('Redis client reconnecting...', {
      attempt: lastReconnectAttempt
    })
  })

  client.on('end', (): void => {
    logger.info('Redis connection closed')
  })
}

/**
 * Wait for connection to complete
 */
async function waitForConnection(timeout: number = 10000): Promise<void> {
  const startTime: number = Date.now()

  while (isConnecting && Date.now() - startTime < timeout) {
    await new Promise((resolve) => setTimeout(resolve, 100))
  }

  if (isConnecting) {
    throw new Error('Timeout waiting for Redis connection')
  }
}

/**
 * Disconnect from Redis gracefully
 */
export async function disconnectRedis(): Promise<void> {
  if (!redisClient) return

  try {
    if (redisClient.isOpen) {
      await redisClient.quit()
    }
  } catch (err) {
    logger.error('Error disconnecting Redis', err)
    try {
      redisClient.destroy()
    } catch (_) {
      //
    }
  } finally {
    redisClient = null
    isConnecting = false
    lastReconnectAttempt = 0
  }
}

/**
 * Get Redis client instance
 */
export function getRedisClient(): RedisClientType | null {
  return redisClient
}

/**
 * Check if Redis is available
 */
export function isRedisAvailable(): boolean {
  return redisClient?.isOpen ?? false
}

/**
 * Health check for Redis connection
 */
export async function healthCheck(): Promise<boolean> {
  if (!redisClient?.isOpen) {
    return false
  }

  try {
    const response: string = await redisClient.ping()
    return response === 'PONG'
  } catch (error: unknown) {
    logger.error('Redis health check failed', { error })
    return false
  }
}

/**
 * Set cache with enhanced options
 */
export async function setCache(key: string, value: string | number | Record<string, unknown> | Array<unknown>, options: CacheOptions = {}): Promise<boolean> {
  if (!redisClient?.isOpen) {
    logger.warning('Redis not available, cache set skipped', { key })
    return false
  }

  try {
    const config: RedisConfig = getRedisConfig()
    const ttl: number = options.ttl ?? config.ttl
    const serialized: string = typeof value === 'string' ? value : JSON.stringify(value)
    const setOptions: Record<string, unknown> = { EX: ttl }

    if (options.nx) setOptions.NX = true
    if (options.xx) setOptions.XX = true

    await redisClient.set(key, serialized, setOptions)

    logger.debug('Cache set successfully', { key, ttl })
    return true
  } catch (error: unknown) {
    logger.error('Error setting cache', { error, key })
    return false
  }
}

/**
 * Get cache with type safety
 */
export async function getCache<T = string>(key: string): Promise<T | null> {
  if (!redisClient?.isOpen) {
    logger.warning('Redis not available, cache get skipped', { key })
    return null
  }

  try {
    const value: string | null = await redisClient.get(key)

    if (!value) return null

    // Try to parse as JSON, otherwise return as string
    try {
      return JSON.parse(value) as T
    } catch {
      return value as T
    }
  } catch (error: unknown) {
    logger.error('Error getting cache', { error, key })
    return null
  }
}

/**
 * Get multiple cache keys at once
 */
export async function getManyCache<T = string>(keys: Array<string>): Promise<Map<string, T | null>> {
  const result: Map<string, T | null> = new Map()

  if (!redisClient?.isOpen || keys.length === 0) {
    return result
  }

  try {
    const values: Array<string | null> = await redisClient.mGet(keys)

    keys.forEach((key: string, index: number): void => {
      const value: string | null = values[index]
      if (!value) {
        result.set(key, null)
        return
      }

      try {
        result.set(key, JSON.parse(value) as T)
      } catch {
        result.set(key, value as T)
      }
    })

    return result
  } catch (error: unknown) {
    logger.error('Error getting multiple cache keys', { error, keys })
    return result
  }
}

/**
 * Set multiple cache keys at once
 */
export async function setManyCache(entries: Map<string, string | number | Record<string, unknown>>, ttl?: number): Promise<boolean> {
  if (!redisClient?.isOpen || entries.size === 0) {
    return false
  }

  try {
    const pipeline = redisClient.multi()

    for (const [key, value] of entries) {
      const serialized: string = typeof value === 'string' ? value : JSON.stringify(value)
      const config: RedisConfig = getRedisConfig()
      const cacheTtl: number = ttl ?? config.ttl

      pipeline.set(key, serialized, { EX: cacheTtl })
    }

    await pipeline.exec()
    logger.debug('Multiple cache keys set successfully', {
      count: entries.size
    })
    return true
  } catch (error: unknown) {
    logger.error('Error setting multiple cache keys', { error })
    return false
  }
}

/**
 * Delete cache
 */
export async function deleteCache(...keys: Array<string>): Promise<number> {
  if (!redisClient?.isOpen || keys.length === 0) {
    return 0
  }

  try {
    const deleted: number = await redisClient.del(keys)
    logger.debug('Cache deleted', { keys, deleted })
    return deleted
  } catch (error: unknown) {
    logger.error('Error deleting cache', { error, keys })
    return 0
  }
}

/**
 * Delete cache by pattern with SCAN for better performance
 */
export async function deleteCachePattern(pattern: string): Promise<number | undefined> {
  if (!redisClient?.isOpen) {
    return 0
  }

  try {
    let cursor: string = '0'
    let deletedCount: number = 0
    const batchSize: number = 100

    do {
      const { cursor: nextCursor, keys }: { cursor: string; keys: string[] } = await redisClient.scan(cursor, {
        MATCH: pattern,
        COUNT: batchSize
      })

      cursor = nextCursor

      if (keys.length > 0) {
        const multi = redisClient.multi()

        for (const key of keys) {
          multi.del(key)
        }

        const results = await multi.exec()

        for (const res of results) {
          if (typeof res === 'number') {
            deletedCount += res
          }
        }
      }
    } while (cursor !== '0')

    logger.info('Cache pattern deleted', { pattern, count: deletedCount })
    return deletedCount
  } catch (error: unknown) {
    logger.error('Error deleting cache pattern', { error, pattern })
  }
}

/**
 * Check if key exists
 */
export async function cacheExists(...keys: Array<string>): Promise<number> {
  if (!redisClient?.isOpen || keys.length === 0) {
    return 0
  }

  try {
    const result: number = await redisClient.exists(keys)
    return typeof result === 'number' ? result : 0
  } catch (error: unknown) {
    logger.error('Error checking cache existence', { error, keys })
    return 0
  }
}

/**
 * Set cache with hash
 */
export async function setHashCache(key: string, field: string, value: string | number | Record<string, unknown>): Promise<boolean> {
  if (!redisClient?.isOpen) {
    return false
  }

  try {
    const serialized: string = typeof value === 'string' ? value : JSON.stringify(value)
    await redisClient.hSet(key, field, serialized)
    return true
  } catch (error: unknown) {
    logger.error('Error setting hash cache', { error, key, field })
    return false
  }
}

/**
 * Set multiple hash fields at once
 */
export async function setHashCacheMultiple(key: string, data: Record<string, string | number | Record<string, unknown>>): Promise<boolean> {
  if (!redisClient?.isOpen) {
    return false
  }

  try {
    const serialized: Record<string, string> = {}

    for (const [field, value] of Object.entries(data)) {
      serialized[field] = typeof value === 'string' ? value : JSON.stringify(value)
    }

    await redisClient.hSet(key, serialized)
    return true
  } catch (error: unknown) {
    logger.error('Error setting multiple hash fields', { error, key })
    return false
  }
}

/**
 * Get cache from hash
 */
export async function getHashCache<T = string>(key: string, field: string): Promise<T | null> {
  if (!redisClient?.isOpen) {
    return null
  }

  try {
    const value: string | null = await redisClient.hGet(key, field)
    if (!value) return null

    try {
      return JSON.parse(value) as T
    } catch {
      return value as T
    }
  } catch (error: unknown) {
    logger.error('Error getting hash cache', { error, key, field })
    return null
  }
}

/**
 * Get all hash fields
 */
export async function getAllHashCache(key: string): Promise<Record<string, string> | null> {
  if (!redisClient?.isOpen) {
    return null
  }

  try {
    return await redisClient.hGetAll(key)
  } catch (error: unknown) {
    logger.error('Error getting all hash cache', { error, key })
    return null
  }
}

/**
 * Delete hash field
 */
export async function deleteHashField(key: string, ...fields: Array<string>): Promise<number> {
  if (!redisClient?.isOpen || fields.length === 0) {
    return 0
  }

  try {
    return await redisClient.hDel(key, fields)
  } catch (error: unknown) {
    logger.error('Error deleting hash fields', { error, key, fields })
    return 0
  }
}

/**
 * Increment counter with automatic initialization
 */
export async function incrementCounter(key: string, amount: number = 1): Promise<number> {
  if (!redisClient?.isOpen) {
    return 0
  }

  try {
    return await redisClient.incrBy(key, amount)
  } catch (error: unknown) {
    logger.error('Error incrementing counter', { error, key, amount })
    return 0
  }
}

/**
 * Decrement counter
 */
export async function decrementCounter(key: string, amount: number = 1): Promise<number> {
  if (!redisClient?.isOpen) {
    return 0
  }

  try {
    return await redisClient.decrBy(key, amount)
  } catch (error: unknown) {
    logger.error('Error decrementing counter', { error, key, amount })
    return 0
  }
}

/**
 * Get counter value
 */
export async function getCounter(key: string): Promise<number> {
  if (!redisClient?.isOpen) {
    return 0
  }

  try {
    const value: string | null = await redisClient.get(key)
    return value ? parseInt(value, 10) : 0
  } catch (error: unknown) {
    logger.error('Error getting counter', { error, key })
    return 0
  }
}

/**
 * Add to set
 */
export async function addToSet(key: string, ...members: Array<string>): Promise<number> {
  if (!redisClient?.isOpen || members.length === 0) {
    return 0
  }

  try {
    return await redisClient.sAdd(key, members)
  } catch (error: unknown) {
    logger.error('Error adding to set', { error, key })
    return 0
  }
}

/**
 * Remove from set
 */
export async function removeFromSet(key: string, ...members: Array<string>): Promise<number> {
  if (!redisClient?.isOpen || members.length === 0) {
    return 0
  }

  try {
    return await redisClient.sRem(key, members)
  } catch (error: unknown) {
    logger.error('Error removing from set', { error, key })
    return 0
  }
}

/**
 * Get all set members
 */
export async function getSetMembers(key: string): Promise<Array<string>> {
  if (!redisClient?.isOpen) {
    return []
  }

  try {
    return await redisClient.sMembers(key)
  } catch (error: unknown) {
    logger.error('Error getting set members', { error, key })
    return []
  }
}

/**
 * Get set size
 */
export async function getSetSize(key: string): Promise<number> {
  if (!redisClient?.isOpen) {
    return 0
  }

  try {
    return await redisClient.sCard(key)
  } catch (error: unknown) {
    logger.error('Error getting set size', { error, key })
    return 0
  }
}

/**
 * Check if member exists in set
 */
export async function isSetMember(key: string, member: string): Promise<boolean> {
  if (!redisClient?.isOpen) {
    return false
  }

  try {
    const result: number = await redisClient.sIsMember(key, member)

    if (typeof result === 'number') {
      return result === 1
    }

    return !!result
  } catch (error: unknown) {
    logger.error('Error checking set membership', { error, key })
    return false
  }
}

/**
 * Add to sorted set with score
 */
export async function addToSortedSet(key: string, members: Array<{ value: string; score: number }>): Promise<number> {
  if (!redisClient?.isOpen || members.length === 0) {
    return 0
  }

  try {
    const args: Array<{ value: string; score: number }> = members.map((m) => ({
      value: m.value,
      score: m.score
    }))
    return await redisClient.zAdd(key, args)
  } catch (error: unknown) {
    logger.error('Error adding to sorted set', { error, key })
    return 0
  }
}

/**
 * Get sorted set range
 */
export async function getSortedSetRange(key: string, start: number = 0, stop: number = -1, reverse: boolean = false): Promise<Array<string>> {
  if (!redisClient?.isOpen) {
    return []
  }

  try {
    if (reverse) {
      return await redisClient.zRange(key, start, stop, { REV: true })
    }
    return await redisClient.zRange(key, start, stop)
  } catch (error: unknown) {
    logger.error('Error getting sorted set range', { error, key })
    return []
  }
}

/**
 * Get sorted set range with scores
 */
export async function getSortedSetRangeWithScores(key: string, start: number = 0, stop: number = -1, reverse: boolean = false): Promise<Array<{ value: string; score: number }>> {
  if (!redisClient?.isOpen) {
    return []
  }

  try {
    const options = reverse ? { REV: true, WITHSCORES: true } : { WITHSCORES: true }
    const raw: Array<string> = await redisClient.zRange(key, start, stop, options)
    // raw: string[] → [value, score, value, score, ...]
    const parsed: Array<{ value: string; score: number }> = []

    for (let i = 0; i < raw.length; i += 2) {
      const value: string = raw[i]
      const score: number = Number(raw[i + 1])

      parsed.push({ value, score })
    }

    return parsed
  } catch (error: unknown) {
    logger.error('Error getting sorted set range with scores', { error, key })
    return []
  }
}

/**
 * Push to list (left)
 */
export async function pushToList(key: string, ...values: Array<string>): Promise<number> {
  if (!redisClient?.isOpen || values.length === 0) {
    return 0
  }

  try {
    return await redisClient.lPush(key, values)
  } catch (error: unknown) {
    logger.error('Error pushing to list', { error, key })
    return 0
  }
}

/**
 * Pop from list (left)
 */
export async function popFromList(key: string): Promise<string | null> {
  if (!redisClient?.isOpen) {
    return null
  }

  try {
    return await redisClient.lPop(key)
  } catch (error: unknown) {
    logger.error('Error popping from list', { error, key })
    return null
  }
}

/**
 * Get list range
 */
export async function getListRange(key: string, start: number = 0, stop: number = -1): Promise<Array<string>> {
  if (!redisClient?.isOpen) {
    return []
  }

  try {
    return await redisClient.lRange(key, start, stop)
  } catch (error: unknown) {
    logger.error('Error getting list range', { error, key })
    return []
  }
}

/**
 * Get list length
 */
export async function getListLength(key: string): Promise<number> {
  if (!redisClient?.isOpen) {
    return 0
  }

  try {
    return await redisClient.lLen(key)
  } catch (error: unknown) {
    logger.error('Error getting list length', { error, key })
    return 0
  }
}

/**
 * Get TTL of key
 */
export async function getTTL(key: string): Promise<number> {
  if (!redisClient?.isOpen) {
    return -2
  }

  try {
    return await redisClient.ttl(key)
  } catch (error: unknown) {
    logger.error('Error getting TTL', { error, key })
    return -2
  }
}

/**
 * Set expiry on existing key
 */
export async function setExpiry(key: string, ttl: number): Promise<boolean> {
  if (!redisClient?.isOpen) {
    return false
  }

  try {
    const result: number = await redisClient.expire(key, ttl)
    if (typeof result === 'number') {
      return result === 1
    }

    return !!result
  } catch (error: unknown) {
    logger.error('Error setting expiry', { error, key, ttl })
    return false
  }
}

/**
 * Remove expiry from key
 */
export async function removeExpiry(key: string): Promise<boolean> {
  if (!redisClient?.isOpen) {
    return false
  }

  try {
    const result: number = await redisClient.persist(key)
    if (typeof result === 'number') {
      return result === 1
    }

    return !!result
  } catch (error: unknown) {
    logger.error('Error removing expiry', { error, key })
    return false
  }
}

/**
 * Execute atomic transaction
 */
export async function executeTransaction(operations: Array<() => Promise<unknown>>): Promise<Array<unknown> | null> {
  if (!redisClient?.isOpen) {
    return null
  }

  try {
    const multi = redisClient.multi()

    for (const operation of operations) {
      await operation()
    }

    return await multi.exec()
  } catch (error: unknown) {
    logger.error('Error executing transaction', { error })
    return null
  }
}

/**
 * Get Redis info
 */
export async function getRedisInfo(): Promise<string | null> {
  if (!redisClient?.isOpen) {
    return null
  }

  try {
    return await redisClient.info()
  } catch (error: unknown) {
    logger.error('Error getting Redis info', { error })
    return null
  }
}

/**
 * Get database size
 */
export async function getDatabaseSize(): Promise<number> {
  if (!redisClient?.isOpen) {
    return 0
  }

  try {
    return await redisClient.dbSize()
  } catch (error: unknown) {
    logger.error('Error getting database size', { error })
    return 0
  }
}

/**
 * Flush current database
 */
export async function flushDatabase(): Promise<boolean> {
  if (!redisClient?.isOpen) {
    return false
  }

  try {
    await redisClient.flushDb()
    logger.warning('Redis database flushed')
    return true
  } catch (error: unknown) {
    logger.error('Error flushing database', { error })
    return false
  }
}

/**
 * Flush all databases (use with extreme caution!)
 */
export async function flushAll(): Promise<boolean> {
  if (!redisClient?.isOpen) {
    return false
  }

  try {
    await redisClient.flushAll()
    logger.warning('All Redis databases flushed')
    return true
  } catch (error: unknown) {
    logger.error('Error flushing all databases', { error })
    return false
  }
}

// Export client and all functions
export { redisClient }

export default {
  // Connection management
  connectRedis,
  disconnectRedis,
  getRedisClient,
  isRedisAvailable,
  healthCheck,

  // Basic operations
  setCache,
  getCache,
  getManyCache,
  setManyCache,
  deleteCache,
  deleteCachePattern,
  cacheExists,

  // Hash operations
  setHashCache,
  setHashCacheMultiple,
  getHashCache,
  getAllHashCache,
  deleteHashField,

  // Counter operations
  incrementCounter,
  decrementCounter,
  getCounter,

  // Set operations
  addToSet,
  removeFromSet,
  getSetMembers,
  getSetSize,
  isSetMember,

  // Sorted set operations
  addToSortedSet,
  getSortedSetRange,
  getSortedSetRangeWithScores,

  // List operations
  pushToList,
  popFromList,
  getListRange,
  getListLength,

  // TTL operations
  getTTL,
  setExpiry,
  removeExpiry,

  // Advanced operations
  executeTransaction,
  getRedisInfo,
  getDatabaseSize,
  flushDatabase,
  flushAll
}
