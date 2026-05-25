import type { ApiKey, NewApiKey } from '@/modules/auth/models/api-keys.model'

import { db } from '@/database/connection'
import { logger } from '@/configs/logger.configs'
import { apiKeys } from '@/modules/auth/models/api-keys.model'
import { and, count, desc, eq, isNull, sql } from 'drizzle-orm'

export class ApiKeysRepository {
  /**
   * Find an API key by its SHA-256 hash.
   * Used by the authentication middleware on every API request.
   */
  async findByHash(keyHash: string): Promise<ApiKey | null> {
    try {
      const [key]: Array<ApiKey> = await db
        .select()
        .from(apiKeys)
        .where(and(eq(apiKeys.keyHash, keyHash), isNull(apiKeys.deletedAt)))
        .limit(1)

      return key || null
    } catch (error: unknown) {
      logger.error('Error finding API key by hash', { error })
      throw new Error('Failed to find API key', { cause: error })
    }
  }

  /**
   * List all API keys belonging to a user, newest first.
   */
  async findByUserId(userId: string): Promise<Array<ApiKey>> {
    try {
      return await db
        .select()
        .from(apiKeys)
        .where(and(eq(apiKeys.userId, userId), isNull(apiKeys.deletedAt)))
        .orderBy(desc(apiKeys.createdAt))
    } catch (error: unknown) {
      logger.error('Error listing API keys for user', { error, userId })
      throw new Error('Failed to list API keys', { cause: error })
    }
  }

  /**
   * Create a new API key row.
   */
  async create(data: NewApiKey): Promise<ApiKey> {
    try {
      const [key]: Array<ApiKey> = await db.insert(apiKeys).values(data).returning()

      return key
    } catch (error: unknown) {
      logger.error('Error creating API key', { error })
      throw new Error('Failed to create API key', { cause: error })
    }
  }

  /**
   * Revoke an API key owned by userId.
   * Returns null if the key does not exist, is not owned by the user,
   * or is already revoked.
   */
  async revoke(id: string, userId: string, reason?: string): Promise<ApiKey | null> {
    try {
      const [updated]: Array<ApiKey> = await db
        .update(apiKeys)
        .set({ status: 'revoked', revokedAt: new Date(), revokedReason: reason ?? null, updatedAt: new Date() })
        .where(and(eq(apiKeys._id, id), eq(apiKeys.userId, userId), eq(apiKeys.status, 'active')))
        .returning()

      return updated || null
    } catch (error: unknown) {
      logger.error('Error revoking API key', { error, id, userId })
      throw new Error('Failed to revoke API key', { cause: error })
    }
  }

  /**
   * Atomically bump usage statistics after a successful authentication.
   * Non-blocking — callers should fire-and-forget with .catch().
   */
  /**
   * Count the number of active (non-revoked, non-expired, non-deleted) keys for a user.
   */
  async countActiveByUserId(userId: string): Promise<number> {
    try {
      const [result] = await db
        .select({ count: count() })
        .from(apiKeys)
        .where(and(eq(apiKeys.userId, userId), eq(apiKeys.status, 'active'), isNull(apiKeys.deletedAt)))

      return result?.count ?? 0
    } catch (error: unknown) {
      logger.error('Error counting active API keys for user', { error, userId })
      throw new Error('Failed to count API keys', { cause: error })
    }
  }

  async touch(id: string, ip: string): Promise<void> {
    try {
      await db
        .update(apiKeys)
        .set({
          lastUsedAt: new Date(),
          lastUsedIp: ip,
          usageCount: sql`(${apiKeys.usageCount}::bigint + 1)::text`,
          updatedAt: new Date()
        })
        .where(and(eq(apiKeys._id, id), eq(apiKeys.status, 'active'), isNull(apiKeys.deletedAt)))
    } catch (error: unknown) {
      logger.error('Error updating API key usage stats', { error, id })
    }
  }
}
