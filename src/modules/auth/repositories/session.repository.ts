import type { Session, NewSession } from '@/modules/auth/models/sessions.model'

import { db } from '@/database/connection'
import { logger } from '@/configs/logger.configs'
import { and, eq, gt, isNull } from 'drizzle-orm'
import { sessions } from '@/modules/auth/models/sessions.model'

export class SessionRepository {
  /**
   * Create a new session record.
   */
  async create(data: NewSession): Promise<Session> {
    try {
      const [session]: Array<Session> = await db.insert(sessions).values(data).returning()
      return session
    } catch (error: unknown) {
      logger.error('Error creating session', { error })
      throw new Error('Failed to create session', { cause: error })
    }
  }

  /**
   * Find a session by its DB primary key.
   */
  async findById(id: string): Promise<Session | null> {
    try {
      const [session]: Array<Session> = await db.select().from(sessions).where(eq(sessions._id, id)).limit(1)
      return session ?? null
    } catch (error: unknown) {
      logger.error('Error finding session by ID', { error, id })
      throw new Error('Failed to find session', { cause: error })
    }
  }

  /**
   * Find a session by channelId (JWT `_sid`).
   */
  async findByChannelId(channelId: string): Promise<Session | null> {
    try {
      const [session]: Array<Session> = await db.select().from(sessions).where(eq(sessions.channelId, channelId)).limit(1)
      return session ?? null
    } catch (error: unknown) {
      logger.error('Error finding session by channelId', { error, channelId })
      throw new Error('Failed to find session', { cause: error })
    }
  }

  /**
   * Return all non-revoked, non-expired sessions for a user.
   */
  async findActiveByUserId(userId: string): Promise<Array<Session>> {
    try {
      return db
        .select()
        .from(sessions)
        .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt), gt(sessions.expiresAt, new Date())))
    } catch (error: unknown) {
      logger.error('Error finding active sessions', { error, userId })
      throw new Error('Failed to find sessions', { cause: error })
    }
  }

  /**
   * Touch lastSeenAt for the session identified by channelId.
   * Used on every successful token refresh.
   */
  async updateLastSeen(channelId: string): Promise<void> {
    try {
      await db.update(sessions).set({ lastSeenAt: new Date() }).where(eq(sessions.channelId, channelId))
    } catch (error: unknown) {
      logger.error('Error updating session lastSeenAt', { error, channelId })
      // Non-critical — do not throw; a failed lastSeenAt update should not break token refresh.
    }
  }

  /**
   * Revoke a session by its DB primary key.
   * Returns the revoked session or null if not found.
   */
  async revokeById(id: string): Promise<Session | null> {
    try {
      const [session]: Array<Session> = await db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions._id, id)).returning()
      return session ?? null
    } catch (error: unknown) {
      logger.error('Error revoking session by ID', { error, id })
      throw new Error('Failed to revoke session', { cause: error })
    }
  }

  /**
   * Revoke the session identified by channelId (e.g. on sign-out).
   */
  async revokeByChannelId(channelId: string): Promise<void> {
    try {
      await db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.channelId, channelId))
    } catch (error: unknown) {
      logger.error('Error revoking session by channelId', { error, channelId })
      throw new Error('Failed to revoke session', { cause: error })
    }
  }

  /**
   * Revoke all non-revoked sessions for a user (e.g. on password change/reset).
   * Returns the revoked sessions so callers can clean up their Redis tokens.
   */
  async revokeAllByUserId(userId: string): Promise<Array<Session>> {
    try {
      return db
        .update(sessions)
        .set({ revokedAt: new Date() })
        .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
        .returning()
    } catch (error: unknown) {
      logger.error('Error revoking all sessions', { error, userId })
      throw new Error('Failed to revoke sessions', { cause: error })
    }
  }
}
