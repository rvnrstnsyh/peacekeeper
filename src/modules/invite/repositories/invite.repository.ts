import type { Invitation, NewInvitation } from '@/modules/invite/models/invitations.model'

import { db } from '@/database/connection'
import { logger } from '@/configs/logger.configs'
import { invitations } from '@/modules/invite/models/invitations.model'
import { and, count, desc, eq, isNull, or, sql } from 'drizzle-orm'

export class InvitationRepository {
  /**
   * Find an invitation by its unique code
   */
  async findByCode(code: string): Promise<Invitation | null> {
    try {
      const [invitation]: Array<Invitation> = await db.select().from(invitations).where(eq(invitations.code, code)).limit(1)

      return invitation || null
    } catch (error: unknown) {
      logger.error('Error finding invitation by code', { error, code })
      throw new Error('Failed to find invitation', { cause: error })
    }
  }

  /**
   * Find an invitation by its UUID
   */
  async findById(id: string): Promise<Invitation | null> {
    try {
      const [invitation]: Array<Invitation> = await db.select().from(invitations).where(eq(invitations._id, id)).limit(1)

      return invitation || null
    } catch (error: unknown) {
      logger.error('Error finding invitation by id', { error, id })
      throw new Error('Failed to find invitation', { cause: error })
    }
  }

  /**
   * List all non-deleted invitations created by a specific user (newest first)
   */
  async findByCreatorId(creatorId: string): Promise<Array<Invitation>> {
    try {
      return await db.select().from(invitations).where(eq(invitations.creatorId, creatorId)).orderBy(desc(invitations.createdAt))
    } catch (error: unknown) {
      logger.error('Error listing invitations for creator', { error, creatorId })
      throw new Error('Failed to list invitations', { cause: error })
    }
  }

  /**
   * Count all invitations created by a specific user
   */
  async countByCreatorId(creatorId: string): Promise<number> {
    try {
      const [result] = await db.select({ value: count() }).from(invitations).where(eq(invitations.creatorId, creatorId))

      return result?.value ?? 0
    } catch (error: unknown) {
      logger.error('Error counting invitations for creator', { error, creatorId })
      throw new Error('Failed to count invitations', { cause: error })
    }
  }

  /**
   * Create a new invitation
   */
  async create(data: NewInvitation): Promise<Invitation> {
    try {
      const [invitation]: Array<Invitation> = await db.insert(invitations).values(data).returning()

      return invitation
    } catch (error: unknown) {
      logger.error('Error creating invitation', { error })
      throw new Error('Failed to create invitation', { cause: error })
    }
  }

  /**
   * Atomically increment usedCount only when the code is still valid.
   * All validity conditions are evaluated inside the WHERE clause so concurrent
   * redemptions cannot over-redeem a code with a limited maxUses.
   * Returns null (without throwing) when the code has already been exhausted,
   * revoked, or expired at the moment the UPDATE executes.
   */
  async redeemCode(code: string): Promise<Invitation | null> {
    try {
      const [updated]: Array<Invitation> = await db
        .update(invitations)
        .set({ usedCount: sql`${invitations.usedCount} + 1` })
        .where(
          and(
            eq(invitations.code, code),
            isNull(invitations.revokedAt),
            or(isNull(invitations.expiresAt), sql`${invitations.expiresAt} > NOW()`),
            or(isNull(invitations.maxUses), sql`${invitations.usedCount} < ${invitations.maxUses}`)
          )
        )
        .returning()

      return updated || null
    } catch (error: unknown) {
      logger.error('Error redeeming invitation code', { error, code })
      throw new Error('Failed to redeem invitation', { cause: error })
    }
  }

  /**
   * Soft-revoke an invitation owned by creatorId.
   * Returns null if the invitation does not exist or is not owned by that user.
   */
  async revoke(code: string, creatorId: string): Promise<Invitation | null> {
    try {
      const [updated]: Array<Invitation> = await db
        .update(invitations)
        .set({ revokedAt: new Date() })
        .where(and(eq(invitations.code, code), eq(invitations.creatorId, creatorId), isNull(invitations.revokedAt)))
        .returning()

      return updated || null
    } catch (error: unknown) {
      logger.error('Error revoking invitation', { error, code, creatorId })
      throw new Error('Failed to revoke invitation', { cause: error })
    }
  }
}
