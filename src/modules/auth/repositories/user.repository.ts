import type { SQL } from 'drizzle-orm'
import type { User } from '@/modules/auth/models/users.model'
import type { SignUpBetaRequestDTO, UpdateProfileRequestDTO } from '@/modules/auth/dto/auth.dto'

import { db } from '@/database/connection'
import { logger } from '@/configs/logger.configs'
import { users } from '@/modules/auth/models/users.model'
import { and, count, desc, eq, isNull, sql } from 'drizzle-orm'

export class UserRepository {
  /**
   * Find user by _ID
   */
  async findById(userId: string): Promise<User | null> {
    try {
      const [user]: Array<User> = await db
        .select()
        .from(users)
        .where(
          and(
            eq(users._id, userId),
            isNull(users.deletedAt) // Exclude soft deleted
          )
        )
        .limit(1)

      return user || null
    } catch (error: unknown) {
      logger.error('Error finding user by ID', { error, userId })
      throw new Error('Failed to find user', { cause: error })
    }
  }

  /**
   * Find user by email
   */
  async findByEmail(email: string): Promise<User | null> {
    try {
      const [user]: Array<User> = await db
        .select()
        .from(users)
        .where(and(eq(users.email, email.toLowerCase()), isNull(users.deletedAt)))
        .limit(1)

      return user || null
    } catch (error: unknown) {
      logger.error('Error finding user by email', { error, email })
      throw new Error('Failed to find user', { cause: error })
    }
  }

  /**
   * Create new user
   */
  async create(data: SignUpBetaRequestDTO): Promise<User> {
    try {
      const [user]: Array<User> = await db
        .insert(users)
        .values({
          ...data,
          email: data.email.toLowerCase(),
          username: data.email.split('@')[0],
          createdAt: new Date(),
          updatedAt: new Date()
        })
        .returning()

      return user
    } catch (error: unknown) {
      logger.error('Error creating user', { error })
      throw new Error('Failed to create user', { cause: error })
    }
  }

  /**
   * Update user
   */
  async update(userId: string, data: UpdateProfileRequestDTO): Promise<User | null> {
    try {
      const [user]: Array<User> = await db
        .update(users)
        .set({
          ...data,
          updatedAt: new Date()
        })
        .where(and(eq(users._id, userId), isNull(users.deletedAt)))
        .returning()

      return user || null
    } catch (error: unknown) {
      logger.error('Error updating user', { error, userId })
      throw new Error('Failed to update user', { cause: error })
    }
  }

  /**
   * TODO: OPAQUE Update user password
   */

  /**
   * Update last sign in
   */
  async updateLastSignIn(userId: string, ip: string, userAgent: string): Promise<void> {
    try {
      await db
        .update(users)
        .set({
          lastSignInAt: new Date(),
          lastSignInIp: ip,
          lastSignInUserAgent: userAgent,
          updatedAt: new Date()
        })
        .where(and(eq(users._id, userId), isNull(users.deletedAt)))
    } catch (error: unknown) {
      logger.error('Error updating last sign in', { error, userId })
      // Don't throw error, this is not critical
    }
  }

  /**
   * Verify email
   */
  async verifyEmail(userId: string): Promise<void> {
    try {
      await db
        .update(users)
        .set({
          isEmailVerified: true,
          emailVerifiedAt: new Date(),
          updatedAt: new Date()
        })
        .where(and(eq(users._id, userId), isNull(users.deletedAt)))
    } catch (error: unknown) {
      logger.error('Error verifying email', { error, userId })
      throw new Error('Failed to verify email', { cause: error })
    }
  }

  /**
   * Deactivate user
   */
  async deactivate(userId: string): Promise<void> {
    try {
      await db
        .update(users)
        .set({
          isActive: false,
          updatedAt: new Date()
        })
        .where(and(eq(users._id, userId), isNull(users.deletedAt)))
    } catch (error: unknown) {
      logger.error('Error deactivating user', { error, userId })
      throw new Error('Failed to deactivate user', { cause: error })
    }
  }

  /**
   * Activate user
   */
  async activate(userId: string): Promise<void> {
    try {
      await db
        .update(users)
        .set({
          isActive: true,
          updatedAt: new Date()
        })
        .where(and(eq(users._id, userId), isNull(users.deletedAt)))
    } catch (error: unknown) {
      logger.error('Error activating user', { error, userId })
      throw new Error('Failed to activate user', { cause: error })
    }
  }

  /**
   * Delete user (soft delete)
   */
  async delete(userId: string): Promise<void> {
    try {
      await db
        .update(users)
        .set({
          deletedAt: new Date(),
          updatedAt: new Date()
        })
        .where(eq(users._id, userId))
    } catch (error: unknown) {
      logger.error('Error deleting user', { error, userId })
      throw new Error('Failed to delete user', { cause: error })
    }
  }

  /**
   * Permanently delete user (hard delete)
   */
  async permanentDelete(userId: string): Promise<void> {
    try {
      await db.delete(users).where(eq(users._id, userId))
    } catch (error: unknown) {
      logger.error('Error permanently deleting user', { error, userId })
      throw new Error('Failed to permanently delete user', { cause: error })
    }
  }

  /**
   * Find all users with pagination
   */
  async findAll(options: { page?: number; limit?: number; role?: string; isActive?: boolean }): Promise<{ users: Array<User>; total: number; pages: number }> {
    try {
      const { page = 1, limit = 10, role, isActive } = options
      const offset: number = (page - 1) * limit
      // Build where conditions
      const conditions: Array<SQL<unknown>> = [isNull(users.deletedAt)]

      if (role) {
        conditions.push(eq(users.role, role as User['role']))
      }

      if (isActive !== undefined) {
        conditions.push(eq(users.isActive, isActive))
      }

      // Get users
      const usersList: Array<User> = await db
        .select()
        .from(users)
        .where(and(...conditions))
        .limit(limit)
        .offset(offset)
        .orderBy(desc(users.createdAt))

      // Get total count
      const [{ value: total }] = await db
        .select({ value: count() })
        .from(users)
        .where(and(...conditions))

      return {
        users: usersList,
        total: Number(total),
        pages: Math.ceil(Number(total) / limit)
      }
    } catch (error: unknown) {
      logger.error('Error finding all users', { error })
      throw new Error('Failed to fetch users', { cause: error })
    }
  }

  /**
   * Count users by role
   */
  async countByRole(role: string): Promise<number> {
    try {
      const [{ value: total }] = await db
        .select({ value: count() })
        .from(users)
        .where(and(eq(users.role, role as User['role']), isNull(users.deletedAt)))

      return Number(total)
    } catch (error: unknown) {
      logger.error('Error counting users by role', { error, role })
      throw new Error('Failed to count users', { cause: error })
    }
  }

  /**
   * Check if email exists
   */
  async emailExists(email: string): Promise<boolean> {
    try {
      const user: User | null = await this.findByEmail(email)
      return user !== null
    } catch (error: unknown) {
      logger.error('Error checking email existence', { error, email })
      throw new Error('Failed to check email', { cause: error })
    }
  }

  /**
   * Find active users
   */
  async findActive(): Promise<Array<User>> {
    try {
      return await db
        .select()
        .from(users)
        .where(and(eq(users.isActive, true), isNull(users.deletedAt)))
        .orderBy(desc(users.createdAt))
    } catch (error: unknown) {
      logger.error('Error finding active users', { error })
      throw new Error('Failed to find active users', { cause: error })
    }
  }

  /**
   * Find users by role
   */
  async findByRole(role: string): Promise<Array<User>> {
    try {
      return await db
        .select()
        .from(users)
        .where(and(eq(users.role, role as User['role']), isNull(users.deletedAt)))
        .orderBy(desc(users.createdAt))
    } catch (error: unknown) {
      logger.error('Error finding users by role', { error, role })
      throw new Error('Failed to find users by role', { cause: error })
    }
  }

  /**
   * Find verified users
   */
  async findVerified(): Promise<Array<User>> {
    try {
      return await db
        .select()
        .from(users)
        .where(and(eq(users.isEmailVerified, true), isNull(users.deletedAt)))
        .orderBy(desc(users.createdAt))
    } catch (error: unknown) {
      logger.error('Error finding verified users', { error })
      throw new Error('Failed to find verified users', { cause: error })
    }
  }

  /**
   * Search users by name or email
   */
  async search(query: string): Promise<Array<User>> {
    try {
      return await db
        .select()
        .from(users)
        .where(
          and(
            sql`(
              LOWER(${users.firstName}) LIKE LOWER(${`%${query}%`}) OR
              LOWER(${users.lastName}) LIKE LOWER(${`%${query}%`}) OR
              LOWER(${users.email}) LIKE LOWER(${`%${query}%`})
            )`,
            isNull(users.deletedAt)
          )
        )
        .limit(10)
    } catch (error: unknown) {
      logger.error('Error searching users', { error, query })
      throw new Error('Failed to search users', { cause: error })
    }
  }
}

export default UserRepository
