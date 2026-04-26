import { db } from '@/database/connection'

import type { NewOpaqueEnvelope, OpaqueEnvelope, OpaqueEnvelopeUpdate } from '@/modules/auth/models/opaque-envelopes.model'

import { and, eq, isNull } from 'drizzle-orm'

import { incrementFailedAttempts, isEnvelopeLocked, opaqueEnvelopes, resetFailedAttempts } from '@/modules/auth/models/opaque-envelopes.model'

export class OpaqueEnvelopesRepository {
  /**
   * Create a new OPAQUE envelope
   */
  async create(data: NewOpaqueEnvelope): Promise<OpaqueEnvelope> {
    const [envelope] = await db.insert(opaqueEnvelopes).values(data).returning()

    return envelope
  }

  /**
   * Find envelope by user ID (active only)
   */
  async findByUserId(userId: string): Promise<OpaqueEnvelope | null> {
    const [envelope] = await db
      .select()
      .from(opaqueEnvelopes)
      .where(and(eq(opaqueEnvelopes.userId, userId), isNull(opaqueEnvelopes.deletedAt)))
      .limit(1)

    return envelope || null
  }

  /**
   * Find envelope by credential identifier (active only)
   * @param credentialIdentifier - Buffer containing the credential identifier
   */
  async findByCredentialIdentifier(credentialIdentifier: Buffer): Promise<OpaqueEnvelope | null> {
    const [envelope] = await db
      .select()
      .from(opaqueEnvelopes)
      .where(and(eq(opaqueEnvelopes.credentialIdentifier, credentialIdentifier), isNull(opaqueEnvelopes.deletedAt)))
      .limit(1)

    return envelope || null
  }

  /**
   * Find envelope by ID (active only)
   */
  async findById(id: string): Promise<OpaqueEnvelope | null> {
    const [envelope] = await db
      .select()
      .from(opaqueEnvelopes)
      .where(and(eq(opaqueEnvelopes._id, id), isNull(opaqueEnvelopes.deletedAt)))
      .limit(1)

    return envelope || null
  }

  /**
   * Update an envelope
   */
  async update(id: string, data: OpaqueEnvelopeUpdate): Promise<OpaqueEnvelope | null> {
    const [updated] = await db
      .update(opaqueEnvelopes)
      .set({ ...data, updatedAt: new Date() })
      .where(and(eq(opaqueEnvelopes._id, id), isNull(opaqueEnvelopes.deletedAt)))
      .returning()

    return updated || null
  }

  /**
   * Update OPAQUE Envelope by Credential Identifier
   *
   * Updates an existing OPAQUE envelope with new password data.
   * Used during password change operations to replace old envelope
   * with new registration record while preserving user association.
   *
   * @param credentialIdentifier - Buffer containing credential identifier
   * @param data - Envelope data to update
   * @returns Updated envelope or null if not found
   */
  async updateByCredentialIdentifier(
    credentialIdentifier: Buffer,
    data: {
      clientPublicKey: Buffer
      maskingKey: Buffer
      nonce: Buffer
      authTag: Buffer
      seed: Buffer
      context: string
      lastPasswordChange?: Date
      passwordChangeIp?: string
      passwordChangeUserAgent?: string
    }
  ): Promise<OpaqueEnvelope | null> {
    const [updated] = await db
      .update(opaqueEnvelopes)
      .set({
        ...data,
        updatedAt: new Date()
      })
      .where(and(eq(opaqueEnvelopes.credentialIdentifier, credentialIdentifier), isNull(opaqueEnvelopes.deletedAt)))
      .returning()

    return updated || null
  }

  /**
   * Update envelope by user ID
   */
  async updateByUserId(userId: string, data: OpaqueEnvelopeUpdate): Promise<OpaqueEnvelope | null> {
    const [updated] = await db
      .update(opaqueEnvelopes)
      .set({ ...data, updatedAt: new Date() })
      .where(and(eq(opaqueEnvelopes.userId, userId), isNull(opaqueEnvelopes.deletedAt)))
      .returning()

    return updated || null
  }

  /**
   * Soft delete an envelope
   */
  async delete(id: string): Promise<boolean> {
    const [deleted] = await db
      .update(opaqueEnvelopes)
      .set({ deletedAt: new Date(), updatedAt: new Date() })
      .where(and(eq(opaqueEnvelopes._id, id), isNull(opaqueEnvelopes.deletedAt)))
      .returning()

    return !!deleted
  }

  /**
   * Soft delete envelope by user ID
   */
  async deleteByUserId(userId: string): Promise<boolean> {
    const [deleted] = await db
      .update(opaqueEnvelopes)
      .set({ deletedAt: new Date(), updatedAt: new Date() })
      .where(and(eq(opaqueEnvelopes.userId, userId), isNull(opaqueEnvelopes.deletedAt)))
      .returning()

    return !!deleted
  }

  /**
   * Hard delete an envelope (permanent)
   */
  async hardDelete(id: string): Promise<boolean> {
    const result = await db.delete(opaqueEnvelopes).where(eq(opaqueEnvelopes._id, id))

    return (result.rowCount ?? 0) > 0
  }

  /**
   * Hard delete all envelopes for a user (permanent).
   * Used during password reset to fully remove old credential material
   * before inserting the new one, since the unique constraint on user_id
   * does not filter soft-deleted rows.
   */
  async hardDeleteByUserId(userId: string): Promise<boolean> {
    const result = await db.delete(opaqueEnvelopes).where(eq(opaqueEnvelopes.userId, userId))

    return (result.rowCount ?? 0) > 0
  }

  /**
   * Check if envelope is locked
   */
  isLocked(envelope: OpaqueEnvelope, lockDurationMs?: number): boolean {
    return isEnvelopeLocked(envelope, lockDurationMs)
  }

  /**
   * Record a failed authentication attempt
   */
  async recordFailedAttempt(id: string, maxAttempts: number = 5): Promise<OpaqueEnvelope | null> {
    const envelope = await this.findById(id)
    if (!envelope) return null

    const updates = incrementFailedAttempts(envelope, maxAttempts)
    return this.update(id, updates)
  }

  /**
   * Reset failed attempts after successful authentication
   */
  async recordSuccessfulAuth(id: string): Promise<OpaqueEnvelope | null> {
    const updates = resetFailedAttempts()
    return this.update(id, updates)
  }

  /**
   * Unlock an envelope manually
   */
  async unlock(id: string): Promise<OpaqueEnvelope | null> {
    return this.update(id, {
      lockedAt: null,
      updatedAt: new Date()
    })
  }

  /**
   * Check if credential identifier exists
   * @param credentialIdentifier - Buffer containing the credential identifier
   */
  async existsByCredentialIdentifier(credentialIdentifier: Buffer): Promise<boolean> {
    const envelope = await this.findByCredentialIdentifier(credentialIdentifier)
    return !!envelope
  }

  /**
   * Check if user has an envelope
   */
  async existsByUserId(userId: string): Promise<boolean> {
    const envelope = await this.findByUserId(userId)
    return !!envelope
  }
}

export default OpaqueEnvelopesRepository
