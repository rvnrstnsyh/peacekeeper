import type { Relations } from 'drizzle-orm'
import type { PrimaryKeyBuilder } from 'drizzle-orm/pg-core'
import type { RegistrationRecord } from '@/shared/types/zero-access.utils.types'

import { relations } from 'drizzle-orm'
import { users } from '@/modules/auth/models/users.model'
import { bufferToUint8Array, uint8ArrayToBuffer } from '@/shared/utils/common.utils'
import { customType, foreignKey, integer, pgTable, primaryKey, text, timestamp, unique, uuid, varchar } from 'drizzle-orm/pg-core'

// Source - https://stackoverflow.com
// Posted by Ahmet Yazıcı
// Retrieved 2025-12-09, License - CC BY-SA 4.0
const bytea = customType<{ data: Buffer; notNull: false; default: false }>({
  dataType() {
    return 'bytea'
  }
})

/**
 * OPAQUE Envelopes table
 * Stores server-side OPAQUE protocol data (RFC 9807)
 * Only populated when user.authMode = 'opaque'
 */
export const opaqueEnvelopes = pgTable(
  'opaque_envelopes',
  {
    _id: uuid('_id').notNull().defaultRandom(),
    userId: uuid('user_id').notNull(),
    credentialIdentifier: bytea('credential_identifier').notNull(),

    // RFC 9807 RegistrationRecord fields
    clientPublicKey: bytea('client_public_key').notNull(),
    maskingKey: bytea('masking_key').notNull(),
    nonce: bytea('nonce').notNull(),
    authTag: bytea('auth_tag').notNull(),
    seed: bytea('seed').notNull(),

    // Protocol metadata
    version: varchar('version', { length: 50 }).notNull().default('v0'),
    context: varchar('context', { length: 255 }).notNull().default('OPAQUE-RFC9807-ristretto255-SHA512'),

    // Security metadata
    registrationIp: varchar('registration_ip', { length: 45 }),
    registrationUserAgent: text('registration_user_agent'),
    failedAttempts: integer('failed_attempts').notNull().default(0),
    lockedAt: timestamp('locked_at', { withTimezone: true }),

    // Timestamps and security tracking
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }),
    deletedAt: timestamp('deleted_at', { withTimezone: true })
  },
  (table): Array<PrimaryKeyBuilder> => [
    primaryKey({ name: 'pk_opaque_envelopes', columns: [table._id] }),
    foreignKey({
      name: 'fk_opaque_envelopes_user',
      columns: [table.userId],
      foreignColumns: [users._id]
    }).onDelete('cascade'),
    unique('uq_opaque_envelopes_user_id').on(table.userId),
    unique('uq_opaque_envelopes_credential_identifier').on(table.credentialIdentifier)
  ]
).enableRLS()

export const opaqueEnvelopesRelations: Relations = relations(opaqueEnvelopes, ({ one }) => ({
  user: one(users, {
    fields: [opaqueEnvelopes.userId],
    references: [users._id]
  })
}))

/**
 * Type definitions
 */

export type OpaqueEnvelope = typeof opaqueEnvelopes.$inferSelect
export type NewOpaqueEnvelope = typeof opaqueEnvelopes.$inferInsert
export type OpaqueEnvelopeUpdate = Partial<Omit<NewOpaqueEnvelope, '_id' | 'userId' | 'createdAt'>>

export function toRegistrationRecord(envelope: OpaqueEnvelope): RegistrationRecord {
  return {
    clientPublicKey: bufferToUint8Array(envelope.clientPublicKey),
    maskingKey: bufferToUint8Array(envelope.maskingKey),
    envelope: {
      nonce: bufferToUint8Array(envelope.nonce),
      authTag: bufferToUint8Array(envelope.authTag),
      seed: bufferToUint8Array(envelope.seed)
    }
  }
}

export function fromRegistrationRecord(
  record: RegistrationRecord,
  userId: string,
  credentialIdentifier: Uint8Array,
  context: string,
  metadata?: { registrationIp?: string; registrationUserAgent?: string }
): NewOpaqueEnvelope {
  return {
    userId,
    credentialIdentifier: uint8ArrayToBuffer(credentialIdentifier),
    clientPublicKey: uint8ArrayToBuffer(record.clientPublicKey),
    maskingKey: uint8ArrayToBuffer(record.maskingKey),
    nonce: uint8ArrayToBuffer(record.envelope.nonce),
    authTag: uint8ArrayToBuffer(record.envelope.authTag),
    seed: uint8ArrayToBuffer(record.envelope.seed),
    context,
    registrationIp: metadata?.registrationIp,
    registrationUserAgent: metadata?.registrationUserAgent
  }
}

export function isEnvelopeLocked(envelope: OpaqueEnvelope, lockDurationMs: number = 60 * 60 * 1000): boolean {
  if (!envelope.lockedAt) return false
  const lockExpired = Date.now() - envelope.lockedAt.getTime() > lockDurationMs
  return !lockExpired
}

export function incrementFailedAttempts(envelope: OpaqueEnvelope, maxAttempts: number = 5): OpaqueEnvelopeUpdate {
  const attempts = envelope.failedAttempts + 1
  const shouldLock = attempts >= maxAttempts

  return {
    failedAttempts: attempts,
    lockedAt: shouldLock ? new Date() : envelope.lockedAt,
    updatedAt: new Date()
  }
}

export function resetFailedAttempts(): OpaqueEnvelopeUpdate {
  return {
    failedAttempts: 0,
    lockedAt: null,
    lastUsedAt: new Date(),
    updatedAt: new Date()
  }
}

export default opaqueEnvelopes
