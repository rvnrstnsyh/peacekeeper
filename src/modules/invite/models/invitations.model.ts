import type { Relations } from 'drizzle-orm'
import type { PrimaryKeyBuilder } from 'drizzle-orm/pg-core'

import { relations } from 'drizzle-orm'
import { users } from '@/modules/auth/models/users.model'
import { foreignKey, index, integer, pgTable, primaryKey, timestamp, unique, uuid, varchar } from 'drizzle-orm/pg-core'

/**
 * Invitations table schema
 *
 * Stores user-generated invitation codes.
 * Each authenticated user (account age ≥ 30 days) can create codes with
 * a custom expiry window and maximum redemption count.
 */
export const invitations = pgTable(
  'invitations',
  {
    _id: uuid('_id').notNull().defaultRandom(),

    /** Human-readable invite code, e.g. "A3F9C12B7E" */
    code: varchar('code', { length: 16 }).notNull(),

    /** User who issued this invitation */
    creatorId: uuid('creator_id').notNull(),

    /**
     * Maximum number of times this code can be redeemed.
     * NULL means unlimited uses.
     */
    maxUses: integer('max_uses'),

    /** Running total of successful redemptions */
    usedCount: integer('used_count').notNull().default(0),

    /**
     * Point in time when this code stops being valid.
     * NULL means the code never expires on its own.
     */
    expiresAt: timestamp('expires_at', { withTimezone: true }),

    /** Set when the creator manually revokes the code before expiry */
    revokedAt: timestamp('revoked_at', { withTimezone: true }),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow()
  },
  (table): Array<PrimaryKeyBuilder> => [
    primaryKey({ name: 'pk_invitations', columns: [table._id] }),
    unique('uq_invitations_code').on(table.code),
    foreignKey({
      name: 'fk_invitations_creator',
      columns: [table.creatorId],
      foreignColumns: [users._id]
    }).onDelete('cascade'),
    index('idx_invitations_creator_id').on(table.creatorId)
  ]
).enableRLS()

/**
 * Invitations → Users (creator) relation
 */
export const invitationsRelations: Relations = relations(invitations, ({ one }) => ({
  creator: one(users, {
    fields: [invitations.creatorId],
    references: [users._id]
  })
}))

export type Invitation = typeof invitations.$inferSelect
export type NewInvitation = typeof invitations.$inferInsert
