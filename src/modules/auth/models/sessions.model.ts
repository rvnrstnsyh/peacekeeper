import type { Relations } from 'drizzle-orm'
import type { PrimaryKeyBuilder } from 'drizzle-orm/pg-core'

import { relations } from 'drizzle-orm'
import { users } from '@/modules/auth/models/users.model'
import { boolean, index, pgTable, primaryKey, text, timestamp, unique, uuid, varchar } from 'drizzle-orm/pg-core'

/**
 * Sessions table schema
 * Tracks every active login session per user device.
 * Enables per-device sign-out and "sign out everywhere".
 *
 * Each row corresponds to one OPAQUE authentication or password-change cycle.
 * The channelId maps to the `_sid` claim in the JWT and to the Redis channel-
 * encryption key (`channel_key:{channelId}`).
 */
export const sessions = pgTable(
  'sessions',
  {
    _id: uuid('_id').notNull().defaultRandom(),

    /** Hex channel ID — maps to JWT `_sid` and Redis `session_token:{channelId}` */
    channelId: varchar('channel_id', { length: 64 }).notNull(),

    userId: uuid('user_id').notNull(),

    /** Client IP at login time */
    ip: varchar('ip', { length: 45 }),

    /** Raw User-Agent string at login time */
    userAgent: text('user_agent'),

    /** Whether the session was created with "remember me" */
    isRememberMe: boolean('is_remember_me').notNull().default(false),

    /** Timestamp when the session (refresh token) expires */
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),

    /** Updated on every successful token refresh */
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }),

    /** Set when the session is explicitly revoked (sign-out) */
    revokedAt: timestamp('revoked_at', { withTimezone: true }),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow()
  },
  (table): Array<PrimaryKeyBuilder> => [primaryKey({ name: 'pk_sessions', columns: [table._id] }), unique('uq_sessions_channel_id').on(table.channelId), index('idx_sessions_user_id').on(table.userId)]
).enableRLS()

/**
 * Sessions → Users relation
 */
export const sessionsRelations: Relations = relations(sessions, ({ one }) => ({
  user: one(users, {
    fields: [sessions.userId],
    references: [users._id]
  })
}))

export type Session = typeof sessions.$inferSelect
export type NewSession = typeof sessions.$inferInsert
