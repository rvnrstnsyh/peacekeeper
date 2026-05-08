import type { Relations } from 'drizzle-orm'
import type { PgEnum, PrimaryKeyBuilder } from 'drizzle-orm/pg-core'

import { relations } from 'drizzle-orm'
import { apiKeys } from '@/modules/auth/models/api-keys.model'
import { opaqueEnvelopes } from '@/modules/auth/models/opaque-envelopes.model'
import { boolean, date, pgEnum, pgTable, primaryKey, text, timestamp, unique, uuid, varchar } from 'drizzle-orm/pg-core'

/**
 * User role enumeration
 */
export const roleEnum: PgEnum<['administrator', 'user']> = pgEnum('role', ['administrator', 'user'])

/**
 * Gender enumeration
 */
export const genderEnum: PgEnum<['male', 'female']> = pgEnum('gender', ['male', 'female'])

/**
 * Users table schema
 * Stores user account information, authentication data, and profile details
 * Support both JWT and OPAQUE authentication
 */
export const users = pgTable(
  'users',
  {
    // Primary Key
    _id: uuid('_id').notNull().defaultRandom(),

    // Authentication fields
    email: varchar('email', { length: 255 }).notNull(),
    username: varchar('username', { length: 32 }).notNull(),

    // Personal information
    firstName: text('first_name'),
    lastName: text('last_name'),
    phone: varchar('phone', { length: 32 }),
    dateOfBirth: date('date_of_birth'),
    gender: genderEnum('gender'),
    address: text('address'),
    avatar: text('avatar'),

    // Role and status
    role: roleEnum('role').notNull().default('user'),
    isEmailVerified: boolean('is_email_verified').notNull().default(false),
    emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),
    apiAccess: boolean('api_access').notNull().default(false),
    isActive: boolean('is_active').notNull().default(true),

    // Sign in tracking
    lastSignInAt: timestamp('last_sign_in_at', { withTimezone: true }),
    lastSignInIp: varchar('last_sign_in_ip', { length: 45 }),
    lastSignInUserAgent: text('last_sign_in_user_agent'),

    // Timestamps
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }),
    usernameChangedAt: timestamp('username_changed_at', { withTimezone: true }),
    deletedAt: timestamp('deleted_at', { withTimezone: true })
  },
  (table): Array<PrimaryKeyBuilder> => [primaryKey({ name: 'pk_users', columns: [table._id] }), unique('uq_users_email').on(table.email)]
).enableRLS()

/**
 * User table relations
 */
export const usersRelations: Relations = relations(users, ({ one, many }) => ({
  opaqueEnvelope: one(opaqueEnvelopes, {
    fields: [users._id],
    references: [opaqueEnvelopes.userId]
  }),
  apiKeys: many(apiKeys)
}))

/**
 * Type definitions
 */
export type User = typeof users.$inferSelect
export type NewUser = typeof users.$inferInsert
export type UserUpdate = Partial<Omit<NewUser, 'id' | 'createdAt'>>
export type UserResponse = Omit<User, 'deletedAt'>

export function sanitizeUser(user: User): UserResponse {
  const { deletedAt: _deletedAt, ...sanitized } = user
  return sanitized
}

export function getFullName(user: User): string {
  return `${user.firstName} ${user.lastName}`
}

export function hasRole(user: User, role: string | Array<string>): boolean {
  if (Array.isArray(role)) {
    return role.includes(user.role)
  }
  return user.role === role
}

export function isAdmin(user: User): boolean {
  return user.role === 'administrator'
}

export function isEmailVerified(user: User): boolean {
  return user.isEmailVerified && user.emailVerifiedAt !== null
}

export function isUserActive(user: User): boolean {
  return user.isActive && !user.deletedAt
}

export default users
