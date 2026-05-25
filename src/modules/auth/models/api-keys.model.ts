import { users } from '@/modules/auth/models/users.model'

import type { Relations } from 'drizzle-orm'
import type { PgEnum, PrimaryKeyBuilder } from 'drizzle-orm/pg-core'

import { relations } from 'drizzle-orm'
import { foreignKey, index, jsonb, pgEnum, pgTable, primaryKey, text, timestamp, uuid, varchar } from 'drizzle-orm/pg-core'

type KeyScope = {
  resources?: Array<string>
  actions?: Array<string>
  [key: string]: unknown
}

/**
 * API Key status enumeration
 */
export const apiKeyStatusEnum: PgEnum<['active', 'revoked', 'expired']> = pgEnum('api_key_status', ['active', 'revoked', 'expired'])

/**
 * API Keys table
 * Stores API keys for programmatic access when using OPAQUE mode
 *
 * USAGE:
 * - OPAQUE mode: Required for API access (JWT only for UI)
 * - Traditional mode: Not used (JWT handles both UI and API)
 *
 * API Key Format: "kid_prod_<8hex>.sk_prod_nvll_<48hex>"
 * Example: kid_prod_a91f27c3.sk_prod_nvll_8kf3lxp2qa7wsy1zmc...
 * - KID (key_prefix column): public identifier, safe to log and display
 * - SK (secret): hashed with SHA-256 before storage, shown to user ONCE
 */
export const apiKeys = pgTable(
  'api_keys',
  {
    _id: uuid('_id').notNull().defaultRandom(),
    userId: uuid('user_id').notNull(),

    /**
     * API Key Name/Label
     * User-friendly name to identify the key (e.g., "Production Server", "Mobile App")
     */
    name: varchar('name', { length: 100 }).notNull(),

    /**
     * API Key Hash
     * NEVER store the actual key - only store the hash
     * Hash the key with a strong algorithm (e.g., SHA-256)
     *
     * The actual key is shown to user ONCE during creation
     */
    keyHash: varchar('key_hash', { length: 128 }).notNull(),

    /**
     * Key ID (KID) — public identifier portion of the key
     * Format: kid_<env>_<8 hex chars>  (e.g., "kid_prod_a91f27c3")
     * Safe to log, audit, and display. Never the secret.
     */
    keyPrefix: varchar('key_prefix', { length: 20 }).notNull(),

    /**
     * Key Status
     * - active: Key can be used
     * - revoked: Key manually revoked by user
     * - expired: Key passed expiration date
     */
    status: apiKeyStatusEnum('status').notNull().default('active'),

    /**
     * Permissions/Scopes (JSON)
     * Define what this API key can access
     * Example: {"resources": ["users", "posts"], "actions": ["read", "write"]}
     */
    scopes: jsonb('scopes').$type<KeyScope>(),

    /**
     * IP address of last usage
     * For security monitoring
     */
    lastUsedIp: varchar('last_used_ip', { length: 45 }),

    /**
     * Total number of times this key has been used
     * For usage analytics
     */
    usageCount: varchar('usage_count', { length: 20 }).notNull().default('0'),

    /**
     * Last time this key was used
     * For monitoring and security auditing
     */
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),

    /**
     * Revocation reason
     * If status = 'revoked', store why it was revoked
     */
    revokedReason: text('revoked_reason'),

    revokedAt: timestamp('revoked_at', { withTimezone: true }),

    /**
     * Expiration date
     * Optional - if NULL, key never expires
     * Best practice: Set expiration for security
     */
    expiresAt: timestamp('expires_at', { withTimezone: true }),

    // Timestamps
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }),
    deletedAt: timestamp('deleted_at', { withTimezone: true })
  },
  (table): Array<PrimaryKeyBuilder> => [
    primaryKey({ name: 'pk_api_keys', columns: [table._id] }),
    foreignKey({
      name: 'fk_api_keys_user',
      columns: [table.userId],
      foreignColumns: [users._id]
    }).onDelete('cascade'),
    // Index for fast lookup by key hash
    index('idx_api_keys_key_hash').on(table.keyHash),
    // Index for finding active keys by user
    index('idx_api_keys_user_status').on(table.userId, table.status)
  ]
).enableRLS()

export const apiKeysRelations: Relations = relations(apiKeys, ({ one }) => ({
  user: one(users, { fields: [apiKeys.userId], references: [users._id] })
}))

export type ApiKey = typeof apiKeys.$inferSelect
export type NewApiKey = typeof apiKeys.$inferInsert
export type ApiKeyUpdate = Partial<Omit<NewApiKey, '_id' | 'userId' | 'createdAt'>>
export type ApiKeyResponse = Omit<ApiKey, 'keyHash'> // Never expose hash

/**
 * Generate a new API key in the format: `kid_<env>_<8hex>.<sk_<env>_<namespace>_<48hex>>`
 *
 * The KID (key identifier) is the public portion — safe to log and display.
 * The SK (secret key) is the private portion — hashed before storage, shown to user once.
 *
 * @returns `key`  — the full key shown to the user once (KID + SK)
 * @returns `kid`  — the public identifier stored as `keyPrefix` in the DB
 */
export function generateApiKey(prefix: 'prod' | 'dev' = 'prod', namespace = 'nvll'): { key: string; kid: string } {
  // KID: 4 random bytes → 8 hex chars (public, safe for logs)
  const kidHex: string = Array.from(crypto.getRandomValues(new Uint8Array(4)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  const kid = `kid_${prefix}_${kidHex}`

  // SK: 24 random bytes → 48 hex chars (secret, hashed before DB)
  const secretHex: string = Array.from(crypto.getRandomValues(new Uint8Array(24)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  const sk = `sk_${prefix}_${namespace}_${secretHex}`

  return { key: `${kid}.${sk}`, kid }
}

export async function hashApiKey(key: string): Promise<string> {
  const encoder: TextEncoder = new TextEncoder()
  const data: Uint8Array<ArrayBuffer> = encoder.encode(key)
  const hashBuffer: ArrayBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray: Array<number> = Array.from(new Uint8Array(hashBuffer))

  return hashArray.map((b: number): string => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Extract the KID (public key identifier) from a full API key.
 * Returns the portion before the first `.` — e.g., `kid_prod_a91f27c3`.
 */
export function extractKeyPrefix(key: string): string {
  const dotIndex = key.indexOf('.')
  return dotIndex !== -1 ? key.substring(0, dotIndex) : key.substring(0, 20)
}

export function isApiKeyValid(apiKey: ApiKey): boolean {
  if (apiKey.status !== 'active') return false
  if (apiKey.expiresAt && new Date() > apiKey.expiresAt) return false

  return true
}

export function sanitizeApiKey(apiKey: ApiKey): ApiKeyResponse {
  const { keyHash: _keyHash, ...sanitized }: ApiKey = apiKey
  return sanitized
}

export function recordApiKeyUsage(apiKey: ApiKey, ip?: string): ApiKeyUpdate {
  return {
    lastUsedAt: new Date(),
    lastUsedIp: ip,
    usageCount: (BigInt(apiKey.usageCount) + 1n).toString(),
    updatedAt: new Date()
  }
}

export function revokeApiKey(reason?: string): ApiKeyUpdate {
  return {
    status: 'revoked',
    revokedReason: reason,
    revokedAt: new Date(),
    updatedAt: new Date()
  }
}

export function hasApiKeyScope(apiKey: ApiKey, resource: string, action: string): boolean {
  const scopes: KeyScope | null = apiKey.scopes

  if (!scopes) return true // No scopes = full access (for backward compatibility)

  const resources: Array<string> | undefined = scopes.resources
  const actions: Array<string> | undefined = scopes.actions

  if (resources && !resources.includes(resource)) return false
  if (actions && !actions.includes(action)) return false

  return true
}

export default apiKeys
