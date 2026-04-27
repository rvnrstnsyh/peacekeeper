/**
 * Redis key prefixes for better organization and namespace isolation
 * Uses functional pattern to ensure consistent key generation
 */

import { env } from '@/configs/environment.configs'

export const REDIS_KEYS = {
  OPAQUE_STATE: (userId: string) => `opaque_state:${userId}`,
  VERIFICATION_TOKEN: (userId: string) => `verification_token:${userId}`,
  REFRESH_TOKEN: (userId: string) => `refresh_token:${userId}`,
  REFRESH_TOKEN_PREV: (userId: string) => `refresh_token_prev:${userId}`,
  RESET_PASSWORD_TOKEN: (userId: string) => `reset_token:${userId}`,
  RESET_PASSWORD_STATE: (credentialIdentifier: string) => `reset_pwd_state:${credentialIdentifier}`
} as const

/**
 * TTL (Time To Live) constants in seconds.
 *
 * Token-related TTLs (VERIFICATION_TOKEN, RESET_PASSWORD_TOKEN) are derived
 * from environment variables so they stay in sync with the corresponding JWT
 * expiry settings (JWT_EMAIL_VERIFICATION_EXPIRES_IN / JWT_PASSWORD_RESET_EXPIRES_IN).
 * All other values are protocol-level constants with no JWT counterpart.
 */
export const TTL = {
  OPAQUE_STATE: 300, // 5 minutes - short-lived authentication session state
  get VERIFICATION_TOKEN(): number {
    return env.jwtEmailVerificationExpiresIn
  },
  REFRESH_TOKEN: 86400, // 24 hours - default (unused directly; sign-in uses env.sessionTTL / env.sessionRememberMeTTL)
  REFRESH_TOKEN_PREV: 30, // 30 seconds - grace window for concurrent proxy + api-client refresh requests
  get RESET_PASSWORD_TOKEN(): number {
    return env.jwtPasswordResetExpiresIn
  },
  RESET_PASSWORD_STATE: 300 // 5 minutes - short-lived reset state between alpha and beta
}
