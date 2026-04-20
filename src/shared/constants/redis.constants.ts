/**
 * Redis key prefixes for better organization and namespace isolation
 * Uses functional pattern to ensure consistent key generation
 */
export const REDIS_KEYS = {
  OPAQUE_STATE: (userId: string) => `opaque_state:${userId}`,
  VERIFICATION_TOKEN: (userId: string) => `verification_token:${userId}`,
  REFRESH_TOKEN: (userId: string) => `refresh_token:${userId}`,
  RESET_PASSWORD_TOKEN: (userId: string) => `reset_token:${userId}`,
  RESET_PASSWORD_STATE: (credentialIdentifier: string) => `reset_pwd_state:${credentialIdentifier}`
} as const

/**
 * TTL (Time To Live) constants in seconds
 * Defines expiration times for various cached data
 */
export const TTL = {
  OPAQUE_STATE: 300, // 5 minutes - short-lived authentication session state
  VERIFICATION_TOKEN: 86400, // 24 hours - email verification validity period
  REFRESH_TOKEN: 604800, // 7 days - default (unused directly; sign-in uses env.sessionTTL / env.sessionRememberMeTTL)
  RESET_PASSWORD_TOKEN: 3600, // 1 hour - password reset token validity period
  RESET_PASSWORD_STATE: 300 // 5 minutes - short-lived reset state between alpha and beta
} as const
