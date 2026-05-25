import httpResponse from '@/shared/utils/http-response.utils'

import type { Context, MiddlewareHandler, Next } from 'hono'
import type { AccessTokenPayload } from '@/shared/types/jwt.utils.types'

import { createMiddleware } from 'hono/factory'
import { verifyToken } from '@/shared/utils/jwt.utils'
import { remoteAddr } from '@/shared/utils/remote-addr.utils'
import { logger, logSecurity } from '@/configs/logger.configs'
import { REDIS_KEYS } from '@/shared/constants/redis.constants'
import { sessionStore } from '@/shared/utils/session-store.utils'

/**
 * Authentication middleware options for configuring token verification behavior
 */
interface AuthOptions {
  /** Whether authentication is required. If false, requests without tokens are allowed */
  requiredTokens?: boolean
  /** Whether to check if token is blacklisted in Redis */
  checkBlacklist?: boolean
}

/**
 * Extract JWT Token from Authorization Header (Private Helper)
 *
 * Extracts JWT access token from Authorization header with flexible format support.
 * Supports both standard "Bearer <token>" and direct "<token>" formats.
 *
 * @param ctx - Hono context containing request headers
 * @returns JWT token string or null if Authorization header not present
 * @remarks
 * - Checks for "Bearer " prefix and strips it if present
 * - Returns raw token if no "Bearer " prefix found
 * - Case-sensitive: expects "Bearer" with capital B
 */
function extractToken(ctx: Context<Generics>): string | null {
  const authHeader: string | undefined = ctx.req.header('authorization')

  if (!authHeader) {
    return null
  }

  // Support both "Bearer token" and "token" formats
  if (authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }

  return authHeader
}

/**
 * Check Token Blacklist in Redis (Private Helper)
 *
 * Verifies if JWT token has been blacklisted (revoked via sign out).
 * Fails gracefully if Redis is unavailable to prevent blocking legitimate requests.
 *
 * @param token - JWT token string to check
 * @returns True if token is blacklisted, false if not blacklisted or Redis unavailable
 * @remarks
 * - Returns false if Redis is closed/unavailable (graceful degradation)
 * - Returns false on Redis errors to allow request to proceed
 * - Blacklist key format: `blacklist:${token}`
 * - Tokens added to blacklist during signOut with TTL matching token expiration
 */
async function isTokenBlacklisted(token: string): Promise<boolean> {
  try {
    const blacklisted: string | null = await sessionStore.get(`blacklist:${token}`)
    return blacklisted !== null
  } catch (error: unknown) {
    logger.error('Error checking token blacklist', { error })
    return false
  }
}

/**
 * Authentication Middleware Factory
 *
 * Creates configurable authentication middleware that verifies JWT tokens,
 * validates signatures using Ed25519, checks token blacklist, and sets
 * user context for downstream handlers.
 *
 * Features:
 * - Ed25519 JWT signature verification with automatic key rotation support
 * - Token blacklist checking via Redis (revoked/signed-out tokens)
 * - Token type validation (access vs refresh tokens)
 * - Graceful degradation when Redis unavailable
 * - Detailed security logging for suspicious activities
 * - User context injection for authenticated requests
 *
 * Process flow:
 * 1. Extracts token from Authorization header
 * 2. Handles missing token based on requiredTokens option
 * 3. Verifies JWT signature and expiration using Ed25519
 * 4. Validates token type is "access" (not "refresh")
 * 5. Checks token blacklist in Redis (if checkBlacklist enabled)
 * 6. Sets user object in context from token payload
 * 7. Continues to next handler
 *
 * @param options - Authentication configuration options
 * @param options.requiredTokens - If false, allows requests without tokens (default: true)
 * @param options.checkBlacklist - If false, skips Redis blacklist check (default: true)
 * @returns Hono middleware function
 *
 * @remarks
 * - Returns 401 Unauthorized for missing/invalid/expired tokens (when requiredTokens=true)
 * - Returns 401 for wrong token type (using refresh token instead of access token)
 * - Returns 401 for blacklisted tokens with "Token has been revoked" message
 * - Logs security events for invalid tokens, wrong types, and blacklisted tokens
 * - Automatically handles Ed25519 key rotation via token header version
 * - Sets ctx.user for downstream handlers to access authenticated user data
 *
 * @example
 * // Require authentication (default behavior)
 * app.use('/api/protected/*', auth())
 *
 * @example
 * // Optional authentication - allow both authenticated and public access
 * app.use('/api/posts/*', auth({ requiredTokens: false }))
 *
 * @example
 * // Skip blacklist check for high-performance read-only endpoints
 * app.use('/api/public-data/*', auth({ checkBlacklist: false }))
 */
export function authentication(options: AuthOptions = {}): MiddlewareHandler {
  const { requiredTokens = true, checkBlacklist = true }: AuthOptions = options

  return createMiddleware(async (ctx: Context<Generics>, next: Next): Promise<Response | void> => {
    try {
      const token: string | null = extractToken(ctx)

      // If no token and not requiredTokens, continue without authentication
      if (!token && !requiredTokens) {
        return await next()
      }

      // If no token but requiredTokens, return 401
      if (!token && requiredTokens) {
        return httpResponse.unauthorized(ctx, 'Authentication token is required')
      }

      // At this point token is guaranteed to be non-null
      const tokenStr: string = token as string
      // Verify token signature and expiration using Ed25519
      // This automatically handles key rotation by extracting the key version from token header
      let payload: AccessTokenPayload
      try {
        payload = (await verifyToken(tokenStr)) as AccessTokenPayload
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : 'Invalid token'

        logSecurity('invalid_token', 'medium', {
          ip: remoteAddr(ctx),
          path: ctx.req.path,
          error: errorMessage
        })

        // Provide specific error messages
        if (errorMessage.includes('expired')) {
          return httpResponse.unauthorized(ctx, 'Token has expired')
        }
        if (errorMessage.includes('signature')) {
          return httpResponse.unauthorized(ctx, 'Invalid token signature')
        }

        return httpResponse.unauthorized(ctx, 'Invalid or expired token')
      }

      // Verify token type
      if (payload.type !== 'access') {
        logSecurity('wrong_token_type', 'medium', {
          userId: payload._id,
          ip: remoteAddr(ctx),
          path: ctx.req.path,
          tokenType: payload.type
        })
        return httpResponse.unauthorized(ctx, 'Invalid token type')
      }

      // Check if token is blacklisted (revoked/logged out)
      if (checkBlacklist && (await isTokenBlacklisted(tokenStr))) {
        logSecurity('blacklisted_token', 'high', {
          userId: payload._id,
          ip: remoteAddr(ctx),
          path: ctx.req.path
        })
        return httpResponse.unauthorized(ctx, 'Token has been revoked')
      }

      // Check if the session channel has been remotely revoked (e.g. sign-out from another device)
      if (checkBlacklist && payload._sid) {
        try {
          const channelRevoked: string | null = await sessionStore.get(REDIS_KEYS.REVOKED_CHANNEL(payload._sid))
          if (channelRevoked !== null) {
            logSecurity('blacklisted_token', 'high', {
              userId: payload._id,
              ip: remoteAddr(ctx),
              path: ctx.req.path,
              channelId: payload._sid
            })
            return httpResponse.unauthorized(ctx, 'Session has been revoked')
          }
        } catch {
          // Redis unavailable — allow request to proceed (graceful degradation)
        }
      }

      // Set user info in context for downstream handlers
      if (payload._id && payload._cid && payload.user) {
        ctx.set('session', payload as AccessTokenPayload)
      }

      return await next()
    } catch (error: unknown) {
      logger.error('Auth middleware error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        path: ctx.req.path
      })
      return httpResponse.internalServerError(ctx, 'Authentication failed')
    }
  })
}

/**
 * Optional Authentication Middleware
 *
 * Pre-configured middleware that allows requests without tokens to proceed.
 * Useful for endpoints that provide enhanced features for authenticated users
 * but also work for unauthenticated users.
 *
 * Configuration: { requiredTokens: false, checkBlacklist: true }
 *
 * @remarks
 * - Requests without tokens proceed normally (no 401 error)
 * - Valid tokens are still verified and user context is set
 * - Blacklist checking is enabled for signed-out tokens
 * - Downstream handlers should check if ctx.get('session') is defined
 * @example
 * // Allow viewing posts without login, but show author details if logged in
 * app.use('/api/posts/*', optionalAuth)
 * app.get('/api/posts/:id', (ctx) => {
 *   const session = ctx.get('session') // undefined for unauthenticated requests
 *   // ... fetch post with optional session-specific data
 * })
 */
export const optionalAuth: MiddlewareHandler = authentication({
  requiredTokens: false
})

/**
 * Strict Authentication Middleware
 *
 * Pre-configured middleware with maximum security: requires valid tokens
 * and performs blacklist checking. This is the default and most secure option.
 *
 * Configuration: { requiredTokens: true, checkBlacklist: true }
 *
 * @remarks
 * - Identical to calling auth() with no options (default behavior)
 * - Requires valid JWT token in Authorization header
 * - Verifies token signature and expiration
 * - Checks Redis blacklist for revoked tokens
 * - Returns 401 for missing, invalid, expired, or blacklisted tokens
 * - Use for all protected endpoints where authentication is mandatory
 * @example
 * // Protect user profile and settings endpoints
 * app.use('/api/user/*', auth)
 * app.use('/api/settings/*', auth)
 */
export const auth: MiddlewareHandler = authentication({
  requiredTokens: true,
  checkBlacklist: true
})

/**
 * Fast Authentication Middleware
 *
 * Pre-configured middleware that skips Redis blacklist checking for
 * high-performance scenarios. Use only when token revocation checking
 * is not critical (read-only public data, high-traffic endpoints).
 *
 * Configuration: { requiredTokens: true, checkBlacklist: false }
 *
 * @remarks
 * - Requires valid JWT token but skips blacklist check
 * - Still verifies JWT signature, expiration, and token type
 * - Reduces Redis load for high-traffic endpoints
 * - Signed-out users can still access until token naturally expires
 * - Security trade-off: faster performance vs delayed token revocation
 * - Do NOT use for sensitive operations (payments, data modification)
 * @example
 * // High-traffic read-only endpoints where slight revocation delay is acceptable
 * app.use('/api/articles/*', fastAuth)
 * app.use('/api/public-stats/*', fastAuth)
 * @warning
 * Do not use for endpoints that:
 * - Modify user data or system state
 * - Access sensitive information
 * - Perform financial transactions
 * - Require immediate session termination on sign out
 */
export const fastAuth: MiddlewareHandler = authentication({
  requiredTokens: true,
  checkBlacklist: false
})

export default auth
