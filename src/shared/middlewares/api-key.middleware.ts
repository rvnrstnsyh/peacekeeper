import httpResponse from '@/shared/utils/http-response.utils'

import type { Context, MiddlewareHandler, Next } from 'hono'

import { createMiddleware } from 'hono/factory'
import { logSecurity } from '@/configs/logger.configs'
import { remoteAddr } from '@/shared/utils/remote-addr.utils'
import { ApiKeysService } from '@/modules/api-keys/services/api-keys.service'

/**
 * API Key Authentication Middleware
 *
 * Authenticates requests using an API key supplied via:
 *   - `X-API-Key: kid_prod_<kid>.sk_prod_nvll_<secret>` header  (preferred)
 *   - `Authorization: Bearer kid_prod_<kid>.sk_prod_nvll_<secret>` header (alternative)
 *
 * On success:
 *   - Sets `ctx.set('apiUser', user)` — the owning user record
 *   - Sets `ctx.set('apiKeyId', key._id)` — for audit logging
 *   - Usage stats (lastUsedAt, usageCount) are updated non-blocking
 *
 * On failure: returns 401 Unauthorized.
 *
 * @remarks
 * - Does NOT set the `session` context used by JWT middleware.
 *   Use `apiKeyAuth` OR `auth`, not both, on the same route.
 * - API keys must start with "kid_" to be recognized.
 * - `user.apiAccess` must be true; the service enforces this.
 */
export function apiKeyAuth(): MiddlewareHandler {
  return createMiddleware(async (ctx: Context<Generics>, next: Next): Promise<Response | void> => {
    const ip: string = remoteAddr(ctx)

    // Prefer X-API-Key header; fall back to Bearer token if it looks like an API key
    const xApiKey: string | undefined = ctx.req.header('x-api-key')
    const authHeader: string | undefined = ctx.req.header('authorization')
    const bearerKey: string | undefined = authHeader?.startsWith('Bearer kid_') ? authHeader.substring(7) : undefined
    const rawKey: string | undefined = xApiKey ?? bearerKey

    if (!rawKey?.startsWith('kid_')) {
      logSecurity('api_key_missing', 'medium', { ip, reason: 'No API key provided' })
      return httpResponse.unauthorized(ctx, 'API key is required')
    }

    try {
      const service: ApiKeysService = new ApiKeysService()
      const { user, apiKey } = await service.authenticateByKey(rawKey, ip)

      ctx.set('apiUser', user)
      ctx.set('apiKeyId', apiKey._id)

      return await next()
    } catch (error: unknown) {
      const message: string = error instanceof Error ? error.message : 'Invalid API key'
      logSecurity('api_key_auth_failed', 'medium', { ip, reason: message })
      return httpResponse.unauthorized(ctx, 'Invalid or expired API key')
    }
  })
}
