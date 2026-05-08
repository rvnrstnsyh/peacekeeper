import httpResponse from '@/shared/utils/http-response.utils'

import type { Context, MiddlewareHandler, Next } from 'hono'
import type { AccessTokenPayload } from '@/shared/types/jwt.utils.types'

import { createMiddleware } from 'hono/factory'
import { logger } from '@/configs/logger.configs'
import { REDIS_KEYS } from '@/shared/constants/redis.constants'
import { base64ToUint8Array } from '@/shared/utils/common.utils'
import { sessionStore } from '@/shared/utils/session-store.utils'
import { channelEncrypt, channelDecrypt } from '@/shared/utils/channel-crypto.utils'

/**
 * Channel Encryption Middleware
 *
 * Provides application-layer channel encryption on top of TLS for all
 * authenticated endpoints. Uses AES-256-GCM with a per-session key derived
 * from the OPAQUE sessionKey via HKDF-SHA256.
 *
 * Request: if `X-Channel: 1` header is present and the method has a body
 * (POST / PUT / PATCH), reads `{ enc: "<base64>" }` from the request body,
 * decrypts it, and stores the result in context as `decryptedBody` so
 * that the validation middleware can access the original plaintext.
 *
 * Response: always encrypts the downstream response body into
 * `{ enc: "<base64>" }` and adds `X-Channel: 1` to the response headers.
 *
 * Graceful degradation: if the channel key is not found in Redis
 * (e.g. after a Redis restart), the middleware logs a warning and passes
 * the request through unencrypted. TLS still protects the transport.
 *
 * @remarks
 * Must be placed AFTER the `auth` middleware (needs `session` in context)
 * and BEFORE `validateBody` (stores decryptedBody for the validator to read).
 */
export function channelEncryption(): MiddlewareHandler {
  return createMiddleware(async (ctx: Context<Generics>, next: Next): Promise<Response | void> => {
    const session: AccessTokenPayload | undefined = ctx.get('session')
    const channelId: string | undefined = session?._sid as string | undefined

    // No channel established for this session — pass through
    if (!channelId) {
      return await next()
    }

    const sessionKeyB64: string | null = await sessionStore.get(REDIS_KEYS.CHANNEL_KEY(channelId))

    if (!sessionKeyB64) {
      // Channel key evicted from Redis (e.g. restart). Degrade gracefully.
      logger.warning('Channel key not found in Redis, proceeding without channel encryption', { channelId })
      return await next()
    }

    const sessionKey: Uint8Array = base64ToUint8Array(sessionKeyB64)
    const isEncryptedRequest: boolean = ctx.req.header('x-channel') === '1'
    const hasBody: boolean = ['POST', 'PUT', 'PATCH'].includes(ctx.req.method)

    // ── Decrypt request body ────────────────────────────────────────────────
    if (isEncryptedRequest && hasBody) {
      try {
        const encBody = await ctx.req.json<{ enc?: string }>()
        if (typeof encBody.enc === 'string') {
          const decryptedStr: string = await channelDecrypt(sessionKey, encBody.enc)
          const decryptedBody: unknown = JSON.parse(decryptedStr)
          ctx.set('decryptedBody', decryptedBody)
        }
      } catch (error: unknown) {
        logger.error('Channel request decryption failed', {
          error: error instanceof Error ? error.message : String(error),
          channelId
        })
        return httpResponse.badRequest(ctx, 'Channel decryption failed')
      }
    }

    await next()

    // ── Encrypt response body ───────────────────────────────────────────────
    try {
      const responseText: string = await ctx.res.text()
      const encryptedData: string = await channelEncrypt(sessionKey, responseText)

      const newHeaders: Headers = new Headers()
      ctx.res.headers.forEach((value: string, name: string): void => {
        newHeaders.append(name, value)
      })
      newHeaders.set('Content-Type', 'application/json')
      newHeaders.set('X-Channel', '1')
      newHeaders.delete('Content-Length')

      ctx.res = new Response(JSON.stringify({ enc: encryptedData }), {
        status: ctx.res.status,
        headers: newHeaders
      })
    } catch (error: unknown) {
      logger.error('Channel response encryption failed', {
        error: error instanceof Error ? error.message : String(error),
        channelId
      })
      // Do not fail the request — return the original (already consumed) response text
      // by creating a new response from it.
    }
  })
}
