import { Hono } from 'hono'
import { auth } from '@/shared/middlewares/auth.middleware'
import { ApiKeysController } from '@/modules/api-keys/controllers/api-keys.controller'
import { channelEncryption } from '@/shared/middlewares/channel-encryption.middleware'
import { rateLimitMiddleware } from '@/shared/middlewares/rate-limit.middleware'
import { validateBody, validateParams } from '@/shared/middlewares/validation.middleware'
import { createApiKeySchema, apiKeyIdParamSchema } from '@/modules/api-keys/validators/api-keys.validators'

import type { AccessTokenPayload } from '@/shared/types/jwt.utils.types'

const endpoint: Hono<Generics> = new Hono<Generics>()
const controller: ApiKeysController = new ApiKeysController()
const chanEnc = channelEncryption()

/** Broad guard: 60 req / 15 min per IP across all api-key management routes */
const apiKeyBaseLimit = rateLimitMiddleware({ max: 60, windowMs: 15 * 60 * 1000 })

/**
 * Creation is throttled separately: 5 new keys per hour per authenticated user.
 * API keys are long-lived credentials — bulk creation is a red flag.
 */
const apiKeyCreateLimit = rateLimitMiddleware({
  max: 5,
  windowMs: 60 * 60 * 1000,
  keyGenerator: (ctx) => {
    const session = ctx.get('session') as AccessTokenPayload | undefined
    return session?._id ? `api_key_create:${session._id}` : (ctx.req.header('cf-connecting-ip') ?? ctx.req.header('x-forwarded-for') ?? 'unknown')
  }
})

endpoint
  .use('*', apiKeyBaseLimit)
  .get('/', auth, chanEnc, controller.listApiKeys)
  .post('/', auth, chanEnc, apiKeyCreateLimit, validateBody(createApiKeySchema), controller.createApiKey)
  .delete('/:id', auth, chanEnc, validateParams(apiKeyIdParamSchema), controller.revokeApiKey)

export default endpoint
