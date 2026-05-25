import { Hono } from 'hono'
import { auth } from '@/shared/middlewares/auth.middleware'
import { InviteController } from '@/modules/invite/controllers/invite.controller'
import { channelEncryption } from '@/shared/middlewares/channel-encryption.middleware'
import { rateLimitMiddleware } from '@/shared/middlewares/rate-limit.middleware'
import { validateBody, validateParams } from '@/shared/middlewares/validation.middleware'
import { createInvitationSchema, inviteCodeParamSchema } from '@/modules/invite/validators/invite.validators'

import type { AccessTokenPayload } from '@/shared/types/jwt.utils.types'

const endpoint: Hono<Generics> = new Hono<Generics>()
const controller: InviteController = new InviteController()
const chanEnc = channelEncryption()

/** Broad guard: 120 req / 15 min per IP across all invite routes */
const inviteBaseLimit = rateLimitMiddleware({ max: 120, windowMs: 15 * 60 * 1000 })

/**
 * Creation is throttled separately to discourage bulk code generation:
 * 10 new codes per hour per authenticated user (keyed by user ID)
 */
const inviteCreateLimit = rateLimitMiddleware({
  max: 10,
  windowMs: 60 * 60 * 1000,
  keyGenerator: (ctx) => {
    const session = ctx.get('session') as AccessTokenPayload | undefined
    return session?._id ? `invite_create:${session._id}` : (ctx.req.header('cf-connecting-ip') ?? ctx.req.header('x-forwarded-for') ?? 'unknown')
  }
})

endpoint
  .use('*', inviteBaseLimit)
  // Public — anyone (including unauthenticated sign-up pages) can preview a code
  .get('/:code', validateParams(inviteCodeParamSchema), controller.getInvitation)
  // Protected — require valid session
  .get('/', auth, chanEnc, controller.listInvitations)
  .post('/', auth, chanEnc, inviteCreateLimit, validateBody(createInvitationSchema), controller.createInvitation)
  .delete('/:code', auth, chanEnc, validateParams(inviteCodeParamSchema), controller.revokeInvitation)

export default endpoint
