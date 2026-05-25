import { Hono } from 'hono'
import { auth } from '@/shared/middlewares/auth.middleware'
import { AuthController } from '@/modules/auth/controllers/auth.controller'
import { authRateLimiter, registrationRateLimiter, passwordResetRateLimiter, rateLimitMiddleware } from '@/shared/middlewares/rate-limit.middleware'
import { channelEncryption } from '@/shared/middlewares/channel-encryption.middleware'
import { validateBody, validateCookies, validateParams } from '@/shared/middlewares/validation.middleware'
import {
  changePasswordAlphaSchema,
  changePasswordBetaSchema,
  forgotPasswordSchema,
  refreshTokenSchema,
  resetPasswordAlphaSchema,
  resetPasswordBetaSchema,
  signInAlphaSchema,
  signInBetaSchema,
  signUpAlphaSchema,
  signUpBetaSchema,
  updateProfileSchema,
  verifyEmailSchema,
  securityKeysAlphaSchema,
  securityKeysBetaSchema,
  sessionIdParamSchema
} from '@/modules/auth/validators/auth.validators'

const endpoint: Hono<Generics> = new Hono<Generics>()
const controller: AuthController = new AuthController()
const chanEnc = channelEncryption()

endpoint
  // Broad DoS guard on all auth routes — keeps the door partially closed
  // even for endpoints that have no per-route limiter below.
  .use('*', rateLimitMiddleware({ max: 300, windowMs: 15 * 60 * 1000 }))
  // ── Registration ── 10 attempts/hr per IP (prevents account farming)
  .post('/sign-up/alpha', registrationRateLimiter, validateBody(signUpAlphaSchema), controller.signUpAlpha)
  .post('/sign-up/beta', registrationRateLimiter, validateBody(signUpBetaSchema), controller.signUpBeta)
  // ── Sign-in ── max 10 failed attempts per 15 min per IP (skipSuccessful)
  .post('/sign-in/alpha', authRateLimiter, validateBody(signInAlphaSchema), controller.signInAlpha)
  .post('/sign-in/beta', authRateLimiter, validateBody(signInBetaSchema), controller.signInBeta)
  .get('/refresh-token', validateCookies(refreshTokenSchema), controller.refreshToken)
  // ── Password reset ── 5 attempts/hr per IP (prevents email flooding)
  .post('/forgot-password', passwordResetRateLimiter, validateBody(forgotPasswordSchema), controller.forgotPassword)
  .post('/reset-password/alpha', passwordResetRateLimiter, validateBody(resetPasswordAlphaSchema), controller.resetPasswordAlpha)
  .post('/reset-password/beta', passwordResetRateLimiter, validateBody(resetPasswordBetaSchema), controller.resetPasswordBeta)
  .get('/verify-email/:verify-email-token', validateParams(verifyEmailSchema), controller.verifyEmail)
  // Security keys retrieval (public routes — OPAQUE re-auth is the gate)
  .post('/security-keys/alpha', validateBody(securityKeysAlphaSchema), controller.securityKeysAlpha)
  .post('/security-keys/beta', validateBody(securityKeysBetaSchema), controller.securityKeysBeta)
  // Protected routes — channel encryption runs after auth (reads session) and
  // before validateBody (may supply the decrypted request body)
  .post('/change-password/alpha', auth, chanEnc, validateBody(changePasswordAlphaSchema), controller.changePasswordAlpha)
  .post('/change-password/beta', auth, chanEnc, validateBody(changePasswordBetaSchema), controller.changePasswordBeta)
  .get('/profile', auth, chanEnc, controller.getProfile)
  .put('/profile', auth, chanEnc, validateBody(updateProfileSchema), controller.updateProfile)
  .post('/resend-verification', auth, chanEnc, controller.resendVerification)
  .get('/resend-verification/status', auth, controller.getResendVerificationStatus)
  .delete('/sign-out', auth, chanEnc, validateCookies(refreshTokenSchema), controller.signOut)
  // ── Session management — list, revoke one, revoke all
  .get('/sessions', auth, chanEnc, controller.getSessions)
  .delete('/sessions', auth, chanEnc, controller.revokeAllSessions)
  .delete('/sessions/:sessionId', auth, chanEnc, validateParams(sessionIdParamSchema), controller.revokeSession)

export default endpoint
