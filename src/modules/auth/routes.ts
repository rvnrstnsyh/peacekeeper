import { Hono } from 'hono'
import { auth } from '@/shared/middlewares/auth.middleware'
import { AuthController } from '@/modules/auth/controllers/auth.controller'
import { rateLimitMiddleware } from '@/shared/middlewares/rate-limit.middleware'
import { validateBody, validateCookies, validateParams } from '@/shared/middlewares/validation.middleware'
import {
  changePasswordAlphaSchema,
  changePasswordBetaSchema,
  forgotPasswordSchema,
  refreshTokenSchema,
  resetPasswordSchema as _,
  signInAlphaSchema,
  signInBetaSchema,
  signUpAlphaSchema,
  signUpBetaSchema,
  updateProfileSchema,
  verifyEmailSchema
} from '@/modules/auth/validators/auth.validator'

const endpoint: Hono<Generics> = new Hono<Generics>()
const controller: AuthController = new AuthController()

endpoint
  // Rate limiting for auth endpoints, 20 requests per 15 minutes
  // Increase the limit for production
  .use('*', rateLimitMiddleware({ max: 20, windowMs: 15 * 60 * 1000 }))
  // Public routes
  .post('/sign-up/alpha', validateBody(signUpAlphaSchema), controller.signUpAlpha)
  .post('/sign-up/beta', validateBody(signUpBetaSchema), controller.signUpBeta)
  .post('/sign-in/alpha', validateBody(signInAlphaSchema), controller.signInAlpha)
  .post('/sign-in/beta', validateBody(signInBetaSchema), controller.signInBeta)
  .get('/refresh-token', validateCookies(refreshTokenSchema), controller.refreshToken)
  .post('/forgot-password', validateBody(forgotPasswordSchema), controller.forgotPassword)
  // TODO .post('/reset-password/alpha', validateBody(resetPasswordSchema), controller.resetPassword)
  // TODO .post('/reset-password/beta/:reset-token', validateBody(resetPasswordSchema), controller.resetPassword)
  .get('/verify-email/:verify-email-token', validateParams(verifyEmailSchema), controller.verifyEmail)
  // Protected routes
  .post('/change-password/alpha', auth, validateBody(changePasswordAlphaSchema), controller.changePasswordAlpha)
  .post('/change-password/beta', auth, validateBody(changePasswordBetaSchema), controller.changePasswordBeta)
  .get('/profile', auth, controller.getProfile)
  .put('/profile', auth, validateBody(updateProfileSchema), controller.updateProfile)
  .post('/resend-verification', auth, controller.resendVerification)
  .delete('/sign-out', auth, validateCookies(refreshTokenSchema), controller.signOut)

export default endpoint
