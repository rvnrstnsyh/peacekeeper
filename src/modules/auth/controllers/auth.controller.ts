import httpResponse from '@/shared/utils/http-response.utils'

import type { Context } from 'hono'
import type { AccessTokenPayload } from '@/shared/types/jwt.utils.types'
import type { KE1, KE2, KE3, RegistrationRecord, RegistrationRequest, RegistrationResponse } from '@/shared/types/zero-access.utils.types'
import type {
  // Service DTOs
  ServiceRefreshTokenResultDTO,
  ServiceSignInAlphaResultDTO,
  ServiceSignInBetaResultDTO,
  ServiceSignUpBetaResultDTO,
  ServiceUserProfileResultDTO,
  // Request DTOs
  SignUpAlphaRequestDTO,
  SignUpAlphaResponseDTO,
  SignUpBetaRequestDTO,
  SignInAlphaRequestDTO,
  SignInBetaRequestDTO,
  SignInBetaResponseDTO,
  RefreshTokenRequestDTO,
  ForgotPasswordRequestDTO,
  ResetPasswordAlphaRequestDTO,
  ResetPasswordAlphaResponseDTO,
  ResetPasswordBetaRequestDTO,
  ChangePasswordAlphaRequestDTO,
  ChangePasswordAlphaResponseDTO,
  ChangePasswordBetaRequestDTO,
  ChangePasswordBetaResponseDTO,
  UpdateProfileRequestDTO
} from '@/modules/auth/dto/auth.dto'

import { setCookie } from 'hono/cookie'
import { decodeBase64 } from 'hono/utils/encode'
import { env } from '@/configs/environment.configs'
import { randomBytes } from '@noble/hashes/utils.js'
import { remoteAddr } from '@/shared/utils/remote-addr.utils'
import { ZeroAccess } from '@/shared/utils/zero-access.utils'
import { AuthService } from '@/modules/auth/services/auth.service'
import { Serializer } from '@/shared/utils/zero-access.utils/serializer'
import { logAuth, logError, logger, logSecurity } from '@/configs/logger.configs'
import { base64ToUint8Array, uint8ArrayToBase64 } from '@/shared/utils/common.utils'

/**
 * OPAQUE protocol instance for secure password authentication
 * Initialized with server context for cryptographic operations
 */
export const opaque: ZeroAccess = new ZeroAccess(env.OPAQUE_CONTEXT)

/**
 * AuthController
 *
 * Handles all authentication-related HTTP requests including registration,
 * sign-in, token management, and user profile operations.
 * Implements OPAQUE protocol (RFC 9807) for password-authenticated key exchange.
 */
export class AuthController {
  private authService: AuthService

  /**
   * Extract Token (Private Helper)
   *
   * Extracts JWT access token from Authorization header.
   * Expects format: "Bearer <token>"
   *
   * @param ctx - Hono context with Authorization header
   * @returns Extracted token string or null if not found/invalid format
   * @private
   */
  private extractToken(ctx: Context<Generics>): string | null {
    const authHeader: string | undefined = ctx.req.header('authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null
    }
    return authHeader.substring(7)
  }

  /**
   * Initializes the AuthController with required services
   */
  constructor() {
    this.authService = new AuthService()
  }

  /**
   * Sign Up Alpha - Phase 1 of OPAQUE Registration
   *
   * Initiates user registration by processing the client's blinded message
   * and generating server's OPAQUE registration response. Creates a random
   * credential identifier and evaluates the registration request using OPRF.
   *
   * @param ctx - Hono context containing validated request body
   * @returns Response with evaluatedMessage, serverPublicKey, and credentialIdentifier
   * @remarks
   * - First phase of two-phase OPAQUE registration
   * - Generates 32-byte random credential identifier
   * - Uses OPRF seed for evaluation
   * - Returns 400 Bad Request on processing failure
   * @endpoint POST /api/v0/auth/sign-up/alpha
   * @body { request: string } - Base64-encoded blinded message from client
   * @public
   */
  public signUpAlpha = async (ctx: Context<Generics>): Promise<Response> => {
    const ip: string = remoteAddr(ctx)

    try {
      const payload: SignUpAlphaRequestDTO = ctx.get('validatedBody') as SignUpAlphaRequestDTO
      const registrationRequest: RegistrationRequest = {
        blindedMessage: decodeBase64(payload.request.blindedMessage)
      }
      const credentialIdentifier: Uint8Array = randomBytes(32)
      const registrationResponse: RegistrationResponse = opaque.createRegistrationResponse(registrationRequest, env.serverKeyPair.publicKey, credentialIdentifier, env.oprfSeed)

      logAuth('sign_up_alpha', ip, true)

      const signUpAlphaResponse: SignUpAlphaResponseDTO = {
        credentialIdentifier: uint8ArrayToBase64(credentialIdentifier),
        evaluatedMessage: uint8ArrayToBase64(registrationResponse.evaluatedMessage),
        serverPublicKey: uint8ArrayToBase64(registrationResponse.serverPublicKey)
      }

      return httpResponse.ok(ctx, 'Registration initialized', undefined, signUpAlphaResponse)
    } catch (error) {
      logError(error as Error, {
        controller: 'AuthController',
        method: 'signUpAlpha',
        ip
      })
      return httpResponse.badRequest(ctx, 'Registration initialization failed')
    }
  }

  /**
   * Sign Up Beta - Phase 2 of OPAQUE Registration
   *
   * Completes user registration by deserializing the registration record,
   * creating the user account with email and username, and storing the
   * OPAQUE registration data. Issues access and refresh tokens upon success.
   *
   * @param ctx - Hono context containing validated registration data
   * @returns Response with user data, access token, and refresh token (cookie)
   * @remarks
   * - Second and final phase of OPAQUE registration
   * - Creates user account in database
   * - Sets secure HTTP-only refresh token cookie (7-day expiration)
   * - Returns 409 Conflict if email, username, or credential identifier exists
   * - Returns 400 Bad Request on other failures
   * @endpoint POST /api/v0/auth/sign-up/beta
   * @body {
   *   credentialIdentifier: string,
   *   record: {
   *     clientPublicKey: string,
   *     maskingKey: string,
   *     envelope: {
   *       nonce: string,
   *       authTag: string,
   *       seed: string
   *     }
   *   },
   *   email: string,
   *   username: string,
   *   firstName: string,
   *   lastName: string,
   *   phone: string,
   *   role: 'admin' | 'user',
   *   dateOfBirth: Date,
   *   gender: 'male' | 'female',
   *   address: string
   * }
   * @public
   */
  public signUpBeta = async (ctx: Context<Generics>): Promise<Response> => {
    const ip: string = remoteAddr(ctx)
    const userAgent: string = ctx.req.header('user-agent') || 'unknown'

    try {
      const payload: SignUpBetaRequestDTO = ctx.get('validatedBody') as SignUpBetaRequestDTO
      const credentialIdentifier: Uint8Array = base64ToUint8Array(payload.credentialIdentifier)
      const registrationRecord: RegistrationRecord = Serializer.deserializeRegistrationRecord(payload.record)
      const signUpResult: ServiceSignUpBetaResultDTO = await this.authService.signUpBeta(payload, registrationRecord, credentialIdentifier, env.OPAQUE_CONTEXT, ip, userAgent)
      const userId: string = signUpResult.user._id

      logAuth('sign_up_beta', userId, true, {
        email: signUpResult.user.email,
        username: signUpResult.user.username,
        ip
      })

      const signUpBetaResponse: ServiceSignUpBetaResultDTO = {
        ...signUpResult
      }

      return httpResponse.created(ctx, 'Registration successful', undefined, signUpBetaResponse)
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logError(error as Error, {
        controller: 'AuthController',
        method: 'signUpBeta',
        ip
      })

      if (message.includes('Email already registered')) {
        return httpResponse.conflict(ctx, 'Email already registered')
      }

      if (message.includes('Username already taken')) {
        return httpResponse.conflict(ctx, 'Username already taken')
      }

      if (message.includes('Credential identifier already exists')) {
        return httpResponse.conflict(ctx, 'Credential identifier already exists')
      }

      return httpResponse.badRequest(ctx, 'Registration failed')
    }
  }

  /**
   * Sign In Alpha - Phase 1 of OPAQUE Authentication
   *
   * Initiates authentication by deserializing client's KE1 message,
   * fetching user's registration record by email, and generating
   * server's KE2 response using OPAQUE protocol.
   *
   * @param ctx - Hono context containing email and KE1 message
   * @returns Response with KE2 message and credential identifier
   * @remarks
   * - First phase of two-phase OPAQUE authentication
   * - Retrieves user by email and validates existence
   * - Generates KE2 using stored registration record
   * - Logs failed attempts for security monitoring
   * - Returns 401 Unauthorized if user not found or validation fails
   * @endpoint POST /api/v0/auth/sign-in/alpha
   * @body {
   *   email: string,
   *   ke1: {
   *     blindedMessage: string,
   *     clientNonce: string,
   *     clientPublicKeyshare: string
   *   }
   * }
   * @public
   */
  public signInAlpha = async (ctx: Context<Generics>): Promise<Response> => {
    const ip: string = remoteAddr(ctx)
    const userAgent: string = ctx.req.header('user-agent') || 'unknown'

    try {
      const payload: SignInAlphaRequestDTO = ctx.get('validatedBody') as SignInAlphaRequestDTO
      const ke1: KE1 = Serializer.deserializeKE1(payload.ke1)
      const { ke2, credentialIdentifier }: ServiceSignInAlphaResultDTO = await this.authService.signInAlpha(payload.email, ke1, env.serverKeyPair, env.oprfSeed, opaque, payload.rememberMe)

      logAuth('sign_in_alpha', credentialIdentifier, true, { ip })

      const signInAlphaResponse = {
        credentialIdentifier,
        ke2: Serializer.serializeKE2(ke2)
      }

      return httpResponse.ok(ctx, 'Authentication initialized', undefined, signInAlphaResponse)
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logAuth('sign_in_alpha', ip, false, { ip, userAgent, reason: message })
      logSecurity('failed_sign_in', 'medium', { ip, error: message })

      return httpResponse.unauthorized(ctx, 'Invalid credentials')
    }
  }

  /**
   * Sign In Beta - Phase 2 of OPAQUE Authentication
   *
   * Completes authentication by deserializing client's KE3 message,
   * verifying MAC authentication, finalizing OPAQUE key exchange,
   * and issuing JWT tokens upon successful verification.
   *
   * @param ctx - Hono context containing credential identifier and KE3 message
   * @returns Response with user data, access token, and refresh token (cookie)
   * @remarks
   * - Second and final phase of OPAQUE authentication
   * - Verifies MAC to authenticate client
   * - Sets secure HTTP-only refresh token cookie (7-day expiration)
   * - Returns 400 Bad Request if authentication session expired or not found
   * - Returns 401 Unauthorized if MAC verification fails
   * @endpoint POST /api/v0/auth/sign-in/beta
   * @body {
   *   credentialIdentifier: string,
   *   ke3: {
   *     clientMac: string
   *   }
   * }
   * @public
   */
  public signInBeta = async (ctx: Context<Generics>): Promise<Response> => {
    const ip: string = remoteAddr(ctx)
    const userAgent: string = ctx.req.header('user-agent') || 'unknown'

    try {
      const payload: SignInBetaRequestDTO = ctx.get('validatedBody') as SignInBetaRequestDTO
      const ke3: KE3 = Serializer.deserializeKE3(payload.ke3)
      const signInResult: ServiceSignInBetaResultDTO = await this.authService.signInBeta(payload.credentialIdentifier, ke3, opaque, ip, userAgent)
      const userId: string = signInResult.user._id
      const cookieTTL: number = signInResult.rememberMe ? 30 * 24 * 60 * 60 : 24 * 60 * 60

      logAuth('sign_in_beta', userId, true, {
        email: signInResult.user.email,
        ip
      })
      setCookie(ctx, 'Refresh-Token', signInResult.tokens.refreshToken, {
        domain: undefined,
        path: '/api/v0',
        expires: new Date(Date.now() + cookieTTL * 1000),
        maxAge: cookieTTL,
        httpOnly: true,
        secure: env.isProduction,
        sameSite: 'Strict' as const,
        priority: 'High' as const,
        partitioned: false,
        prefix: 'secure' as const
      })

      const signInBetaResponse: SignInBetaResponseDTO = {
        user: signInResult.user,
        accessToken: signInResult.tokens.accessToken,
        expiresIn: signInResult.tokens.expiresIn
      }

      return httpResponse.ok(ctx, 'Authentication successful', undefined, signInBetaResponse)
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logAuth('sign_in_beta', ip, false, { ip, userAgent, reason: message })
      logSecurity('failed_sign_in', 'medium', { ip, error: message })

      if (message.includes('expired') || message.includes('not found')) {
        return httpResponse.badRequest(ctx, 'Authentication session expired. Please try again.')
      }

      if (message.includes('MAC verification failed')) {
        return httpResponse.unauthorized(ctx, 'Invalid credentials')
      }
      return httpResponse.unauthorized(ctx, 'Authentication failed')
    }
  }

  /**
   * Refresh Token
   *
   * Generates new access and refresh tokens using a valid refresh token
   * from secure HTTP-only cookie. Validates the old token and issues
   * new token pair with updated expiration.
   *
   * @param ctx - Hono context with refresh token in __Secure-Refresh-Token cookie
   * @returns Response with new access token
   * @remarks
   * - Reads refresh token from __Secure-Refresh-Token cookie
   * - Validates token and generates new token pair
   * - Sets new refresh token cookie (7-day expiration)
   * - Returns 401 Unauthorized if token is invalid, expired, or missing
   * @endpoint POST /api/v0/auth/refresh-token
   * @cookie __Secure-Refresh-Token: string
   * @public
   */
  public refreshToken = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const payload: RefreshTokenRequestDTO = ctx.get('validatedCookies') as RefreshTokenRequestDTO
      const ip: string = remoteAddr(ctx)
      const result: ServiceRefreshTokenResultDTO = await this.authService.refreshToken(payload['__Secure-Refresh-Token'])

      logAuth('token_refresh', result.userId, true, { ip })
      setCookie(ctx, 'Refresh-Token', result.tokens.refreshToken, {
        domain: undefined,
        path: '/api/v0',
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        maxAge: 7 * 24 * 60 * 60,
        httpOnly: true,
        secure: env.isProduction,
        sameSite: 'Strict' as const,
        priority: 'High' as const,
        partitioned: false,
        prefix: 'secure' as const
      })

      return httpResponse.ok(ctx, 'Token refreshed successfully', undefined, {
        accessToken: result.tokens.accessToken
      })
    } catch (error: unknown) {
      logError(error as Error, {
        controller: 'AuthController',
        method: 'refreshToken',
        ip: remoteAddr(ctx)
      })
      if (error instanceof Error) {
        return httpResponse.unauthorized(ctx, error.message)
      }
      return httpResponse.internalServerError(ctx, 'Token refresh failed')
    }
  }

  /**
   * Forgot Password
   *
   * Initiates password reset process by generating a reset token
   * and sending it to user's email. Always returns success message
   * regardless of email existence to prevent email enumeration attacks.
   *
   * @param ctx - Hono context with validated email in request body
   * @returns Response with generic success message
   * @remarks
   * - Always returns success message for security (prevents email enumeration)
   * - Generates reset token only if email exists in database
   * - Sends password reset link via email service
   * - Token has expiration time for security
   * @endpoint POST /api/v0/auth/forgot-password
   * @validation Required
   * @body { email: string }
   * @public
   */
  public forgotPassword = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const payload: ForgotPasswordRequestDTO = ctx.get('validatedBody') as ForgotPasswordRequestDTO
      const ip: string = remoteAddr(ctx)

      await this.authService.forgotPassword(payload.email)

      logger.info('Password reset requested', { email: payload.email, ip })

      // Always return success for security reasons
      return httpResponse.ok(ctx, 'If the email exists, a reset link has been sent')
    } catch (error: unknown) {
      logError(error as Error, {
        controller: 'AuthController',
        method: 'forgotPassword'
      })
      // Don't reveal if email exists
      return httpResponse.ok(ctx, 'If the email exists, a reset link has been sent')
    }
  }

  /**
   * Reset Password Alpha - Phase 1 of OPAQUE Password Reset
   *
   * Validates the user's reset token (from the forgot-password email link),
   * then initiates a fresh OPAQUE registration for the new password.
   * Generates a new credential identifier — the user's keypair is fully replaced
   * (unlike change-password which preserves the existing keypair).
   *
   * @param ctx - Hono context containing resetToken and OPAQUE blinded message
   * @returns Response with new credentialIdentifier, evaluatedMessage, serverPublicKey
   * @remarks
   * - Reset token is a one-time JWT from forgotPassword (1-hour expiry)
   * - On success a 5-minute reset state is stored in Redis for phase 2
   * - Returns 400 Bad Request if token is invalid, expired, or already used
   * @endpoint POST /api/v0/auth/reset-password/alpha
   * @body { resetToken: string, request: { blindedMessage: string } }
   * @public
   */
  public resetPasswordAlpha = async (ctx: Context<Generics>): Promise<Response> => {
    const ip: string = remoteAddr(ctx)

    try {
      const payload: ResetPasswordAlphaRequestDTO = ctx.get('validatedBody') as ResetPasswordAlphaRequestDTO
      const registrationRequest = { blindedMessage: decodeBase64(payload.request.blindedMessage) }

      const result: ResetPasswordAlphaResponseDTO = await this.authService.resetPasswordAlpha(payload.resetToken, registrationRequest, env.serverKeyPair.publicKey, env.oprfSeed, opaque)

      logAuth('reset_password_alpha', ip, true)

      return httpResponse.ok(ctx, 'Password reset initialized', undefined, result)
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logError(error as Error, { controller: 'AuthController', method: 'resetPasswordAlpha', ip })
      logSecurity('failed_password_reset', 'medium', { ip, error: message })

      if (message.includes('Invalid or expired reset token')) {
        return httpResponse.badRequest(ctx, 'Invalid or expired reset token')
      }
      if (message.includes('deactivated')) {
        return httpResponse.unauthorized(ctx, 'Account is deactivated')
      }

      return httpResponse.badRequest(ctx, 'Password reset initialization failed')
    }
  }

  /**
   * Reset Password Beta - Phase 2 of OPAQUE Password Reset
   *
   * Completes password reset by storing the new OPAQUE registration record
   * (new keypair), invalidating all existing sessions, and issuing a fresh
   * token pair. The old OPAQUE envelope is replaced entirely.
   *
   * @param ctx - Hono context containing new credentialIdentifier and record
   * @returns Response with user data, new access token, and refresh token (cookie)
   * @remarks
   * - Requires a valid reset state in Redis from resetPasswordAlpha (5-min TTL)
   * - Old envelope is soft-deleted and replaced with the new one
   * - All existing sessions are invalidated (refresh tokens cleared)
   * - Sets a new secure HTTP-only refresh token cookie
   * @endpoint POST /api/v0/auth/reset-password/beta
   * @body { credentialIdentifier: string, record: { clientPublicKey, maskingKey, envelope } }
   * @public
   */
  public resetPasswordBeta = async (ctx: Context<Generics>): Promise<Response> => {
    const ip: string = remoteAddr(ctx)
    const userAgent: string = ctx.req.header('user-agent') || 'unknown'

    try {
      const payload: ResetPasswordBetaRequestDTO = ctx.get('validatedBody') as ResetPasswordBetaRequestDTO
      const newRecord = Serializer.deserializeRegistrationRecord(payload.record)

      const result: ServiceSignInBetaResultDTO = await this.authService.resetPasswordBeta(payload.credentialIdentifier, newRecord, env.OPAQUE_CONTEXT, ip, userAgent)

      logAuth('reset_password_beta', result.user._id, true, { email: result.user.email, ip })

      setCookie(ctx, 'Refresh-Token', result.tokens.refreshToken, {
        domain: undefined,
        path: '/api/v0',
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        maxAge: 7 * 24 * 60 * 60,
        httpOnly: true,
        secure: env.isProduction,
        sameSite: 'Strict' as const,
        priority: 'High' as const,
        partitioned: false,
        prefix: 'secure' as const
      })

      return httpResponse.ok(ctx, 'Password reset successful', undefined, {
        user: result.user,
        accessToken: result.tokens.accessToken,
        expiresIn: result.tokens.expiresIn
      })
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logError(error as Error, { controller: 'AuthController', method: 'resetPasswordBeta', ip })
      logSecurity('failed_password_reset', 'high', { ip, error: message })

      if (message.includes('expired') || message.includes('not found')) {
        return httpResponse.badRequest(ctx, 'Reset session expired. Please restart the forgot password process.')
      }

      return httpResponse.badRequest(ctx, 'Password reset failed')
    }
  }

  /**
   * Reset Password (commented out - old bcrypt implementation)
   * @see resetPasswordAlpha / resetPasswordBeta for the OPAQUE implementation
   */

  /**
   * Verify Email
   *
   * Verifies user's email address by validating the verification token
   * from URL parameter and updating user's email verification status
   * in the database.
   *
   * @param ctx - Hono context with verify-email-token URL parameter
   * @returns Response confirming successful email verification
   * @remarks
   * - Token extracted from URL path parameter
   * - Validates token and checks expiration
   * - Updates user's emailVerified status to true
   * - Returns 400 Bad Request if token invalid, expired, or already used
   * - Returns 500 Internal Server Error on database failure
   * @endpoint GET /api/v0/auth/verify-email/:verify-email-token
   * @param verify-email-token - Verification token from URL
   * @public
   */
  public verifyEmail = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const token: string = ctx.req.param('verify-email-token') ?? ''
      const userId: string | number = await this.authService.verifyEmail(token)

      logger.info('Email verified', { userId })

      return httpResponse.ok(ctx, 'Email verified successfully')
    } catch (error: unknown) {
      logError(error as Error, {
        controller: 'AuthController',
        method: 'verifyEmail'
      })
      if (error instanceof Error) {
        return httpResponse.badRequest(ctx, error.message)
      }
      return httpResponse.internalServerError(ctx, 'Email verification failed')
    }
  }

  /**
   * Change Password Alpha - Phase 1 of OPAQUE Password Change
   *
   * Initiates password change by processing both old password authentication (KE1)
   * and new password registration request. Generates server's KE2 for old password
   * verification and registration response for new password.
   *
   * @param ctx - Hono context containing authenticated user and change password request
   * @returns Response with KE2 for old password and registration response for new password
   * @remarks
   * - First phase of two-phase OPAQUE password change
   * - Requires authentication (user must be signed in)
   * - Validates old password via OPAQUE KE2 generation
   * - Generates registration response for new password
   * - Stores server state in Redis for phase 2 verification
   * - Returns 401 Unauthorized if old credentials are invalid
   * - Returns 400 Bad Request on processing failure
   * @endpoint POST /api/v0/auth/change-password/alpha
   * @authentication Required
   * @body {
   *   request: {
   *     oldPasswordKE1: {
   *       blindedMessage: string,
   *       clientNonce: string,
   *       clientPublicKeyshare: string
   *     },
   *     newPasswordRegistrationRequest: {
   *       blindedMessage: string
   *     }
   *   }
   * }
   * @public
   */
  public changePasswordAlpha = async (ctx: Context<Generics>): Promise<Response> => {
    const ip: string = remoteAddr(ctx)
    const userAgent: string = ctx.req.header('user-agent') || 'unknown'

    try {
      const session: AccessTokenPayload = ctx.get('session')
      const userId: string = session._id
      const payload: ChangePasswordAlphaRequestDTO = ctx.get('validatedBody') as ChangePasswordAlphaRequestDTO
      // Deserialize KE1 for old password
      const oldPasswordKE1: KE1 = Serializer.deserializeKE1(payload.request.oldPasswordKE1)
      // Deserialize registration request for new password
      const newPasswordRegistrationRequest: RegistrationRequest = {
        blindedMessage: base64ToUint8Array(payload.request.newPasswordRegistrationRequest.blindedMessage)
      }
      // Process change password request through service
      const { ke2, registrationResponse, credentialIdentifier }: { ke2: KE2; registrationResponse: RegistrationResponse; credentialIdentifier: string } = await this.authService.changePasswordAlpha(
        userId,
        base64ToUint8Array(session._cid),
        oldPasswordKE1,
        newPasswordRegistrationRequest,
        env.serverKeyPair,
        env.oprfSeed,
        opaque
      )

      logAuth('change_password_alpha', userId, true, { ip, userAgent })

      const changePasswordAlphaResponse: ChangePasswordAlphaResponseDTO = {
        credentialIdentifier,
        oldPasswordKE2: Serializer.serializeKE2(ke2),
        newPasswordRegistrationResponse: {
          evaluatedMessage: uint8ArrayToBase64(registrationResponse.evaluatedMessage),
          serverPublicKey: uint8ArrayToBase64(registrationResponse.serverPublicKey)
        }
      }

      return httpResponse.ok(ctx, 'Password change initialized', undefined, changePasswordAlphaResponse)
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logAuth('change_password_alpha', ip, false, {
        ip,
        userAgent,
        reason: message
      })
      logSecurity('failed_password_change', 'medium', { ip, error: message })

      if (message.includes('Invalid credentials') || message.includes('not found')) {
        return httpResponse.unauthorized(ctx, 'Invalid credentials')
      }

      return httpResponse.badRequest(ctx, 'Password change initialization failed')
    }
  }

  /**
   * Change Password Beta - Phase 2 of OPAQUE Password Change
   *
   * Completes password change by verifying old password authentication (KE3),
   * finalizing new password registration, and updating OPAQUE envelope in database.
   * Issues new JWT tokens after successful password change.
   *
   * @param ctx - Hono context containing authenticated user and finalization data
   * @returns Response with success status and new access token
   * @remarks
   * - Second and final phase of OPAQUE password change
   * - Verifies KE3 MAC to authenticate old password
   * - Finalizes new password registration record
   * - Updates OPAQUE envelope in database (atomic operation)
   * - Invalidates all existing sessions (refresh tokens)
   * - Issues new access and refresh tokens
   * - Sets new secure HTTP-only refresh token cookie (7-day expiration)
   * - Returns 400 Bad Request if session expired or invalid
   * - Returns 401 Unauthorized if MAC verification fails
   * @endpoint POST /api/v0/auth/change-password/beta
   * @authentication Required
   * @body {
   *   credentialIdentifier: string,
   *   ke3: {
   *     clientMac: string
   *   },
   *   newRecord: {
   *     clientPublicKey: string,
   *     maskingKey: string,
   *     envelope: {
   *       nonce: string,
   *       authTag: string,
   *       seed: string
   *     }
   *   }
   * }
   * @public
   */
  public changePasswordBeta = async (ctx: Context<Generics>): Promise<Response> => {
    const ip: string = remoteAddr(ctx)
    const userAgent: string = ctx.req.header('user-agent') || 'unknown'

    try {
      const session: AccessTokenPayload = ctx.get('session')
      const userId: string = session._id
      const payload: ChangePasswordBetaRequestDTO = ctx.get('validatedBody') as ChangePasswordBetaRequestDTO
      // Deserialize KE3 for old password verification
      const ke3: KE3 = Serializer.deserializeKE3(payload.ke3)
      // Deserialize new registration record
      const newRecord: RegistrationRecord = Serializer.deserializeRegistrationRecord(payload.newRecord)
      // Complete password change through service
      const result: ServiceSignInBetaResultDTO = await this.authService.changePasswordBeta(userId, payload.credentialIdentifier, ke3, newRecord, opaque, env.OPAQUE_CONTEXT, ip, userAgent)

      logAuth('change_password_beta', userId, true, {
        email: result.user.email,
        ip,
        userAgent
      })
      // Set new refresh token cookie
      setCookie(ctx, 'Refresh-Token', result.tokens.refreshToken, {
        domain: undefined,
        path: '/api/v0',
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        maxAge: 7 * 24 * 60 * 60,
        httpOnly: true,
        secure: env.isProduction,
        sameSite: 'Strict' as const,
        priority: 'High' as const,
        partitioned: false,
        prefix: 'secure' as const
      })

      const changePasswordBetaResponse: ChangePasswordBetaResponseDTO = {
        user: result.user,
        accessToken: result.tokens.accessToken,
        expiresIn: result.tokens.expiresIn
      }

      return httpResponse.ok(ctx, 'Password changed successfully', undefined, changePasswordBetaResponse)
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logAuth('change_password_beta', ip, false, {
        ip,
        userAgent,
        reason: message
      })
      logSecurity('failed_password_change', 'high', { ip, error: message })

      if (message.includes('expired') || message.includes('not found')) {
        return httpResponse.badRequest(ctx, 'Password change session expired. Please try again.')
      }

      if (message.includes('MAC verification failed')) {
        return httpResponse.unauthorized(ctx, 'Invalid old password')
      }

      return httpResponse.badRequest(ctx, 'Password change failed')
    }
  }

  /**
   * Get Current User
   *
   * Retrieves complete profile information of the currently
   * authenticated user from the database.
   *
   * @param ctx - Hono context with authenticated user
   * @returns Response with user profile data
   * @remarks
   * - Requires authentication middleware
   * - Returns full user profile excluding sensitive fields
   * - Returns 500 Internal Server Error on database failure
   * @endpoint GET /api/v0/auth/profile
   * @authentication Required
   * @header Authorization: Bearer <access-token>
   * @public
   */
  public getProfile = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const userId: string = session._id
      const data: ServiceUserProfileResultDTO = await this.authService.getProfile(userId)

      return httpResponse.ok(ctx, 'OK', undefined, data)
    } catch (error: unknown) {
      logError(error as Error, {
        controller: 'AuthController',
        method: 'getProfile'
      })
      return httpResponse.internalServerError(ctx, 'Failed to fetch user profile')
    }
  }

  /**
   * Update Profile
   *
   * Updates authenticated user's profile information with validated
   * data from request body. Allows updating fields like username,
   * display name, bio, etc.
   *
   * @param ctx - Hono context with authenticated user and validated update data
   * @returns Response with updated user profile data
   * @remarks
   * - Requires authentication middleware
   * - Validation performed by validation middleware
   * - Returns 400 Bad Request on validation errors or conflicts (e.g., username taken)
   * - Returns 500 Internal Server Error on database failure
   * @endpoint PUT /api/v0/auth/profile
   * @authentication Required
   * @validation Required
   * @header Authorization: Bearer <access-token>
   * @body UpdateProfileRequestDTO
   * @public
   */
  public updateProfile = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const userId: string = session._id
      const payload: UpdateProfileRequestDTO = ctx.get('validatedBody') as UpdateProfileRequestDTO
      const data: ServiceUserProfileResultDTO = await this.authService.updateProfile(userId, payload)

      logger.info('Profile updated', { userId: userId })

      return httpResponse.ok(ctx, 'Profile updated successfully', undefined, data)
    } catch (error: unknown) {
      logError(error as Error, {
        controller: 'AuthController',
        method: 'updateProfile'
      })
      if (error instanceof Error) {
        return httpResponse.badRequest(ctx, error.message)
      }
      return httpResponse.internalServerError(ctx, 'Failed to update profile')
    }
  }

  /**
   * Resend Verification Email
   *
   * Generates new email verification token and sends it to
   * authenticated user's registered email address.
   *
   * @param ctx - Hono context with authenticated user
   * @returns Response confirming verification email sent
   * @remarks
   * - Requires authentication middleware
   * - Generates new verification token with expiration
   * - Sends verification email via email service
   * - Returns 400 Bad Request if email already verified
   * - Returns 500 Internal Server Error on email sending failure
   * @endpoint POST /api/v0/auth/resend-verification
   * @authentication Required
   * @header Authorization: Bearer <access-token>
   * @public
   */
  public resendVerification = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const userId: string = session._id

      await this.authService.resendVerificationEmail(userId)

      logger.info('Verification email resent', { userId })

      return httpResponse.ok(ctx, 'Verification email sent')
    } catch (error: unknown) {
      logError(error as Error, {
        controller: 'AuthController',
        method: 'resendVerification'
      })
      if (error instanceof Error) {
        return httpResponse.badRequest(ctx, error.message)
      }
      return httpResponse.internalServerError(ctx, 'Failed to resend verification email')
    }
  }

  /**
   * Sign Out
   *
   * Signs out authenticated user by extracting access token from
   * Authorization header and adding it to token blacklist to
   * invalidate the session.
   *
   * @param ctx - Hono context with authenticated user and Authorization header
   * @returns Response confirming successful sign out
   * @remarks
   * - Requires authentication middleware
   * - Extracts token from "Bearer <token>" format
   * - Adds token to blacklist for invalidation
   * - Returns 401 Unauthorized if token not found in header
   * @endpoint POST /api/v0/auth/sign-out
   * @authentication Required
   * @header Authorization: Bearer <access-token>
   * @public
   */
  public signOut = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const userId: string = session._id
      const token: string | null = this.extractToken(ctx)

      if (!token) {
        return httpResponse.unauthorized(ctx)
      }
      await this.authService.signOut(userId, token)

      logAuth('sign_out', userId, true, { ip: remoteAddr(ctx) })

      return httpResponse.ok(ctx, 'Signed out successfully')
    } catch (error: unknown) {
      logError(error as Error, {
        controller: 'AuthController',
        method: 'signOut'
      })
      return httpResponse.internalServerError(ctx, 'Sign out failed')
    }
  }
}

export default AuthController
