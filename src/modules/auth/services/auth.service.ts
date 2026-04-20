import type { User } from '@/modules/auth/models/users.model'
import type { ZeroAccess } from '@/shared/utils/zero-access.utils'
import type { BaseTokenPayload, RefreshTokenPayload, TokenPair } from '@/shared/types/jwt.utils.types'
import type { NewOpaqueEnvelope, OpaqueEnvelope } from '@/modules/auth/models/opaque-envelopes.model'
import type { KE1, KE2, KE3, RegistrationRecord, RegistrationRequest, RegistrationResponse, ServerState } from '@/shared/types/zero-access.utils.types'
import type {
  // Service DTOs
  ServiceSignUpBetaResultDTO,
  ServiceSignInAlphaResultDTO,
  ServiceSignInBetaResultDTO,
  ServiceRefreshTokenResultDTO,
  ServiceUserProfileResultDTO,
  // Request DTOs
  SignUpBetaRequestDTO,
  UpdateProfileRequestDTO,
  ResetPasswordAlphaResponseDTO
} from '@/modules/auth/dto/auth.dto'

import { logger } from '@/configs/logger.configs'
import { env } from '@/configs/environment.configs'
import { randomBytes } from '@noble/hashes/utils.js'
import { sessionStore } from '@/shared/utils/session-store.utils'
import { REDIS_KEYS, TTL } from '@/shared/constants/redis.constants'
import { UserRepository } from '@/modules/auth/repositories/user.repository'
import { base64ToUint8Array, uint8ArrayToBuffer } from '@/shared/utils/common.utils'
import { OpaqueEnvelopesRepository } from '@/modules/auth/repositories/opaque-envelopes.repository'
import {
  createJwtTokenPair,
  decodeToken,
  generateEmailVerificationToken,
  generatePasswordResetToken,
  verifyEmailVerificationToken,
  verifyPasswordResetToken,
  verifyRefreshToken
} from '@/shared/utils/jwt.utils'

/**
 * AuthService
 *
 * Core authentication service implementing OPAQUE protocol (RFC 9807) for
 * password-authenticated key exchange. Manages user registration, authentication,
 * token lifecycle, and account operations with Redis-backed session management.
 *
 * Key responsibilities:
 * - OPAQUE protocol registration and authentication flows
 * - JWT token generation and validation
 * - Session state management via Redis
 * - Email verification workflows
 * - Password reset operations
 * - User profile management
 */
export class AuthService {
  private userRepository: UserRepository
  private opaqueEnvelopesRepository: OpaqueEnvelopesRepository

  /**
   * Generate and Store Email Verification Token (Private Helper)
   *
   * Creates JWT-based email verification token with 24-hour expiration
   * and stores it in Redis. Fails gracefully if Redis is unavailable
   * by logging warning without throwing error.
   *
   * @param userId - User ID for token generation and Redis key
   * @param email - User email address included in JWT payload
   * @throws Error if JWT token generation fails
   * @remarks
   * - Token expires in 24 hours (TTL.VERIFICATION_TOKEN)
   * - Non-blocking operation - errors are logged but not thrown
   * - TODO: Integrate email service to send verification link
   * @private
   */
  private async generateVerificationToken(userId: string, email: string): Promise<void> {
    try {
      const token: string = await generateEmailVerificationToken(userId, email)
      await sessionStore.set(REDIS_KEYS.VERIFICATION_TOKEN(userId), token, TTL.VERIFICATION_TOKEN)

      // TODO: Send verification email
      // await emailService.sendVerificationEmail(email, token)
    } catch (error: unknown) {
      logger.error('Failed to generate verification token', { userId, error })
      throw error
    }
  }

  /**
   * Store OPAQUE Server State in Redis (Private Helper)
   *
   * Persists authentication state between OPAQUE protocol phases (signInAlpha → signInBeta).
   * State includes expectedClientMac for KE3 verification, sessionKey for potential E2EE,
   * userId for user lookup, and timestamp for debugging.
   *
   * @param credentialIdentifier - Base64 credential identifier used as Redis key
   * @param state - Authentication state object containing:
   *   - userId: User identifier for database lookup
   *   - expectedClientMac: Base64-encoded MAC for KE3 verification
   *   - sessionKey: Base64-encoded session key for E2EE (future use)
   *   - timestamp: Unix timestamp for debugging/monitoring
   * @throws Error if Redis is unavailable (cannot proceed with authentication)
   * @remarks
   * - State expires in 5 minutes (TTL.OPAQUE_STATE) to prevent session fixation
   * - Redis availability is required - throws error if not available
   * - State must be deleted after use to prevent replay attacks
   * @private
   */
  private async storeOpaqueState(
    credentialIdentifier: string,
    state: {
      userId: string
      expectedClientMac: string
      sessionKey: string
      rememberMe: boolean
      timestamp: number
    }
  ): Promise<void> {
    const stateKey: string = REDIS_KEYS.OPAQUE_STATE(credentialIdentifier)
    await sessionStore.set(stateKey, JSON.stringify(state), TTL.OPAQUE_STATE)
    logger.debug('OPAQUE state stored', {
      credentialIdentifier,
      expiresIn: `${TTL.OPAQUE_STATE}s`
    })
  }

  /**
   * Retrieve OPAQUE Server State from Redis (Private Helper)
   *
   * Fetches stored authentication state for KE3 verification in signInBeta.
   * Returns null if state not found or expired (5-minute TTL).
   *
   * @param credentialIdentifier - Base64 credential identifier used as Redis key
   * @returns Parsed authentication state object or null if not found/expired
   * @throws Error if Redis is unavailable
   * @remarks
   * - Used in signInBeta to verify KE3 message
   * - Returns null for expired or non-existent state
   * - State includes expectedClientMac, sessionKey, userId, and timestamp
   * @private
   */
  private async getOpaqueState(credentialIdentifier: string): Promise<{
    userId: string
    expectedClientMac: string
    sessionKey: string
    rememberMe: boolean
    timestamp: number
  } | null> {
    const stateKey: string = REDIS_KEYS.OPAQUE_STATE(credentialIdentifier)
    const stateData: string | null = await sessionStore.get(stateKey)
    if (!stateData) return null
    return JSON.parse(stateData) as { userId: string; expectedClientMac: string; sessionKey: string; rememberMe: boolean; timestamp: number }
  }

  /**
   * Delete OPAQUE Server State from Redis (Private Helper)
   *
   * Removes authentication state after KE3 verification completes
   * (whether successful or failed). Prevents state reuse and replay attacks.
   *
   * @param credentialIdentifier - Base64 credential identifier used as Redis key
   * @remarks
   * - Called after signInBeta completes (success or failure)
   * - Fails silently if Redis is unavailable
   * - Essential for preventing replay attacks
   * @private
   */
  private async deleteOpaqueState(credentialIdentifier: string): Promise<void> {
    await sessionStore.del(REDIS_KEYS.OPAQUE_STATE(credentialIdentifier))
  }

  /**
   * Store Refresh Token in Redis (Private Helper)
   *
   * Caches refresh token in Redis for validation during token refresh operations.
   * Enables token reuse detection and invalidation on sign out.
   *
   * @param userId - User ID used as Redis key
   * @param token - JWT refresh token string to store
   * @remarks
   * - Token expires in 7 days (TTL.REFRESH_TOKEN)
   * - Fails gracefully if Redis unavailable (logs warning)
   * - Used for token reuse detection in refreshToken method
   * - Automatically overwritten on new token generation
   * @private
   */
  private async storeRefreshToken(userId: string, token: string, ttl: number = TTL.REFRESH_TOKEN): Promise<void> {
    await sessionStore.set(REDIS_KEYS.REFRESH_TOKEN(userId), token, ttl)
  }

  /**
   * Sanitize User (Private Helper)
   *
   * Removes sensitive and internal fields from user object before
   * returning to client. Prevents exposure of soft-delete metadata
   * and other internal database fields.
   *
   * @param user - Raw user object from database with all fields
   * @returns Sanitized user object without sensitive fields (deletedAt, etc.)
   * @remarks
   * - Removes deletedAt field (soft delete timestamp)
   * - Applied to all user data returned to client
   * - Maintains type safety with ServiceUserProfileResultDTO
   * @private
   */
  private sanitizeUser(user: User): ServiceUserProfileResultDTO {
    const { deletedAt: _deletedAt, ...sanitized }: User = user
    return sanitized as ServiceUserProfileResultDTO
  }

  /**
   * Initializes AuthService with required repositories
   */
  constructor() {
    this.userRepository = new UserRepository()
    this.opaqueEnvelopesRepository = new OpaqueEnvelopesRepository()
  }

  /**
   * Sign Up Beta - Complete OPAQUE Registration
   *
   * Finalizes user registration by creating user account and storing OPAQUE envelope.
   * This is phase 2 of the OPAQUE registration protocol (signUpAlpha → signUpBeta).
   *
   * Process flow:
   * 1. Validates email uniqueness in database
   * 2. Validates credential identifier uniqueness
   * 3. Creates user account with provided data
   * 4. Converts OPAQUE registration record to database format
   * 5. Stores OPAQUE envelope with user association
   * 6. Generates email verification token asynchronously (non-blocking)
   *
   * @param payload - Registration data (email, username, etc.)
   * @param record - OPAQUE registration record from client (clientPublicKey, maskingKey, envelope)
   * @param credentialIdentifier - Unique 32-byte identifier for this credential
   * @param context - OPAQUE context string for protocol consistency
   * @param ip - Client IP address for audit trail
   * @param userAgent - Client user agent for audit trail
   * @returns Object containing sanitized user data
   * @throws Error "Email already registered" if email exists
   * @throws Error "Credential identifier already exists" if credential ID exists
   * @throws Error "Failed to create user account" if user creation fails
   * @throws Error "Failed to complete registration" if envelope creation fails
   * @remarks
   * - Implements automatic rollback: if envelope creation fails, user is deleted
   * - Email verification token generation is non-blocking (errors logged only)
   * - All OPAQUE Uint8Arrays converted to Buffers for database storage
   * - Envelope stores nonce, authTag, and seed separately for database structure
   * @public
   */
  public signUpBeta = async (
    payload: SignUpBetaRequestDTO,
    record: RegistrationRecord,
    credentialIdentifier: Uint8Array,
    context: string,
    ip: string,
    userAgent: string
  ): Promise<ServiceSignUpBetaResultDTO> => {
    const existingUser: User | null = await this.userRepository.findByEmail(payload.email)

    if (existingUser) {
      throw new Error('Email already registered')
    }

    const credentialIdentifierBuffer: Buffer = uint8ArrayToBuffer(credentialIdentifier)
    const existingEnvelope: OpaqueEnvelope | null = await this.opaqueEnvelopesRepository.findByCredentialIdentifier(credentialIdentifierBuffer)

    if (existingEnvelope) {
      throw new Error('Credential identifier already exists')
    }

    const totalUsers: number = await this.userRepository.countAll()
    const role: 'admin' | 'user' = totalUsers === 0 ? 'admin' : 'user'

    let user: User
    try {
      user = await this.userRepository.create({ ...payload, role })
    } catch (error: unknown) {
      logger.error('Failed to create user', { error, email: payload.email })
      throw new Error('Failed to create user account', { cause: error })
    }

    const userId: string = user._id

    try {
      const newOpaqueEnvelope: NewOpaqueEnvelope = {
        userId,
        credentialIdentifier: credentialIdentifierBuffer,
        clientPublicKey: uint8ArrayToBuffer(record.clientPublicKey),
        maskingKey: uint8ArrayToBuffer(record.maskingKey),
        nonce: uint8ArrayToBuffer(record.envelope.nonce),
        authTag: uint8ArrayToBuffer(record.envelope.authTag),
        seed: uint8ArrayToBuffer(record.envelope.seed),
        context,
        registrationIp: ip,
        registrationUserAgent: userAgent
      }
      const envelope: OpaqueEnvelope = await this.opaqueEnvelopesRepository.create(newOpaqueEnvelope)
      const envelopeId: string = envelope._id

      logger.info('OPAQUE envelope created', { userId, envelopeId })
    } catch (envelopeError) {
      // Rollback: delete user if envelope creation fails
      logger.error('Failed to create OPAQUE envelope, rolling back user', {
        userId,
        error: envelopeError
      })

      try {
        await this.userRepository.delete(userId)
      } catch (rollbackError) {
        logger.error('Failed to rollback user creation', {
          userId,
          error: rollbackError
        })
      }
      throw new Error('Failed to complete registration', { cause: envelopeError })
    }

    // Generate and store verification token (non-blocking)
    this.generateVerificationToken(userId, user.email).catch((error: unknown) => {
      logger.error('Failed to generate verification token', {
        userId,
        error
      })
    })

    logger.info('User registered successfully', {
      userId,
      email: user.email,
      username: user.username
    })

    return { user: this.sanitizeUser(user) }
  }

  /**
   * Sign In Alpha - Initiate OPAQUE Authentication
   *
   * Starts authentication using OPAQUE protocol phase 1 (signInAlpha → signInBeta).
   * Retrieves user's OPAQUE envelope, generates KE2 message, and stores server state.
   *
   * Process flow:
   * 1. Validates user exists by email
   * 2. Checks user account is active
   * 3. Retrieves OPAQUE envelope from database
   * 4. Reconstructs RegistrationRecord from database fields
   * 5. Generates KE2 using OPAQUE protocol with server keys
   * 6. Stores server state in Redis (expectedClientMac, sessionKey, userId)
   * 7. Returns KE2 and credential identifier for client
   *
   * @param email - User's email address for lookup
   * @param ke1 - Key Exchange message 1 from client (OPAQUE protocol)
   * @param serverKeyPair - Server's OPAQUE key pair (publicKey, privateKey)
   * @param oprfSeed - OPRF seed for deterministic operations
   * @param opaque - ZeroAccess instance for OPAQUE operations
   * @returns Object containing KE2 message and base64 credential identifier
   * @throws Error "User not found" if email doesn't exist
   * @throws Error "Account is deactivated" if user.isActive is false
   * @throws Error "Invalid credentials" if OPAQUE envelope not found
   * @remarks
   * - Server state stored in Redis with 5-minute expiration
   * - State required for KE3 verification in signInBeta
   * - Credential identifier returned as base64 for client use
   * - ServerState contains expectedClientMac and sessionKey
   * @public
   */
  public signInAlpha = async (
    email: string,
    ke1: KE1,
    serverKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array },
    oprfSeed: Uint8Array,
    opaque: ZeroAccess,
    rememberMe: boolean
  ): Promise<ServiceSignInAlphaResultDTO> => {
    const user: User | null = await this.userRepository.findByEmail(email)
    if (!user) {
      throw new Error('User not found')
    }

    if (!user.isActive) {
      throw new Error('Account is deactivated')
    }

    const userId: string = user._id
    const envelope: OpaqueEnvelope | null = await this.opaqueEnvelopesRepository.findByUserId(userId)

    if (!envelope) {
      throw new Error('Invalid credentials')
    }

    const record: RegistrationRecord = {
      clientPublicKey: uint8ArrayToBuffer(envelope.clientPublicKey),
      maskingKey: uint8ArrayToBuffer(envelope.maskingKey),
      envelope: {
        nonce: uint8ArrayToBuffer(envelope.nonce),
        authTag: uint8ArrayToBuffer(envelope.authTag),
        seed: uint8ArrayToBuffer(envelope.seed)
      }
    }

    const { ke2, state }: { ke2: KE2; state: ServerState } = opaque.generateKE2(
      undefined,
      serverKeyPair.privateKey,
      serverKeyPair.publicKey,
      record,
      envelope.credentialIdentifier,
      oprfSeed,
      ke1,
      undefined
    )
    const credentialIdentifier: string = uint8ArrayToBuffer(envelope.credentialIdentifier).toString('base64')

    await this.storeOpaqueState(credentialIdentifier, {
      userId,
      expectedClientMac: uint8ArrayToBuffer(state.expectedClientMac).toString('base64'),
      sessionKey: uint8ArrayToBuffer(state.sessionKey).toString('base64'),
      rememberMe,
      timestamp: Date.now()
    })

    logger.info('OPAQUE KE2 generated', {
      credentialIdentifier,
      email: user.email
    })
    return { ke2, credentialIdentifier }
  }

  /**
   * Sign In Beta - Complete OPAQUE Authentication
   *
   * Finalizes authentication by verifying KE3 MAC and issuing JWT tokens.
   * This is phase 2 of the OPAQUE authentication protocol (signInAlpha → signInBeta).
   *
   * Process flow:
   * 1. Retrieves server state from Redis using credential identifier
   * 2. Converts base64 expectedClientMac to Uint8Array
   * 3. Verifies KE3 MAC matches expectedClientMac using OPAQUE
   * 4. Deletes server state from Redis (prevent replay)
   * 5. Validates user exists and is active
   * 6. Generates JWT access and refresh tokens
   * 7. Stores refresh token in Redis
   *
   * @param credentialIdentifier - Base64 credential identifier from signInAlpha
   * @param ke3 - Key Exchange message 3 from client containing clientMac
   * @param opaque - ZeroAccess instance for MAC verification
   * @param ip - Client IP address for audit logging
   * @param userAgent - Client user agent for audit logging
   * @returns Object containing sanitized user data and JWT token pair
   * @throws Error "Authentication session expired or not found" if state not in Redis
   * @throws Error "Invalid authentication - MAC verification failed" if MAC mismatch
   * @throws Error "User not found" if userId from state doesn't exist
   * @throws Error "Account is deactivated" if user.isActive is false
   * @remarks
   * - Server state deleted immediately after retrieval (success or failure)
   * - MAC verification is critical security check - failure logs and throws
   * - Session key available in state for future E2EE features (currently unused)
   * - Refresh token stored with 7-day expiration
   * - Access token includes userId, email, username, and role in payload
   * @public
   */
  public signInBeta = async (credentialIdentifier: string, ke3: KE3, opaque: ZeroAccess, ip: string, userAgent: string): Promise<ServiceSignInBetaResultDTO> => {
    const state = await this.getOpaqueState(credentialIdentifier)
    if (!state) {
      throw new Error('Authentication session expired or not found')
    }

    const expectedClientMac: Uint8Array = base64ToUint8Array(state.expectedClientMac)
    // TODO: use sessionKey for encrypted session if needed (E2EE)
    const _sessionKey: Uint8Array = base64ToUint8Array(state.sessionKey)
    // Verify KE3 - MAC comparison
    const isValid: boolean = opaque.verifyKE3(ke3.clientMac, expectedClientMac)

    if (!isValid) {
      // Cleanup state on failure
      await this.deleteOpaqueState(credentialIdentifier)
      throw new Error('Invalid authentication - MAC verification failed')
    }

    // Authentication successful - cleanup state
    await this.deleteOpaqueState(credentialIdentifier)

    const user: User | null = await this.userRepository.findById(state.userId)
    if (!user) {
      throw new Error('User not found')
    }

    if (!user.isActive) {
      throw new Error('Account is deactivated')
    }

    const userId: string = user._id
    const refreshTokenTTL: number = state.rememberMe ? env.sessionRememberMeTTL : env.sessionTTL
    const tokens: TokenPair = await createJwtTokenPair(
      {
        user: {
          _id: userId,
          _cid: credentialIdentifier,
          email: user.email,
          username: user.username,
          role: user.role
        }
      },
      refreshTokenTTL
    )

    await this.storeRefreshToken(userId, tokens.refreshToken, refreshTokenTTL)

    logger.info('User authenticated successfully', {
      userId,
      email: user.email,
      ip,
      userAgent
    })
    return { user: this.sanitizeUser(user), tokens, rememberMe: state.rememberMe }
  }

  /**
   * Refresh Token
   *
   * Generates new JWT access and refresh token pair using valid refresh token.
   * Validates token against Redis cache if available for additional security.
   *
   * Process flow:
   * 1. Verifies refresh token JWT signature and expiration
   * 2. Extracts userId from token payload
   * 3. Validates user exists and is active
   * 4. Compares token with stored token in Redis (if Redis available)
   * 5. Generates new JWT token pair
   * 6. Updates stored refresh token in Redis
   *
   * @param refreshToken - Current JWT refresh token from client cookie
   * @returns Object containing userId and new token pair (accessToken, refreshToken)
   * @throws Error "Invalid refresh token" if JWT verification fails
   * @throws Error "User not found" if userId doesn't exist in database
   * @throws Error "Account is deactivated" if user.isActive is false
   * @throws Error "Invalid refresh token" if stored token doesn't match (token reuse)
   * @remarks
   * - Redis token validation is optional - works without Redis (JWT-only validation)
   * - Token mismatch detection prevents token reuse attacks
   * - New refresh token stored with 7-day expiration
   * - Old refresh token is replaced, not revoked explicitly
   * @public
   */
  public refreshToken = async (refreshToken: string): Promise<ServiceRefreshTokenResultDTO> => {
    const payload: RefreshTokenPayload = await verifyRefreshToken(refreshToken)
    const user: User | null = await this.userRepository.findById(payload._id)
    const envelope: OpaqueEnvelope | null = await this.opaqueEnvelopesRepository.findByCredentialIdentifier(Buffer.from(payload._cid, 'base64'))

    if (!user) {
      throw new Error('User not found')
    }
    if (!user.isActive) {
      throw new Error('Account is deactivated')
    }
    if (!envelope) {
      throw new Error("Credential identifier doesn't exist")
    }

    const userId: string = user._id
    const storedToken: string | null = await sessionStore.get(REDIS_KEYS.REFRESH_TOKEN(userId))
    if (storedToken && storedToken !== refreshToken) {
      throw new Error('Invalid refresh token')
    }

    const tokens: TokenPair = await createJwtTokenPair({
      user: {
        _id: userId,
        _cid: uint8ArrayToBuffer(envelope.credentialIdentifier).toString('base64'),
        email: user.email,
        username: user.username,
        role: user.role
      }
    })

    await sessionStore.set(REDIS_KEYS.REFRESH_TOKEN(userId), tokens.refreshToken, TTL.REFRESH_TOKEN)
    logger.info('Token refreshed successfully', { userId })
    return { userId, tokens }
  }

  /**
   * Forgot Password
   *
   * Initiates password reset by generating reset token and storing in Redis.
   * Returns silently regardless of email existence to prevent enumeration attacks.
   *
   * Process flow:
   * 1. Looks up user by email (returns silently if not found)
   * 2. Generates password reset JWT token with 1-hour expiration
   * 3. Stores token in Redis with 1-hour TTL
   * 4. TODO: Sends reset email with token link
   *
   * @param email - User's email address for lookup
   * @remarks
   * - Always succeeds to prevent email enumeration attacks
   * - Returns immediately without error if user doesn't exist
   * - Reset token stored with 1-hour expiration (3600 seconds)
   * - Email sending not yet implemented (marked TODO)
   * - Token should be sent via email link: /reset-password/:token
   * @public
   */
  public forgotPassword = async (email: string): Promise<void> => {
    const user: User | null = await this.userRepository.findByEmail(email)
    if (!user) {
      return
    }
    const userId: string = user._id
    const resetToken: string = await generatePasswordResetToken(userId, user.email)

    await sessionStore.set(REDIS_KEYS.RESET_PASSWORD_TOKEN(userId), resetToken, TTL.RESET_PASSWORD_TOKEN)

    // TODO: Send reset email with resetToken link
    // await this.emailService.sendPasswordResetEmail(user.email, resetToken)

    logger.info('Password reset requested', { userId })
  }

  /**
   * Reset Password Alpha - Initiate OPAQUE Password Reset
   *
   * Phase 1 of the OPAQUE-based password reset flow.
   * Validates the reset token issued by forgotPassword, then starts a fresh
   * OPAQUE registration for the new password — identical to signUpAlpha but
   * gated by the reset token. A brand-new credential identifier is generated
   * so the user's keypair is fully replaced (unlike changePassword which keeps it).
   *
   * Process flow:
   * 1. Verify the reset token JWT and extract userId
   * 2. Validate token matches the one stored in Redis (anti-replay)
   * 3. Check user exists and is active
   * 4. Generate a new random 32-byte credential identifier
   * 5. Evaluate the client's blinded message via OPRF (createRegistrationResponse)
   * 6. Store reset state in Redis keyed by the new credentialIdentifier
   * 7. Return credentialIdentifier, evaluatedMessage, and serverPublicKey
   *
   * @param resetToken - JWT password reset token from forgotPassword
   * @param registrationRequest - OPAQUE registration request with blindedMessage
   * @param serverPublicKey - Server's OPAQUE public key
   * @param oprfSeed - OPRF seed for deterministic operations
   * @param opaque - ZeroAccess instance for OPAQUE operations
   * @returns Reset alpha response with new credentialIdentifier + OPRF result
   * @throws Error "Invalid or expired reset token" if token verification fails
   * @throws Error "Invalid or expired reset token" if Redis token mismatch
   * @throws Error "User not found" if userId from token doesn't exist
   * @throws Error "Account is deactivated" if user.isActive is false
   * @public
   */
  public resetPasswordAlpha = async (
    resetToken: string,
    registrationRequest: RegistrationRequest,
    serverPublicKey: Uint8Array,
    oprfSeed: Uint8Array,
    opaque: ZeroAccess
  ): Promise<ResetPasswordAlphaResponseDTO> => {
    // Verify and decode the reset token
    let userId: string
    try {
      const payload = await verifyPasswordResetToken(resetToken)
      userId = payload.userId
    } catch {
      throw new Error('Invalid or expired reset token')
    }

    // Validate token matches stored Redis value (anti-replay)
    const storedToken: string | null = await sessionStore.get(REDIS_KEYS.RESET_PASSWORD_TOKEN(userId))
    if (!storedToken || storedToken !== resetToken) {
      throw new Error('Invalid or expired reset token')
    }

    const user: User | null = await this.userRepository.findById(userId)
    if (!user) {
      throw new Error('User not found')
    }
    if (!user.isActive) {
      throw new Error('Account is deactivated')
    }

    // Generate fresh credential identifier — full keypair reset
    const newCredentialIdentifier: Uint8Array = randomBytes(32)
    const registrationResponse = opaque.createRegistrationResponse(registrationRequest, serverPublicKey, newCredentialIdentifier, oprfSeed)
    const credId: string = uint8ArrayToBuffer(newCredentialIdentifier).toString('base64')

    // Store transient reset state for beta phase
    await sessionStore.set(REDIS_KEYS.RESET_PASSWORD_STATE(credId), JSON.stringify({ userId, timestamp: Date.now() }), TTL.RESET_PASSWORD_STATE)

    logger.info('Password reset alpha completed', { userId })

    return {
      credentialIdentifier: credId,
      evaluatedMessage: uint8ArrayToBuffer(registrationResponse.evaluatedMessage).toString('base64'),
      serverPublicKey: uint8ArrayToBuffer(registrationResponse.serverPublicKey).toString('base64')
    }
  }

  /**
   * Reset Password Beta - Complete OPAQUE Password Reset
   *
   * Phase 2 of the OPAQUE-based password reset flow.
   * The client has completed OPAQUE client-side registration and sends the
   * new RegistrationRecord. The server replaces the old OPAQUE envelope with
   * the new one (new credentialIdentifier), invalidates all existing sessions,
   * and issues a fresh token pair.
   *
   * This is equivalent to a fresh sign-up for the OPAQUE layer — the user's
   * entire keypair is replaced, which is the intended behavior for reset (as
   * opposed to changePassword which preserves the existing credentialIdentifier).
   *
   * Process flow:
   * 1. Retrieve reset state from Redis using credentialIdentifier
   * 2. Validate state exists and extract userId
   * 3. Delete reset state and reset token from Redis (one-time use)
   * 4. Validate user exists and is active
   * 5. Soft-delete old OPAQUE envelope
   * 6. Create new OPAQUE envelope with new credentialIdentifier + newRecord
   * 7. Invalidate all existing refresh tokens
   * 8. Generate new JWT access and refresh tokens
   *
   * @param credentialIdentifier - Base64 new credential identifier from alpha phase
   * @param newRecord - New OPAQUE registration record from client
   * @param context - OPAQUE context string for protocol consistency
   * @param ip - Client IP address for audit logging
   * @param userAgent - Client user agent for audit logging
   * @returns Object containing sanitized user data and new JWT token pair
   * @throws Error "Reset session expired or not found" if state not in Redis
   * @throws Error "User not found" if userId from state doesn't exist
   * @throws Error "Account is deactivated" if user.isActive is false
   * @throws Error "Failed to complete password reset" if envelope creation fails
   * @public
   */
  public resetPasswordBeta = async (credentialIdentifier: string, newRecord: RegistrationRecord, context: string, ip: string, userAgent: string): Promise<ServiceSignInBetaResultDTO> => {
    // Retrieve and validate reset state
    const stateRaw: string | null = await sessionStore.get(REDIS_KEYS.RESET_PASSWORD_STATE(credentialIdentifier))
    if (!stateRaw) {
      throw new Error('Reset session expired or not found')
    }
    const state = JSON.parse(stateRaw) as { userId: string; timestamp: number }

    // Consume reset state and token (one-time use)
    await sessionStore.del(REDIS_KEYS.RESET_PASSWORD_STATE(credentialIdentifier))
    await sessionStore.del(REDIS_KEYS.RESET_PASSWORD_TOKEN(state.userId))

    const user: User | null = await this.userRepository.findById(state.userId)
    if (!user) {
      throw new Error('User not found')
    }
    if (!user.isActive) {
      throw new Error('Account is deactivated')
    }

    const userId: string = user._id
    const credentialIdBuffer: Buffer = Buffer.from(credentialIdentifier, 'base64')

    // Replace old envelope: soft-delete first, then create new one with new keypair
    await this.opaqueEnvelopesRepository.deleteByUserId(userId)

    try {
      const newOpaqueEnvelope: NewOpaqueEnvelope = {
        userId,
        credentialIdentifier: credentialIdBuffer,
        clientPublicKey: uint8ArrayToBuffer(newRecord.clientPublicKey),
        maskingKey: uint8ArrayToBuffer(newRecord.maskingKey),
        nonce: uint8ArrayToBuffer(newRecord.envelope.nonce),
        authTag: uint8ArrayToBuffer(newRecord.envelope.authTag),
        seed: uint8ArrayToBuffer(newRecord.envelope.seed),
        context,
        registrationIp: ip,
        registrationUserAgent: userAgent
      }
      await this.opaqueEnvelopesRepository.create(newOpaqueEnvelope)
    } catch (envelopeError) {
      logger.error('Failed to create new OPAQUE envelope during password reset', { userId, error: envelopeError })
      throw new Error('Failed to complete password reset', { cause: envelopeError })
    }

    // Invalidate all existing sessions
    await sessionStore.del(REDIS_KEYS.REFRESH_TOKEN(userId))

    // Issue fresh token pair with the new credentialIdentifier
    const tokens: TokenPair = await createJwtTokenPair({
      user: {
        _id: userId,
        _cid: credentialIdentifier,
        email: user.email,
        username: user.username,
        role: user.role
      }
    })

    await this.storeRefreshToken(userId, tokens.refreshToken)

    logger.info('Password reset successfully', { userId, email: user.email, ip, userAgent })

    return {
      user: this.sanitizeUser(user),
      tokens,
      rememberMe: false
    }
  }

  /**
   * @deprecated OPAQUE migration pending — old bcrypt-based reset password.
   * Kept for reference only. See resetPasswordAlpha / resetPasswordBeta above.
   */
  // public resetPassword = async (token: string, newPassword: string): Promise<string> => { ... }

  /**
   * Verify Email
   *
   * Verifies user's email address using JWT verification token from email link.
   * Updates user's isEmailVerified flag and removes token from Redis.
   *
   * Process flow:
   * 1. Verifies JWT token signature and expiration
   * 2. Extracts userId from token payload
   * 3. Validates token matches stored token in Redis (if available)
   * 4. Updates user.isEmailVerified to true in database
   * 5. Deletes verification token from Redis
   *
   * @param token - JWT email verification token from verification link
   * @returns User ID of verified user
   * @throws Error "Invalid verification token" if JWT verification fails
   * @throws Error "Invalid verification token" if stored token doesn't match
   * @throws Error from repository if user not found or update fails
   * @remarks
   * - Token valid for 24 hours (TTL.VERIFICATION_TOKEN)
   * - Redis validation is optional - works with JWT-only if Redis unavailable
   * - Token deleted after use to prevent reuse
   * - Updates isEmailVerified flag via repository.verifyEmail
   * @public
   */
  public verifyEmail = async (token: string): Promise<string> => {
    const { userId } = await verifyEmailVerificationToken(token)

    const storedToken: string | null = await sessionStore.get(REDIS_KEYS.VERIFICATION_TOKEN(userId))
    if (storedToken && storedToken !== token) {
      throw new Error('Invalid verification token')
    }

    await this.userRepository.verifyEmail(userId)
    await sessionStore.del(REDIS_KEYS.VERIFICATION_TOKEN(userId))

    logger.info('Email verified successfully', { userId })

    return userId
  }

  /**
   * Change Password Alpha - Initiate OPAQUE Password Change
   *
   * Starts password change using OPAQUE protocol phase 1. Retrieves user's
   * OPAQUE envelope, generates KE2 for old password verification, creates
   * registration response for new password, and stores server state.
   *
   * Process flow:
   * 1. Validates user exists and is active
   * 2. Retrieves OPAQUE envelope from database
   * 3. Reconstructs RegistrationRecord from database fields
   * 4. Generates KE2 using OPAQUE protocol (old password verification)
   * 5. Creates registration response for new password
   * 6. Stores server state in Redis with change password context
   * 7. Returns KE2, registration response, and credential identifier
   *
   * @param userId - User ID from authenticated session
   * @param credentialIdentifier - User's current credential identifier
   * @param oldPasswordKE1 - KE1 message for old password authentication
   * @param newPasswordRegistrationRequest - Registration request for new password
   * @param serverKeyPair - Server's OPAQUE key pair
   * @param oprfSeed - OPRF seed for deterministic operations
   * @param opaque - ZeroAccess instance for OPAQUE operations
   * @returns Object containing KE2, registration response, and credential identifier
   * @throws Error "User not found" if userId doesn't exist
   * @throws Error "Account is deactivated" if user.isActive is false
   * @throws Error "Invalid credentials" if OPAQUE envelope not found
   * @remarks
   * - Server state stored in Redis with 5-minute expiration
   * - State includes both old password verification and new password data
   * - Credential identifier returned as base64 for client use
   * @public
   */
  public changePasswordAlpha = async (
    userId: string,
    credentialIdentifier: Uint8Array,
    oldPasswordKE1: KE1,
    newPasswordRegistrationRequest: RegistrationRequest,
    serverKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array },
    oprfSeed: Uint8Array,
    opaque: ZeroAccess
  ): Promise<{
    ke2: KE2
    registrationResponse: RegistrationResponse
    credentialIdentifier: string
  }> => {
    const user: User | null = await this.userRepository.findById(userId)
    if (!user) {
      throw new Error('User not found')
    }

    if (!user.isActive) {
      throw new Error('Account is deactivated')
    }

    const envelope: OpaqueEnvelope | null = await this.opaqueEnvelopesRepository.findByCredentialIdentifier(uint8ArrayToBuffer(credentialIdentifier))

    if (!envelope) {
      throw new Error('Invalid credentials')
    }

    // Reconstruct registration record for old password verification
    const record: RegistrationRecord = {
      clientPublicKey: new Uint8Array(envelope.clientPublicKey),
      maskingKey: new Uint8Array(envelope.maskingKey),
      envelope: {
        nonce: new Uint8Array(envelope.nonce),
        authTag: new Uint8Array(envelope.authTag),
        seed: new Uint8Array(envelope.seed)
      }
    }

    // Generate KE2 for old password authentication
    const { ke2, state }: { ke2: KE2; state: ServerState } = opaque.generateKE2(
      undefined,
      serverKeyPair.privateKey,
      serverKeyPair.publicKey,
      record,
      credentialIdentifier,
      oprfSeed,
      oldPasswordKE1,
      undefined
    )

    // Create registration response for new password
    const registrationResponse: RegistrationResponse = opaque.createRegistrationResponse(newPasswordRegistrationRequest, serverKeyPair.publicKey, credentialIdentifier, oprfSeed)
    const credId: string = uint8ArrayToBuffer(credentialIdentifier).toString('base64')

    // Store state with both old and new password context
    await this.storeOpaqueState(credId, {
      userId,
      expectedClientMac: uint8ArrayToBuffer(state.expectedClientMac).toString('base64'),
      sessionKey: uint8ArrayToBuffer(state.sessionKey).toString('base64'),
      rememberMe: false,
      timestamp: Date.now()
    })

    logger.info('Password change initialized', {
      userId,
      credentialIdentifier: credId
    })

    return {
      ke2,
      registrationResponse,
      credentialIdentifier: credId
    }
  }

  /**
   * Change Password Beta - Complete OPAQUE Password Change
   *
   * Finalizes password change by verifying old password (KE3 MAC), updating
   * OPAQUE envelope with new password data, and issuing new JWT tokens.
   * This is phase 2 of the OPAQUE password change protocol.
   *
   * Process flow:
   * 1. Retrieves server state from Redis
   * 2. Verifies KE3 MAC matches expectedClientMac (old password authentication)
   * 3. Deletes server state from Redis (prevent replay)
   * 4. Validates user exists and is active
   * 5. Updates OPAQUE envelope with new registration record
   * 6. Invalidates all existing refresh tokens
   * 7. Generates new JWT access and refresh tokens
   * 8. Stores new refresh token in Redis
   *
   * @param userId - User ID from authenticated session
   * @param credentialIdentifier - Base64 credential identifier from alpha phase
   * @param ke3 - KE3 message for old password verification
   * @param newRecord - New registration record for new password
   * @param opaque - ZeroAccess instance for MAC verification
   * @param context - OPAQUE context string for protocol consistency
   * @param ip - Client IP address for audit logging
   * @param userAgent - Client user agent for audit logging
   * @returns Object containing sanitized user data and new JWT token pair
   * @throws Error "Password change session expired or not found" if state not in Redis
   * @throws Error "Invalid old password - MAC verification failed" if MAC mismatch
   * @throws Error "User not found" if userId doesn't exist
   * @throws Error "Account is deactivated" if user.isActive is false
   * @remarks
   * - Atomic operation: either all changes succeed or all fail
   * - All existing sessions invalidated for security
   * - Server state deleted immediately after retrieval
   * - New envelope replaces old envelope in database
   * - Client keypair seed reused to maintain identity continuity
   * @public
   */
  public changePasswordBeta = async (
    userId: string,
    credentialIdentifier: string,
    ke3: KE3,
    newRecord: RegistrationRecord,
    opaque: ZeroAccess,
    context: string,
    ip: string,
    userAgent: string
  ): Promise<ServiceSignInBetaResultDTO> => {
    // Retrieve and verify server state
    const state = await this.getOpaqueState(credentialIdentifier)
    if (!state) {
      throw new Error('Password change session expired or not found')
    }

    // Verify old password via MAC comparison
    const expectedClientMac: Uint8Array = base64ToUint8Array(state.expectedClientMac)
    const isValid: boolean = opaque.verifyKE3(ke3.clientMac, expectedClientMac)

    if (!isValid) {
      // Cleanup state on failure
      await this.deleteOpaqueState(credentialIdentifier)
      throw new Error('Invalid old password - MAC verification failed')
    }

    // Old password verified - cleanup state
    await this.deleteOpaqueState(credentialIdentifier)

    // Validate user
    const user: User | null = await this.userRepository.findById(userId)
    if (!user) {
      throw new Error('User not found')
    }

    if (!user.isActive) {
      throw new Error('Account is deactivated')
    }

    // Update OPAQUE envelope with new password data
    const credentialIdBuffer: Buffer = Buffer.from(credentialIdentifier, 'base64')
    const updatedEnvelopeData = {
      clientPublicKey: uint8ArrayToBuffer(newRecord.clientPublicKey),
      maskingKey: uint8ArrayToBuffer(newRecord.maskingKey),
      nonce: uint8ArrayToBuffer(newRecord.envelope.nonce),
      authTag: uint8ArrayToBuffer(newRecord.envelope.authTag),
      seed: uint8ArrayToBuffer(newRecord.envelope.seed),
      context,
      lastPasswordChange: new Date(),
      passwordChangeIp: ip,
      passwordChangeUserAgent: userAgent
    }
    const updatedEnvelope: OpaqueEnvelope | null = await this.opaqueEnvelopesRepository.updateByCredentialIdentifier(credentialIdBuffer, updatedEnvelopeData)

    if (!updatedEnvelope) {
      throw new Error('Failed to update password')
    }

    // Invalidate all existing refresh tokens for this user
    await sessionStore.del(REDIS_KEYS.REFRESH_TOKEN(userId))

    // Generate new JWT token pair
    const tokens: TokenPair = await createJwtTokenPair({
      user: {
        _id: userId,
        _cid: credentialIdentifier,
        email: user.email,
        username: user.username,
        role: user.role
      }
    })

    // Store new refresh token
    await this.storeRefreshToken(userId, tokens.refreshToken)

    logger.info('Password changed successfully', {
      userId,
      email: user.email,
      ip,
      userAgent
    })

    return {
      user: this.sanitizeUser(user),
      tokens,
      rememberMe: false
    }
  }

  /**
   * Get Profile
   *
   * Retrieves user profile data by user ID with sensitive fields removed.
   *
   * @param userId - User ID for database lookup
   * @returns Sanitized user profile data without internal fields
   * @throws Error "User not found" if userId doesn't exist
   * @remarks
   * - Used by GET /auth/profile endpoint
   * - Applies sanitizeUser to remove deletedAt and other sensitive fields
   * - Simple wrapper around repository findById with sanitization
   * @public
   */
  public getProfile = async (userId: string): Promise<ServiceUserProfileResultDTO> => {
    const user: User | null = await this.userRepository.findById(userId)

    if (!user) {
      throw new Error('User not found')
    }
    return this.sanitizeUser(user)
  }

  /**
   * Update Profile
   *
   * Updates user profile information with validated data from request.
   * Allows updating non-sensitive fields like username, displayName, bio, avatar, etc.
   *
   * @param userId - User ID for database update
   * @param data - Profile update data pre-validated by middleware
   * @returns Updated and sanitized user profile
   * @throws Error "User not found" if userId doesn't exist
   * @throws Error from repository if update fails (e.g., username conflict, validation error)
   * @remarks
   * - Validation performed by middleware before calling this method
   * - Only allows updating non-sensitive user fields
   * - Returns sanitized data without internal fields
   * - Repository handles unique constraint validation (username, etc.)
   * @public
   */
  public updateProfile = async (userId: string, data: UpdateProfileRequestDTO): Promise<ServiceUserProfileResultDTO> => {
    const user: User | null = await this.userRepository.update(userId, data)

    if (!user) {
      throw new Error('User not found')
    }
    logger.info('Profile updated successfully', { userId })
    return this.sanitizeUser(user)
  }

  /**
   * Resend Verification Email
   *
   * Generates and stores new email verification token for user.
   * Used when original verification email was not received or expired.
   *
   * Process flow:
   * 1. Validates user exists by userId
   * 2. Checks email is not already verified
   * 3. Generates new JWT verification token (24-hour expiration)
   * 4. Stores token in Redis (overwrites existing token)
   * 5. TODO: Sends verification email with new token
   *
   * @param userId - User ID for token generation
   * @throws Error "User not found" if userId doesn't exist
   * @throws Error "Email already verified" if user.isEmailVerified is true
   * @remarks
   * - Prevents spam by blocking resend for verified emails
   * - New token replaces any existing token in Redis
   * - Token stored with 24-hour expiration (86400 seconds)
   * - Email sending not yet implemented (marked TODO)
   * - Token should be sent via email link: /verify-email/:token
   * @public
   */
  public resendVerificationEmail = async (userId: string): Promise<void> => {
    const user: User | null = await this.userRepository.findById(userId)

    if (!user) {
      throw new Error('User not found')
    }
    if (user.isEmailVerified) {
      throw new Error('Email already verified')
    }

    const verificationToken: string = await generateEmailVerificationToken(userId, user.email)

    await sessionStore.set(REDIS_KEYS.VERIFICATION_TOKEN(userId), verificationToken, TTL.VERIFICATION_TOKEN)

    // TODO: Send verification email
    // await this.emailService.sendVerificationEmail(user.email, verificationToken)
    logger.info('Verification email resent', { userId })
  }

  /**
   * Sign Out
   *
   * Invalidates user session by blacklisting access token and removing refresh token.
   * Prevents token reuse by adding access token to Redis blacklist.
   *
   * Process flow:
   * 1. Decodes access token to extract expiration time
   * 2. Calculates remaining TTL until token expiration
   * 3. Adds access token to Redis blacklist with TTL
   * 4. Deletes refresh token from Redis
   *
   * @param userId - User ID for refresh token deletion
   * @param token - JWT access token to blacklist
   * @remarks
   * - Access token blacklisted with TTL matching its remaining lifetime
   * - TTL prevents unnecessary storage after token naturally expires
   * - If Redis unavailable, logs success but tokens not invalidated server-side
   * - Blacklisted tokens rejected by authentication middleware
   * - Refresh token deletion prevents token refresh after sign out
   * @public
   */
  public signOut = async (userId: string, token: string): Promise<void> => {
    const decoded: BaseTokenPayload | null = await decodeToken(token)
    let ttl: number = 3600

    if (decoded?.exp) {
      ttl = Math.max(decoded.exp - Math.floor(Date.now() / 1000), 0)
    }
    if (ttl > 0) {
      await sessionStore.set(`blacklist:${token}`, '1', ttl)
    }
    await sessionStore.del(REDIS_KEYS.REFRESH_TOKEN(userId))
    logger.info('User signed out successfully', { userId })
  }
}

export default AuthService
