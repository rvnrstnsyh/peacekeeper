import type { KE1Serialized, KE2, KE2Serialized, KE3Serialized, RegistrationRecordSerialized } from '@/shared/types/zero-access.utils.types'

// ============================================================================
// REQUEST DTOs - Data Transfer Objects for incoming requests
// ============================================================================

/**
 * OPAQUE Registration - Step 1 (Alpha)
 * Client sends blinded password
 */
export interface SignUpAlphaRequestDTO {
  request: {
    blindedMessage: string
  }
}

/**
 * OPAQUE Registration - Step 2 (Beta)
 * Client sends RegistrationRecord (NO PASSWORD)
 *
 * CRITICAL: password field is REMOVED
 * Password never reaches the server in OPAQUE protocol
 */
export interface SignUpBetaRequestDTO {
  credentialIdentifier: string
  record: RegistrationRecordSerialized
  email: string
  username: string
  firstName?: string
  lastName?: string
  phone?: string
  dateOfBirth?: string
  gender?: 'male' | 'female'
  address?: string
  /** Optional invitation code provided during sign-up */
  inviteCode?: string
}

/**
 * Sign in alpha request
 */
export interface SignInAlphaRequestDTO {
  email: string
  ke1: KE1Serialized
  rememberMe: boolean
}

/**
 * Sign in beta request
 */
export interface SignInBetaRequestDTO {
  credentialIdentifier: string
  ke3: KE3Serialized
}

/**
 * Refresh Token request
 */
export interface RefreshTokenRequestDTO {
  '__Secure-Refresh-Token': string
}

/**
 * Change Password Alpha Request DTO
 *
 * Request body for initiating password change (Phase 1).
 * Contains old password authentication data (KE1) and new password
 * registration request.
 */
export interface ChangePasswordAlphaRequestDTO {
  request: {
    /** KE1 message for old password authentication */
    oldPasswordKE1: KE1Serialized
    /** Registration request for new password */
    newPasswordRegistrationRequest: {
      /** Base64-encoded blinded message (32 bytes) */
      blindedMessage: string
    }
  }
}

/**
 * Change Password Beta Request DTO
 *
 * Request body for completing password change (Phase 2).
 * Contains KE3 for old password verification and new registration record.
 */
export interface ChangePasswordBetaRequestDTO {
  /** Base64-encoded credential identifier from alpha phase */
  credentialIdentifier: string
  /** KE3 message for old password verification */
  ke3: KE3Serialized
  /** New registration record for new password */
  newRecord: RegistrationRecordSerialized
}

/**
 * Forgot Password request
 */
export interface ForgotPasswordRequestDTO {
  email: string
}

/**
 * Reset Password Alpha Request DTO
 *
 * Request body for initiating password reset (Phase 1).
 * User provides their reset token (received via email) and a blinded
 * message to start the OPAQUE re-registration flow.
 * The server generates a fresh credential identifier and OPRF response.
 */
export interface ResetPasswordAlphaRequestDTO {
  /** JWT reset token issued by forgotPassword endpoint */
  resetToken: string
  /** OPAQUE registration request containing blinded message */
  request: {
    /** Base64-encoded blinded message (32 bytes) */
    blindedMessage: string
  }
}

/**
 * Reset Password Alpha Response DTO
 *
 * Server response for password reset initiation (Phase 1).
 * Mirrors SignUpAlphaResponseDTO — client uses this to complete
 * the OPAQUE registration of the new password.
 */
export interface ResetPasswordAlphaResponseDTO {
  /** Base64-encoded new credential identifier (32 bytes) */
  credentialIdentifier: string
  /** Base64-encoded OPRF-evaluated element (32 bytes) */
  evaluatedMessage: string
  /** Base64-encoded server public key (32 bytes) */
  serverX25519PublicKey: string
}

/**
 * Reset Password Beta Request DTO
 *
 * Request body for completing password reset (Phase 2).
 * Client sends the new OPAQUE registration record after completing
 * client-side OPAQUE registration with the alpha response.
 * Keypair is fully regenerated — equivalent to a fresh sign-up.
 */
export interface ResetPasswordBetaRequestDTO {
  /** Base64-encoded credential identifier from alpha phase */
  credentialIdentifier: string
  /** New OPAQUE registration record for the new password */
  record: RegistrationRecordSerialized
}

/**
 * Update Profile request
 */
export interface UpdateProfileRequestDTO {
  username?: string
  firstName?: string
  lastName?: string
  phone?: string
  dateOfBirth?: string
  gender?: 'male' | 'female' | null
  address?: string
  avatar?: string | null
}

/**
 * Resend Verification Email request
 * No body needed - user ID comes from authenticated session context
 */
export type ResendVerificationRequestDTO = Record<never, never>

// ============================================================================
// RESPONSE DTOs - Data Transfer Objects for outgoing responses
// ============================================================================

/**
 * User Response DTO (without sensitive data)
 */
export interface ServiceUserProfileResultDTO {
  _id: string
  email: string
  username: string
  firstName: string
  lastName: string
  phone?: string
  role: string
  dateOfBirth?: string
  gender?: string
  address?: string
  avatar?: string
  isEmailVerified: boolean
  isActive: boolean
  usernameChangedAt?: Date | null
  createdAt: Date
  updatedAt: Date
}

/**
 * Auth Tokens DTO
 */
export interface AuthTokensDTO {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

/**
 * Sign Up Alpha Response
 */
export interface SignUpAlphaResponseDTO {
  credentialIdentifier: string
  evaluatedMessage: string // base64 encoded
  serverX25519PublicKey: string // base64 encoded
}

/**
 * Sign Up Beta Response
 */
export interface SignUpBetaResponseDTO {
  user: ServiceUserProfileResultDTO
  message?: string
}

/**
 * Sign In Alpha Response
 */
export interface SignInAlphaResponseDTO {
  credentialIdentifier: string
  ke2: KE2Serialized // serialized KE2
}

/**
 * Sign In Beta Response
 */
export interface SignInBetaResponseDTO {
  user: ServiceUserProfileResultDTO
  accessToken: string
  expiresIn: number
  clientED25519PublicKey: string
  clientX25519PublicKey: string
}

/**
 * Security Keys Alpha Request DTO
 *
 * Request body for initiating security keys retrieval (Phase 1).
 * Identical to sign-in alpha but serves as a dedicated endpoint
 * for authenticated access to the user's cryptographic identity.
 */
export interface SecurityKeysAlphaRequestDTO {
  email: string
  ke1: KE1Serialized
}

/**
 * Security Keys Beta Request DTO
 *
 * Request body for completing security keys retrieval (Phase 2).
 * Verifies the KE3 MAC and returns the user's OPAQUE client public key.
 */
export interface SecurityKeysBetaRequestDTO {
  credentialIdentifier: string
  ke3: KE3Serialized
}

/**
 * Security Keys Beta Response DTO
 *
 * Response confirming successful password verification.
 * Contains the user's OPAQUE client public key (base64).
 */
export interface SecurityKeysBetaResponseDTO {
  clientED25519PublicKey: string
  clientX25519PublicKey: string
}

/**
 * Refresh Token Response
 */
export interface RefreshTokenResponseDTO {
  accessToken: string
  expiresIn: number
}

/**
 * Change Password Alpha Response DTO
 *
 * Response for password change initialization (Phase 1).
 * Contains KE2 for old password verification and registration response
 * for new password.
 */
export interface ChangePasswordAlphaResponseDTO {
  /** Base64-encoded credential identifier for phase 2 */
  credentialIdentifier: string
  /** KE2 message for old password authentication */
  oldPasswordKE2: {
    /** Base64-encoded OPRF-evaluated element (32 bytes) */
    evaluatedMessage: string
    /** Base64-encoded masking nonce (32 bytes) */
    maskingNonce: string
    /** Base64-encoded masked response (variable length) */
    maskedResponse: string
    /** Base64-encoded server nonce (32 bytes) */
    serverNonce: string
    /** Base64-encoded server ephemeral public key (32 bytes) */
    serverX25519PublicKeyshare: string
    /** Base64-encoded server MAC (64 bytes) */
    serverMac: string
  }
  /** Registration response for new password */
  newPasswordRegistrationResponse: {
    /** Base64-encoded OPRF-evaluated message (32 bytes) */
    evaluatedMessage: string
    /** Base64-encoded server public key (32 bytes) */
    serverX25519PublicKey: string
  }
}

/**
 * Change Password Beta Response DTO
 *
 * Response for password change completion (Phase 2).
 * Contains user data and new JWT tokens after successful password change.
 */
export interface ChangePasswordBetaResponseDTO {
  /** Sanitized user profile data */
  user: ServiceUserProfileResultDTO
  /** New JWT access token */
  accessToken: string
  /** Token expiration time in seconds */
  expiresIn: number
}

/**
 * Sign Out Response
 */
export interface SignOutResponseDTO {
  message: string
}

/**
 * Get Profile Response
 */
export interface GetProfileResponseDTO {
  user: ServiceUserProfileResultDTO
}

/**
 * Update Profile Response
 */
export interface UpdateProfileResponseDTO {
  user: ServiceUserProfileResultDTO
}

/**
 * Forgot Password Response
 */
export interface ForgotPasswordResponseDTO {
  message: string
}

/**
 * Reset Password Response
 */
export interface ResetPasswordResponseDTO {
  message: string
}

/**
 * Verify Email Response
 */
export interface VerifyEmailResponseDTO {
  message: string
}

/**
 * Resend Verification Response
 */
export interface ResendVerificationResponseDTO {
  message: string
}

// ============================================================================
// SESSION MANAGEMENT DTOs
// ============================================================================

/**
 * Single session info returned by GET /sessions
 */
export interface SessionDTO {
  /** DB primary key (UUID) — used as the identifier for revoke requests */
  _id: string
  /** Client IP at login time */
  ip?: string | null
  /** Raw User-Agent at login time */
  userAgent?: string | null
  /** Whether the session was created with "remember me" */
  isRememberMe: boolean
  /** When the session was created */
  createdAt: Date
  /** When a token refresh last occurred (null on first login) */
  lastSeenAt?: Date | null
  /** When the refresh token (and thus the session) expires */
  expiresAt: Date
  /** True when this entry matches the caller's current session */
  isCurrent: boolean
}

/**
 * GET /sessions response
 */
export interface GetSessionsResponseDTO {
  sessions: Array<SessionDTO>
}

/**
 * Result returned by revokeSession service — indicates whether the caller
 * signed themselves out so the controller can clear the cookie.
 */
export interface RevokeSessionResultDTO {
  isSelf: boolean
}

// ============================================================================
// SERVICE DTOs - Internal data structures for service layer
// ============================================================================

/**
 * Internal DTO for service layer - complete tokens with refresh token
 */
export interface ServiceAuthTokensDTO {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

/**
 * Internal DTO for service layer - sign in alpha result
 */
export interface ServiceSignInAlphaResultDTO {
  ke2: KE2
  credentialIdentifier: string
}

/**
 * Internal DTO for service layer - sign in beta result
 */
export interface ServiceSignInBetaResultDTO {
  user: ServiceUserProfileResultDTO
  tokens: ServiceAuthTokensDTO
  rememberMe: boolean
  clientED25519PublicKey?: string
  clientX25519PublicKey?: string
}

/**
 * Internal DTO for service layer - reset password beta result
 * Does NOT include tokens — user must sign in manually after reset.
 */
export interface ServiceResetPasswordBetaResultDTO {
  userId: string
}

/**
 * Internal DTO for service layer - refresh token result
 */
export interface ServiceRefreshTokenResultDTO {
  userId: string
  tokens: ServiceAuthTokensDTO
}

/**
 * Internal DTO for service layer - sign up result
 */
export interface ServiceSignUpBetaResultDTO {
  user: ServiceUserProfileResultDTO
}
