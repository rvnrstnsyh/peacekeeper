/**
 * JWT Token Payload Types
 * Defines the structure of different token types used in the application
 * Compatible with JOSE library (requires index signature)
 */

/**
 * Base token payload containing common fields for all token types
 * Index signature required for JOSE compatibility
 */
export interface BaseTokenPayload {
  /** User ID (UUID or string) */
  _id: string
  /** Credential identifier */
  _cid: string
  /** User email address */
  email: string
  /** User role (admin, user, etc.) */
  role: string
  /** Issued at timestamp (seconds since epoch) */
  iat?: number
  /** Expiration timestamp (seconds since epoch) */
  exp?: number
  /** Token issuer */
  iss?: string
  /** Token audience */
  aud?: string
  /** Index signature for JOSE compatibility */
  [key: string]: unknown
}

/**
 * User object embedded in access tokens
 */
export interface TokenUser {
  /** User email address */
  email: string
  /** User role */
  role: string
  /** User first name */
  firstName?: string
  /** User last name */
  lastName?: string
  /** Index signature for JOSE compatibility */
  [key: string]: unknown
}

/**
 * Access token payload
 * Used for API authentication and authorization
 */
export interface AccessTokenPayload extends BaseTokenPayload {
  /** Token type identifier */
  type: 'access'
  /** Full user object (optional, for avoiding additional DB queries) */
  user: TokenUser
}

/**
 * Refresh token payload
 * Used for obtaining new access tokens without re-authentication
 */
export interface RefreshTokenPayload extends BaseTokenPayload {
  /** Token type identifier */
  type: 'refresh'
}

/**
 * Email verification token payload
 * Used for verifying user email addresses
 */
export interface EmailVerificationPayload {
  /** User ID */
  _id: string
  /** User email address to verify */
  email: string
  /** Token type identifier */
  type: 'email_verification'
  /** Issued at timestamp (seconds since epoch) */
  iat?: number
  /** Expiration timestamp (seconds since epoch) */
  exp?: number
  /** Token issuer */
  iss?: string
  /** Token audience */
  aud?: string
  /** Index signature for JOSE compatibility */
  [key: string]: unknown
}

/**
 * Password reset token payload
 * Used for password reset flows
 */
export interface PasswordResetPayload {
  /** User ID */
  userId: string
  /** User email address */
  email: string
  /** Token type identifier */
  type: 'password_reset'
  /** Issued at timestamp (seconds since epoch) */
  iat?: number
  /** Expiration timestamp (seconds since epoch) */
  exp?: number
  /** Token issuer */
  iss?: string
  /** Token audience */
  aud?: string
  /** Index signature for JOSE compatibility */
  [key: string]: unknown
}

/**
 * Union type of all possible token payloads
 */
export type TokenPayload = AccessTokenPayload | RefreshTokenPayload | EmailVerificationPayload | PasswordResetPayload

/**
 * Token Generation Options
 */

/**
 * Payload data for generating access and refresh tokens
 */
export interface TokenGenerationPayload {
  /** Full user object to embed in access token */
  user?: TokenUser
}

/**
 * Token Pair Response
 */

/**
 * Response containing both access and refresh tokens
 */
export interface TokenPair {
  /** JWT access token */
  accessToken: string
  /** JWT refresh token */
  refreshToken: string
  /** Access token expiration time in seconds */
  expiresIn: number
}

/**
 * JWT Options Types
 * These are kept for backward compatibility but JOSE uses different options
 */

/**
 * JWT sign options (JOSE compatible)
 */
export interface JWTSignOptions {
  /** Token expiration (e.g., '7d', '1h', 3600) */
  expiresIn: string | number
  /** Token issuer (typically your application name) */
  issuer?: string
  /** Token audience (typically your API URL) */
  audience?: string
  /** Token subject (typically user ID) */
  subject?: string
  /** Not valid before (delay token validity) */
  notBefore?: string | number
  /** Unique token ID */
  jwtid?: string
}

/**
 * JWT verify options (JOSE compatible)
 */
export interface JWTVerifyOptions {
  /** Expected token issuer */
  issuer?: string
  /** Expected token audience */
  audience?: string | Array<string>
  /** Expected token subject */
  subject?: string
  /** Clock tolerance in seconds for time validation */
  clockTolerance?: number
  /** Maximum token age */
  maxAge?: string | number
  /** Current time (for testing) */
  currentDate?: Date
  /** Expected token type */
  typ?: string
}

/**
 * Decoded JWT header
 */
export interface JWTHeader {
  /** Algorithm (EdDSA for Ed25519) */
  alg: string
  /** Key ID (version identifier) */
  kid?: string
  /** Token type */
  typ?: string
}

/**
 * JWT verification result
 */
export interface JWTVerifyResult<T = TokenPayload> {
  /** Decoded payload */
  payload: T
  /** Protected header */
  protectedHeader: JWTHeader
}
