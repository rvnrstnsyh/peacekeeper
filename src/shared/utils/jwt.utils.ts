import { importJWK, jwtVerify, SignJWT } from 'jose'

import type { JWTPayload, JWTVerifyResult } from 'jose'
import type { SigningKeyPair } from '@/shared/utils/key-manager.utils'
import type {
  AccessTokenPayload,
  BaseTokenPayload,
  EmailVerificationPayload,
  PasswordResetPayload,
  RefreshTokenPayload,
  TokenGenerationPayload,
  TokenPair,
  TokenUser
} from '@/shared/types/jwt.utils.types'

import { logger } from '@/configs/logger.configs'
import { env } from '@/configs/environment.configs'
import { KeyManager } from '@/shared/utils/key-manager.utils'

/**
 * KeyManager instance for signing and verification
 */
const keyManager: KeyManager = new KeyManager({ silent: true })

/**
 * Parse duration string to seconds
 * Supports formats like: '1h', '24h', '7d', '30d', '3600' (seconds)
 *
 * @param duration - Duration string (e.g., '1h', '7d')
 * @returns Duration in seconds
 */
function parseDuration(duration: string | number): number {
  if (typeof duration === 'number') {
    return duration
  }

  const match: RegExpMatchArray | null = duration.match(/^(\d+)([smhd])$/)
  if (!match) {
    // If no unit specified, assume seconds
    const seconds: number = parseInt(duration, 10)
    return isNaN(seconds) ? 3600 : seconds
  }

  const value: number = parseInt(match[1], 10)
  const unit: string = match[2]

  switch (unit) {
    case 's':
      return value
    case 'm':
      return value * 60
    case 'h':
      return value * 3600
    case 'd':
      return value * 86400
    default:
      return 3600
  }
}

/**
 * Generate access token using Ed25519 signing key
 *
 * @param payload - Token generation payload
 * @returns Signed JWT token string
 * @throws Error if token generation fails
 */
export async function generateAccessToken(payload: TokenGenerationPayload): Promise<string> {
  try {
    const signingKey: SigningKeyPair | null = await keyManager.getLatestSigningKey()

    if (!signingKey) {
      throw new Error('No signing key available')
    }

    // Import JWK as crypto key
    const privateKey: CryptoKey | Uint8Array = await importJWK(signingKey.sec, 'EdDSA')
    // Build token payload with index signature for JOSE compatibility
    const tokenPayload: Record<string, unknown> = {}

    // Add user object if provided
    if (payload.user) {
      const { _id, _cid, ...restUser }: TokenUser = payload.user
      tokenPayload._id = _id
      tokenPayload._cid = _cid
      tokenPayload.type = 'access'
      tokenPayload.user = restUser
    }

    const expiresIn: number = parseDuration(env.JWT_ACCESS_EXPIRES_IN)
    const token: string = await new SignJWT(tokenPayload)
      .setProtectedHeader({
        alg: 'EdDSA',
        kid: `v${signingKey.v}` // Key ID for version tracking
      })
      .setIssuedAt()
      .setIssuer(env.APP_NAME)
      .setAudience(env.APP_URL)
      .setExpirationTime(Math.floor(Date.now() / 1000) + expiresIn)
      .sign(privateKey)

    return token
  } catch (error: unknown) {
    logger.error('Error generating access token', { error })
    throw new Error('Failed to generate access token', { cause: error })
  }
}

/**
 * Generate refresh token using Ed25519 signing key
 *
 * @param payload - Token generation payload
 * @returns Signed refresh token string
 * @throws Error if token generation fails
 */
export async function generateRefreshToken(payload: TokenGenerationPayload): Promise<string> {
  try {
    const signingKey: SigningKeyPair | null = await keyManager.getLatestSigningKey()

    if (!signingKey) {
      throw new Error('No signing key available')
    }

    // Import JWK as crypto key
    const privateKey: CryptoKey | Uint8Array = await importJWK(signingKey.sec, 'EdDSA')
    // Build token payload with index signature for JOSE compatibility
    const tokenPayload: Record<string, unknown> = {}
    // Add user object if provided
    if (payload.user) {
      tokenPayload._id = payload.user._id
      tokenPayload._cid = payload.user._cid
    }
    tokenPayload.type = 'refresh'

    const expiresIn: number = parseDuration(env.JWT_REFRESH_EXPIRES_IN)
    const token: string = await new SignJWT(tokenPayload)
      .setProtectedHeader({
        alg: 'EdDSA',
        kid: `v${signingKey.v}`
      })
      .setIssuedAt()
      .setIssuer(env.APP_NAME)
      .setAudience(env.APP_URL)
      .setExpirationTime(Math.floor(Date.now() / 1000) + expiresIn)
      .sign(privateKey)

    return token
  } catch (error: unknown) {
    logger.error('Error generating refresh token', { error })
    throw new Error('Failed to generate refresh token', { cause: error })
  }
}

/**
 * Generate access and refresh token pair
 *
 * @param payload - Token generation payload
 * @returns Token pair with expiry time
 */
export async function createJwtTokenPair(payload: TokenGenerationPayload): Promise<TokenPair> {
  const accessToken: string = await generateAccessToken(payload)
  const refreshToken: string = await generateRefreshToken(payload)
  // Calculate expiry time in seconds
  const decoded: BaseTokenPayload | null = await decodeToken(accessToken)
  const expiresIn: number = decoded?.exp ? decoded.exp - Math.floor(Date.now() / 1000) : 3600

  return { accessToken, refreshToken, expiresIn }
}

/**
 * Extract key version from JWT header
 *
 * @param token - JWT token string
 * @returns Key version number or null
 */
function extractKeyVersion(token: string): number | null {
  try {
    const [headerB64]: Array<string> = token.split('.')

    if (!headerB64) return null

    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf-8'))
    const kid = header.kid as string | undefined

    if (!kid || !kid.startsWith('v')) return null

    const version: number = parseInt(kid.substring(1), 10)
    return isNaN(version) ? null : version
  } catch {
    return null
  }
}

/**
 * Type guard to check if payload is AccessTokenPayload
 */
function isAccessTokenPayload(payload: JWTPayload): payload is AccessTokenPayload {
  return typeof payload === 'object' && payload !== null && 'type' in payload && payload.type === 'access' && '_id' in payload && '_cid' in payload && typeof payload.user === 'object'
}

/**
 * Type guard to check if payload is RefreshTokenPayload
 */
function isRefreshTokenPayload(payload: JWTPayload): payload is RefreshTokenPayload {
  return typeof payload === 'object' && payload !== null && 'type' in payload && payload.type === 'refresh' && '_id' in payload && '_cid' in payload
}

/**
 * Type guard to check if payload is EmailVerificationPayload
 */
function isEmailVerificationPayload(payload: JWTPayload): payload is EmailVerificationPayload {
  return typeof payload === 'object' && payload !== null && 'type' in payload && payload.type === 'email_verification' && '_id' in payload && 'email' in payload
}

/**
 * Type guard to check if payload is PasswordResetPayload
 */
function isPasswordResetPayload(payload: JWTPayload): payload is PasswordResetPayload {
  return typeof payload === 'object' && payload !== null && 'type' in payload && payload.type === 'password_reset' && '_id' in payload && 'email' in payload
}

/**
 * Verify access token using Ed25519 public key
 * Automatically detects and uses the correct key version
 *
 * @param token - JWT token string
 * @returns Decoded access token payload
 * @throws Error if token is invalid or expired
 */
export async function verifyToken(token: string): Promise<AccessTokenPayload> {
  try {
    const keyVersion: number | null = extractKeyVersion(token)
    // Get the appropriate signing key
    const signingKey: SigningKeyPair | null = keyVersion !== null ? await keyManager.getSigningKeyByVersion(keyVersion) : await keyManager.getLatestSigningKey()

    if (!signingKey) {
      throw new Error('Signing key not found')
    }

    // Import JWK public key
    const publicKey: CryptoKey | Uint8Array = await importJWK(signingKey.pub, 'EdDSA')
    const result: JWTVerifyResult = await jwtVerify(token, publicKey, {
      issuer: env.APP_NAME,
      audience: env.APP_URL
    })
    const payload: JWTPayload = result.payload

    // Validate token type using type guard
    if (!isAccessTokenPayload(payload)) {
      throw new Error('Invalid token type')
    }

    return payload
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (error.message.includes('expired')) {
        throw new Error('Token has expired', { cause: error })
      }
      if (error.message.includes('signature')) {
        throw new Error('Invalid token signature', { cause: error })
      }
      throw new Error(error.message, { cause: error })
    }
    throw new Error('Token verification failed', { cause: error })
  }
}

/**
 * Verify refresh token using Ed25519 public key
 *
 * @param token - Refresh token string
 * @returns Decoded refresh token payload
 * @throws Error if token is invalid or expired
 */
export async function verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
  try {
    const keyVersion: number | null = extractKeyVersion(token)
    const signingKey: SigningKeyPair | null = keyVersion !== null ? await keyManager.getSigningKeyByVersion(keyVersion) : await keyManager.getLatestSigningKey()

    if (!signingKey) {
      throw new Error('Signing key not found')
    }

    const publicKey: CryptoKey | Uint8Array = await importJWK(signingKey.pub, 'EdDSA')
    const result: JWTVerifyResult = await jwtVerify(token, publicKey, {
      issuer: env.APP_NAME,
      audience: env.APP_URL
    })
    const payload: JWTPayload = result.payload

    // Validate token type using type guard
    if (!isRefreshTokenPayload(payload)) {
      throw new Error('Invalid token type')
    }
    return payload
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (error.message.includes('expired')) {
        throw new Error('Refresh token has expired', { cause: error })
      }
      if (error.message.includes('signature')) {
        throw new Error('Invalid refresh token signature', { cause: error })
      }
      throw new Error(error.message, { cause: error })
    }
    throw new Error('Refresh token verification failed', { cause: error })
  }
}

/**
 * Decode token without verification
 *
 * @param token - JWT token string
 * @returns Decoded payload or null if decoding fails
 */
export async function decodeToken(token: string): Promise<BaseTokenPayload | null> {
  try {
    const [, payloadB64]: Array<string> = token.split('.')

    if (!payloadB64) return null

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'))
    return payload as BaseTokenPayload
  } catch (error: unknown) {
    logger.error('Error decoding token', { error })
    return null
  }
}

/**
 * Get token expiry date
 *
 * @param token - JWT token string
 * @returns Expiry date or null if not found
 */
export async function getTokenExpiry(token: string): Promise<Date | null> {
  try {
    const decoded: BaseTokenPayload | null = await decodeToken(token)
    if (decoded?.exp) {
      return new Date(decoded.exp * 1000)
    }
    return null
  } catch (error: unknown) {
    logger.error('Error getting token expiry', { error })
    return null
  }
}

/**
 * Check if token is expired
 *
 * @param token - JWT token string
 * @returns True if token is expired
 */
export async function isTokenExpired(token: string): Promise<boolean> {
  const expiry: Date | null = await getTokenExpiry(token)
  if (!expiry) return true
  return expiry.getTime() < Date.now()
}

/**
 * Get remaining time before token expires
 *
 * @param token - JWT token string
 * @returns Remaining time in seconds
 */
export async function getTokenRemainingTime(token: string): Promise<number> {
  const expiry: Date | null = await getTokenExpiry(token)
  if (!expiry) return 0
  const remaining: number = Math.floor((expiry.getTime() - Date.now()) / 1000)
  return remaining > 0 ? remaining : 0
}

/**
 * Generate email verification token (24h expiry)
 *
 * @param userId - User ID
 * @param email - User email
 * @returns Signed verification token
 * @throws Error if token generation fails
 */
export async function generateEmailVerificationToken(userId: string, email: string): Promise<string> {
  try {
    const signingKey: SigningKeyPair | null = await keyManager.getLatestSigningKey()

    if (!signingKey) {
      throw new Error('No signing key available')
    }

    const privateKey: CryptoKey | Uint8Array = await importJWK(signingKey.sec, 'EdDSA')
    const tokenPayload: Record<string, unknown> = {
      userId,
      email,
      type: 'email_verification'
    }
    const token: string = await new SignJWT(tokenPayload)
      .setProtectedHeader({
        alg: 'EdDSA',
        kid: `v${signingKey.v}`
      })
      .setIssuedAt()
      .setIssuer(env.APP_NAME)
      .setExpirationTime('24h')
      .sign(privateKey)

    return token
  } catch (error: unknown) {
    logger.error('Error generating email verification token', { error })
    throw new Error('Failed to generate email verification token', { cause: error })
  }
}

/**
 * Verify email verification token
 *
 * @param token - Verification token string
 * @returns User ID and email
 * @throws Error if token is invalid or expired
 */
export async function verifyEmailVerificationToken(token: string): Promise<{ userId: string; email: string }> {
  try {
    const keyVersion: number | null = extractKeyVersion(token)
    const signingKey: SigningKeyPair | null = keyVersion !== null ? await keyManager.getSigningKeyByVersion(keyVersion) : await keyManager.getLatestSigningKey()

    if (!signingKey) {
      throw new Error('Signing key not found')
    }

    const publicKey: CryptoKey | Uint8Array = await importJWK(signingKey.pub, 'EdDSA')
    const result: JWTVerifyResult = await jwtVerify(token, publicKey, {
      issuer: env.APP_NAME
    })
    const payload: JWTPayload = result.payload

    // Validate token type using type guard
    if (!isEmailVerificationPayload(payload)) {
      throw new Error('Invalid token type')
    }
    return {
      userId: payload._id,
      email: payload.email
    }
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (error.message.includes('expired')) {
        throw new Error('Verification token has expired', { cause: error })
      }
      throw new Error(error.message, { cause: error })
    }
    throw new Error('Token verification failed', { cause: error })
  }
}

/**
 * Generate password reset token (1h expiry)
 *
 * @param userId - User ID
 * @param email - User email
 * @returns Signed reset token
 * @throws Error if token generation fails
 */
export async function generatePasswordResetToken(userId: string, email: string): Promise<string> {
  try {
    const signingKey: SigningKeyPair | null = await keyManager.getLatestSigningKey()

    if (!signingKey) {
      throw new Error('No signing key available')
    }

    const privateKey: CryptoKey | Uint8Array = await importJWK(signingKey.sec, 'EdDSA')
    const tokenPayload: Record<string, unknown> = {
      userId,
      email,
      type: 'password_reset'
    }
    const token: string = await new SignJWT(tokenPayload)
      .setProtectedHeader({
        alg: 'EdDSA',
        kid: `v${signingKey.v}`
      })
      .setIssuedAt()
      .setIssuer(env.APP_NAME)
      .setExpirationTime('1h')
      .sign(privateKey)

    return token
  } catch (error: unknown) {
    logger.error('Error generating password reset token', { error })
    throw new Error('Failed to generate password reset token', { cause: error })
  }
}

/**
 * Verify password reset token
 *
 * @param token - Reset token string
 * @returns User ID and email
 * @throws Error if token is invalid or expired
 */
export async function verifyPasswordResetToken(token: string): Promise<{ userId: string; email: string }> {
  try {
    const keyVersion: number | null = extractKeyVersion(token)
    const signingKey: SigningKeyPair | null = keyVersion !== null ? await keyManager.getSigningKeyByVersion(keyVersion) : await keyManager.getLatestSigningKey()

    if (!signingKey) {
      throw new Error('Signing key not found')
    }

    const publicKey: CryptoKey | Uint8Array = await importJWK(signingKey.pub, 'EdDSA')
    const result: JWTVerifyResult = await jwtVerify(token, publicKey, {
      issuer: env.APP_NAME
    })
    const payload: JWTPayload = result.payload

    // Validate token type using type guard
    if (!isPasswordResetPayload(payload)) {
      throw new Error('Invalid token type')
    }
    return {
      userId: payload.userId,
      email: payload.email
    }
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (error.message.includes('expired')) {
        throw new Error('Reset token has expired', { cause: error })
      }
      throw new Error(error.message, { cause: error })
    }
    throw new Error('Token verification failed', { cause: error })
  }
}
