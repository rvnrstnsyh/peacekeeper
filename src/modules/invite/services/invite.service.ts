import type { Invitation } from '@/modules/invite/models/invitations.model'
import type { CreateInvitationRequestDTO, InvitationDTO, CreateInvitationResponseDTO, ListInvitationsResponseDTO, InvitationPublicInfoDTO } from '@/modules/invite/dto/invite.dto'

import { randomBytes } from '@noble/hashes/utils.js'
import { logger } from '@/configs/logger.configs'
import { UserRepository } from '@/modules/auth/repositories/user.repository'
import { InvitationRepository } from '@/modules/invite/repositories/invite.repository'

/** Minimum account age (in days) before a user may generate invite codes */
const INVITE_MIN_ACCOUNT_AGE_DAYS = 30

/**
 * Derive whether an invitation is still redeemable
 */
function isInvitationActive(invitation: Invitation): boolean {
  if (invitation.revokedAt) return false
  if (invitation.expiresAt && invitation.expiresAt <= new Date()) return false
  if (invitation.maxUses !== null && invitation.usedCount >= invitation.maxUses) return false
  return true
}

/**
 * Map a DB row to the public-facing DTO
 */
function toInvitationDTO(invitation: Invitation): InvitationDTO {
  return {
    id: invitation._id,
    code: invitation.code,
    maxUses: invitation.maxUses,
    usedCount: invitation.usedCount,
    expiresAt: invitation.expiresAt?.toISOString() ?? null,
    revokedAt: invitation.revokedAt?.toISOString() ?? null,
    createdAt: invitation.createdAt.toISOString(),
    isActive: isInvitationActive(invitation)
  }
}

/**
 * Generate a unique 10-character alphanumeric uppercase invite code
 */
function generateCode(): string {
  return Buffer.from(randomBytes(5)).toString('hex').toUpperCase()
}

/**
 * InviteService
 *
 * Manages the full lifecycle of user-generated invitation codes:
 * create, list, revoke, and redeem.
 *
 * Policy constraints:
 * - Account must be at least 30 days old to generate codes
 * - Codes expire only when the creator sets an expiry or max-use limit
 * - Redemption is atomic (SQL increment) to prevent race conditions
 */
export class InviteService {
  private invitationRepository: InvitationRepository
  private userRepository: UserRepository

  constructor() {
    this.invitationRepository = new InvitationRepository()
    this.userRepository = new UserRepository()
  }

  /**
   * Create a new invitation code for the given user.
   *
   * @throws {Error} 'Account must be at least 30 days old to create invitation codes'
   * @throws {Error} 'User not found'
   */
  async createInvitation(userId: string, data: CreateInvitationRequestDTO): Promise<CreateInvitationResponseDTO> {
    const user = await this.userRepository.findById(userId)
    if (!user) {
      throw new Error('User not found')
    }

    const accountAgeMs = Date.now() - user.createdAt.getTime()
    const accountAgeDays = accountAgeMs / (1000 * 60 * 60 * 24)

    if (accountAgeDays < INVITE_MIN_ACCOUNT_AGE_DAYS) {
      const daysRemaining = Math.ceil(INVITE_MIN_ACCOUNT_AGE_DAYS - accountAgeDays)
      throw new Error(`Account must be at least ${INVITE_MIN_ACCOUNT_AGE_DAYS} days old to create invitation codes. ${daysRemaining} day(s) remaining.`)
    }

    // Generate a unique code (retry up to 3 times on collision)
    let code: string | null = null
    for (let attempt = 0; attempt < 3; attempt++) {
      const candidate = generateCode()
      const existing = await this.invitationRepository.findByCode(candidate)
      if (!existing) {
        code = candidate
        break
      }
    }

    if (!code) {
      logger.error('Failed to generate a unique invite code after retries', { userId })
      throw new Error('Failed to generate a unique invitation code. Please try again.')
    }

    const expiresAt = data.expiresIn ? new Date(Date.now() + data.expiresIn * 1000) : null

    const invitation = await this.invitationRepository.create({
      code,
      creatorId: userId,
      maxUses: data.maxUses ?? null,
      usedCount: 0,
      expiresAt,
      revokedAt: null
    })

    logger.info('Invitation code created', { userId, code, maxUses: data.maxUses, expiresAt })

    return { invitation: toInvitationDTO(invitation) }
  }

  /**
   * List all invitations created by the authenticated user
   */
  async listInvitations(userId: string): Promise<ListInvitationsResponseDTO> {
    const [rows, total, user] = await Promise.all([this.invitationRepository.findByCreatorId(userId), this.invitationRepository.countByCreatorId(userId), this.userRepository.findById(userId)])

    const accountAgeDays = user ? (Date.now() - user.createdAt.getTime()) / (1000 * 60 * 60 * 24) : Infinity
    const canCreate = accountAgeDays >= INVITE_MIN_ACCOUNT_AGE_DAYS
    const daysUntilEligible = canCreate ? null : Math.ceil(INVITE_MIN_ACCOUNT_AGE_DAYS - accountAgeDays)

    return {
      invitations: rows.map(toInvitationDTO),
      total,
      canCreate,
      daysUntilEligible
    }
  }

  /**
   * Revoke an invitation code owned by the authenticated user.
   *
   * @throws {Error} 'Invitation not found or already revoked'
   */
  async revokeInvitation(code: string, userId: string): Promise<InvitationDTO> {
    const updated = await this.invitationRepository.revoke(code, userId)
    if (!updated) {
      throw new Error('Invitation not found or already revoked')
    }
    logger.info('Invitation code revoked', { userId, code })
    return toInvitationDTO(updated)
  }

  /**
   * Return public information about a code (used by sign-up UI to show
   * the creator's intent without leaking sensitive data).
   *
   * @throws {Error} 'Invitation not found'
   */
  async getPublicInfo(code: string): Promise<InvitationPublicInfoDTO> {
    const invitation = await this.invitationRepository.findByCode(code)
    if (!invitation) {
      throw new Error('Invitation not found')
    }

    return {
      code: invitation.code,
      isValid: isInvitationActive(invitation),
      usedCount: invitation.usedCount,
      maxUses: invitation.maxUses,
      expiresAt: invitation.expiresAt?.toISOString() ?? null
    }
  }

  /**
   * Validate and redeem an invitation code during user registration.
   * If the code is invalid or exhausted the error is thrown so the
   * caller can decide whether to surface it.
   *
   * @throws {Error} 'Invitation not found'
   * @throws {Error} 'Invitation code is no longer valid'
   */
  async redeemInvitation(code: string): Promise<void> {
    const invitation = await this.invitationRepository.findByCode(code)

    if (!invitation) {
      throw new Error('Invitation not found')
    }

    if (!isInvitationActive(invitation)) {
      throw new Error('Invitation code is no longer valid')
    }

    // Atomic update — returns null if validity conditions were no longer met at
    // the moment the SQL executed (concurrent redemption won the race)
    const result = await this.invitationRepository.redeemCode(code)

    if (!result) {
      throw new Error('Invitation code is no longer valid')
    }

    logger.info('Invitation redeemed', { code })
  }

  /**
   * Validate an invitation code without redeeming it.
   * Used to perform a pre-creation check before a new user is registered,
   * so that invalid codes are rejected before any database writes occur.
   *
   * @throws {Error} 'Invitation not found'
   * @throws {Error} 'Invitation code is no longer valid'
   */
  async validateInvitation(code: string): Promise<void> {
    const invitation = await this.invitationRepository.findByCode(code)

    if (!invitation) {
      throw new Error('Invitation not found')
    }

    if (!isInvitationActive(invitation)) {
      throw new Error('Invitation code is no longer valid')
    }
  }
}
