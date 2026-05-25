// ============================================================================
// REQUEST DTOs
// ============================================================================

/**
 * Create Invitation request body
 */
export interface CreateInvitationRequestDTO {
  /**
   * Seconds from now until the code expires.
   * Omit for a code that never expires.
   * Range: 3600 (1 h) – 31 536 000 (365 days)
   */
  expiresIn?: number
  /**
   * Maximum number of times the code may be redeemed.
   * Omit for unlimited uses.
   * Range: 1 – 1000
   */
  maxUses?: number
}

// ============================================================================
// RESPONSE DTOs
// ============================================================================

/**
 * Single invitation as returned to the API consumer
 */
export interface InvitationDTO {
  id: string
  code: string
  maxUses: number | null
  usedCount: number
  expiresAt: string | null
  revokedAt: string | null
  createdAt: string
  /** Derived: true when code is still valid to redeem */
  isActive: boolean
}

/**
 * Response for POST /invite
 */
export interface CreateInvitationResponseDTO {
  invitation: InvitationDTO
}

/**
 * Response for GET /invite
 */
export interface ListInvitationsResponseDTO {
  invitations: Array<InvitationDTO>
  total: number
  /** Whether the authenticated user is eligible to create new invitation codes */
  canCreate: boolean
  /** Days remaining until eligible; null when already eligible */
  daysUntilEligible: number | null
}

/**
 * Response for GET /invite/:code (public endpoint)
 */
export interface InvitationPublicInfoDTO {
  code: string
  isValid: boolean
  usedCount: number
  maxUses: number | null
  expiresAt: string | null
}
