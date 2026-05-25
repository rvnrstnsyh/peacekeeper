// ============================================================================
// REQUEST DTOs
// ============================================================================

export interface CreateApiKeyRequestDTO {
  /** User-friendly label, e.g. "Production Server" */
  name: string
  /**
   * Seconds from now until the key expires.
   * Omit for a key that never expires.
   * Range: 3600 (1 h) – 31 536 000 (365 days)
   */
  expiresIn?: number
  /**
   * Optional JSON permission scopes.
   * Example: { resources: ["users"], actions: ["read"] }
   */
  scopes?: {
    resources?: Array<string>
    actions?: Array<string>
  }
}

// ============================================================================
// RESPONSE DTOs
// ============================================================================

/**
 * Safe API key representation — never includes the hash or full raw key.
 */
export interface ApiKeyDTO {
  id: string
  /** User-supplied label */
  name: string
  /**
   * First 12 characters of the raw key (e.g. "sk_prod_ab1c").
   * Lets the user identify the key without revealing the secret.
   */
  keyPrefix: string
  status: 'active' | 'revoked' | 'expired'
  scopes: { resources?: Array<string>; actions?: Array<string> } | null
  lastUsedAt: string | null
  lastUsedIp: string | null
  usageCount: string
  expiresAt: string | null
  revokedAt: string | null
  createdAt: string
  /** Derived: true when key is active and not expired */
  isUsable: boolean
}

/**
 * Returned once at creation time — includes the raw key.
 * After this, the full key can never be recovered.
 */
export interface CreatedApiKeyDTO extends ApiKeyDTO {
  /** Full raw API key — shown once, never stored again */
  key: string
}

/** POST /api-keys */
export interface CreateApiKeyResponseDTO {
  apiKey: CreatedApiKeyDTO
}

/** GET /api-keys */
export interface ListApiKeysResponseDTO {
  apiKeys: Array<ApiKeyDTO>
  total: number
}
