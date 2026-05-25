import type { User } from '@/modules/auth/models/users.model'
import type { ApiKey } from '@/modules/auth/models/api-keys.model'
import type { CreateApiKeyRequestDTO, ApiKeyDTO, CreatedApiKeyDTO, ListApiKeysResponseDTO } from '@/modules/api-keys/dto/api-keys.dto'

import { logger } from '@/configs/logger.configs'
import { UserRepository } from '@/modules/auth/repositories/user.repository'
import { generateApiKey, hashApiKey } from '@/modules/auth/models/api-keys.model'
import { ApiKeysRepository } from '@/modules/api-keys/repositories/api-keys.repository'

function isKeyExpired(key: ApiKey): boolean {
  return key.expiresAt !== null && key.expiresAt < new Date()
}

function isKeyUsable(key: ApiKey): boolean {
  return key.status === 'active' && !isKeyExpired(key)
}

function mapToDTO(key: ApiKey): ApiKeyDTO {
  return {
    id: key._id,
    name: key.name,
    keyPrefix: key.keyPrefix,
    status: isKeyExpired(key) && key.status === 'active' ? 'expired' : key.status,
    scopes: key.scopes as ApiKeyDTO['scopes'],
    lastUsedAt: key.lastUsedAt?.toISOString() ?? null,
    lastUsedIp: key.lastUsedIp,
    usageCount: key.usageCount,
    expiresAt: key.expiresAt?.toISOString() ?? null,
    revokedAt: key.revokedAt?.toISOString() ?? null,
    createdAt: key.createdAt.toISOString(),
    isUsable: isKeyUsable(key)
  }
}

export class ApiKeysService {
  private apiKeysRepository: ApiKeysRepository
  private userRepository: UserRepository

  constructor() {
    this.apiKeysRepository = new ApiKeysRepository()
    this.userRepository = new UserRepository()
  }

  /**
   * Create a new API key for a user.
   * The full raw key is returned once and never stored.
   *
   * @throws 'User not found' if userId does not exist
   * @throws 'API access is not enabled for your account' if user.apiAccess is false
   */
  async createApiKey(userId: string, data: CreateApiKeyRequestDTO): Promise<CreatedApiKeyDTO> {
    const user: User | null = await this.userRepository.findById(userId)

    if (!user) throw new Error('User not found')
    if (!user.apiAccess) throw new Error('API access is not enabled for your account')

    const activeCount: number = await this.apiKeysRepository.countActiveByUserId(userId)
    if (activeCount >= 10) throw new Error('Maximum of 10 active API keys reached. Revoke an existing key before creating a new one.')

    const { key: rawKey, kid }: { key: string; kid: string } = generateApiKey('prod')
    const keyHash: string = await hashApiKey(rawKey)
    const keyPrefix: string = kid
    const expiresAt: Date | undefined = data.expiresIn ? new Date(Date.now() + data.expiresIn * 1000) : undefined
    const created = await this.apiKeysRepository.create({
      userId,
      name: data.name,
      keyHash,
      keyPrefix,
      scopes: data.scopes ?? null,
      expiresAt: expiresAt ?? null
    })

    logger.info('API key created', { userId, keyPrefix })

    return { ...mapToDTO(created), key: rawKey }
  }

  /**
   * List all API keys for a user.
   */
  async listApiKeys(userId: string): Promise<ListApiKeysResponseDTO> {
    const keys = await this.apiKeysRepository.findByUserId(userId)

    return {
      apiKeys: keys.map(mapToDTO),
      total: keys.length
    }
  }

  /**
   * Revoke an API key owned by the user.
   *
   * @throws 'API key not found or already revoked' if key doesn't exist / not owned / already revoked
   */
  async revokeApiKey(id: string, userId: string): Promise<ApiKeyDTO> {
    const revoked = await this.apiKeysRepository.revoke(id, userId)

    if (!revoked) throw new Error('API key not found or already revoked')

    logger.info('API key revoked', { id, userId })

    return mapToDTO(revoked)
  }

  /**
   * Authenticate an incoming API key from the Authorization header.
   * Validates hash, status, expiry, and user.apiAccess.
   *
   * @throws 'Invalid API key' if no matching active key found
   * @throws 'API access is not enabled for your account' if user.apiAccess is false
   */
  async authenticateByKey(rawKey: string, ip: string): Promise<{ user: User; apiKey: ApiKey }> {
    const keyHash: string = await hashApiKey(rawKey)
    const key: ApiKey | null = await this.apiKeysRepository.findByHash(keyHash)

    if (!key || !isKeyUsable(key)) {
      throw new Error('Invalid API key')
    }

    const user: User | null = await this.userRepository.findById(key.userId)

    if (!user || !user.apiAccess) {
      throw new Error('API access is not enabled for your account')
    }

    // Non-blocking usage stats update
    this.apiKeysRepository.touch(key._id, ip).catch((err: unknown) => {
      logger.error('Failed to update API key usage stats', { error: err, keyId: key._id })
    })

    return { user, apiKey: key }
  }
}
