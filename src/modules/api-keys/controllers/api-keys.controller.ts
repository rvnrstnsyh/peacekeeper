import httpResponse from '@/shared/utils/http-response.utils'

import type { Context } from 'hono'
import type { AccessTokenPayload } from '@/shared/types/jwt.utils.types'
import type { CreateApiKeyRequestDTO } from '@/modules/api-keys/dto/api-keys.dto'

import { logError } from '@/configs/logger.configs'
import { ApiKeysService } from '@/modules/api-keys/services/api-keys.service'

export class ApiKeysController {
  private apiKeysService: ApiKeysService

  constructor() {
    this.apiKeysService = new ApiKeysService()
  }

  /**
   * GET /api-keys
   * List all API keys for the authenticated user.
   */
  public listApiKeys = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const result = await this.apiKeysService.listApiKeys(session._id)
      return httpResponse.ok(ctx, 'API keys retrieved successfully', undefined, result)
    } catch (error) {
      logError(error as Error, { controller: 'ApiKeysController', method: 'listApiKeys' })
      return httpResponse.internalServerError(ctx, 'Failed to retrieve API keys')
    }
  }

  /**
   * POST /api-keys
   * Create a new API key. The full raw key is returned once in the response.
   */
  public createApiKey = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const body: CreateApiKeyRequestDTO = ctx.get('validatedBody') as CreateApiKeyRequestDTO

      const result = await this.apiKeysService.createApiKey(session._id, body)
      return httpResponse.created(ctx, 'API key created successfully', undefined, { apiKey: result })
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logError(error as Error, { controller: 'ApiKeysController', method: 'createApiKey' })

      if (message.includes('API access is not enabled')) {
        return httpResponse.forbidden(ctx, message)
      }

      if (message.includes('Maximum of 10 active API keys')) {
        return httpResponse.badRequest(ctx, message)
      }

      if (message.includes('User not found')) {
        return httpResponse.notFound(ctx, 'User not found')
      }

      return httpResponse.internalServerError(ctx, 'Failed to create API key')
    }
  }

  /**
   * DELETE /api-keys/:id
   * Revoke an API key owned by the authenticated user.
   */
  public revokeApiKey = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const { id } = ctx.get('validatedParams') as { id: string }

      const result = await this.apiKeysService.revokeApiKey(id, session._id)
      return httpResponse.ok(ctx, 'API key revoked successfully', undefined, { apiKey: result })
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logError(error as Error, { controller: 'ApiKeysController', method: 'revokeApiKey' })

      if (message.includes('not found or already revoked')) {
        return httpResponse.notFound(ctx, 'API key not found or already revoked')
      }

      return httpResponse.internalServerError(ctx, 'Failed to revoke API key')
    }
  }
}
