import httpResponse from '@/shared/utils/http-response.utils'

import type { Context } from 'hono'
import type { AccessTokenPayload } from '@/shared/types/jwt.utils.types'
import type { CreateInvitationRequestDTO } from '@/modules/invite/dto/invite.dto'

import { logError } from '@/configs/logger.configs'
import { InviteService } from '@/modules/invite/services/invite.service'

/**
 * InviteController
 *
 * Handles HTTP requests for the invitation code system.
 * All mutating endpoints require a valid JWT session (auth middleware).
 */
export class InviteController {
  private inviteService: InviteService

  constructor() {
    this.inviteService = new InviteService()
  }

  /**
   * POST /invite
   * Create a new invitation code. Requires account age ≥ 30 days.
   */
  public createInvitation = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const body: CreateInvitationRequestDTO = ctx.get('validatedBody') as CreateInvitationRequestDTO

      const result = await this.inviteService.createInvitation(session._id, body)
      return httpResponse.created(ctx, 'Invitation code created successfully', undefined, result)
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logError(error as Error, { controller: 'InviteController', method: 'createInvitation' })

      if (message.includes('Account must be at least')) {
        return httpResponse.forbidden(ctx, message)
      }

      if (message.includes('User not found')) {
        return httpResponse.notFound(ctx, 'User not found')
      }

      return httpResponse.internalServerError(ctx, 'Failed to create invitation code')
    }
  }

  /**
   * GET /invite
   * List all invitation codes created by the authenticated user.
   */
  public listInvitations = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const result = await this.inviteService.listInvitations(session._id)
      return httpResponse.ok(ctx, 'Invitations retrieved successfully', undefined, result)
    } catch (error) {
      logError(error as Error, { controller: 'InviteController', method: 'listInvitations' })
      return httpResponse.internalServerError(ctx, 'Failed to retrieve invitations')
    }
  }

  /**
   * DELETE /invite/:code
   * Revoke an invitation code owned by the authenticated user.
   */
  public revokeInvitation = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const session: AccessTokenPayload = ctx.get('session')
      const { code } = ctx.get('validatedParams') as { code: string }

      const invitation = await this.inviteService.revokeInvitation(code, session._id)
      return httpResponse.ok(ctx, 'Invitation code revoked successfully', undefined, { invitation })
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      logError(error as Error, { controller: 'InviteController', method: 'revokeInvitation' })

      if (message.includes('not found or already revoked')) {
        return httpResponse.notFound(ctx, 'Invitation not found or already revoked')
      }

      return httpResponse.internalServerError(ctx, 'Failed to revoke invitation code')
    }
  }

  /**
   * GET /invite/:code
   * Public endpoint — return validity info about an invitation code.
   * Used by the sign-up UI to preview code status before registration.
   */
  public getInvitation = async (ctx: Context<Generics>): Promise<Response> => {
    try {
      const { code } = ctx.get('validatedParams') as { code: string }
      const result = await this.inviteService.getPublicInfo(code)
      return httpResponse.ok(ctx, 'Invitation retrieved', undefined, result)
    } catch (error) {
      const message: string = error instanceof Error ? error.message : 'Unknown error'

      if (message.includes('not found')) {
        return httpResponse.notFound(ctx, 'Invitation not found')
      }

      logError(error as Error, { controller: 'InviteController', method: 'getInvitation' })
      return httpResponse.internalServerError(ctx, 'Failed to retrieve invitation')
    }
  }
}
