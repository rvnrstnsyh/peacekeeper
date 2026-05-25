import { z } from 'zod'

export const createInvitationSchema = z.object({
  expiresIn: z
    .number({ error: 'expiresIn must be a number' })
    .int('expiresIn must be an integer')
    .min(3600, 'Minimum expiry is 1 hour (3600 seconds)')
    .max(31_536_000, 'Maximum expiry is 365 days')
    .optional(),
  maxUses: z.number({ error: 'maxUses must be a number' }).int('maxUses must be an integer').min(1, 'maxUses must be at least 1').max(1000, 'maxUses cannot exceed 1000').optional()
})

export const inviteCodeParamSchema = z.object({
  code: z
    .string({ error: 'Invite code is required' })
    .min(1, 'Invite code cannot be empty')
    .max(16, 'Invalid invite code')
    .regex(/^[A-Z0-9]+$/, 'Invalid invite code format')
})
