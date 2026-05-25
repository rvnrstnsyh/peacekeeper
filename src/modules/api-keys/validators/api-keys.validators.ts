import { z } from 'zod'

export const createApiKeySchema = z.object({
  name: z.string({ error: 'Name is required' }).min(1, 'Name cannot be empty').max(100, 'Name must not exceed 100 characters').trim(),
  expiresIn: z
    .number({ error: 'expiresIn must be a number' })
    .int('expiresIn must be an integer')
    .min(3600, 'Minimum expiry is 1 hour (3600 seconds)')
    .max(31_536_000, 'Maximum expiry is 365 days')
    .optional(),
  scopes: z
    .object({
      resources: z.array(z.string().min(1).max(64)).max(50).optional(),
      actions: z.array(z.string().min(1).max(64)).max(20).optional()
    })
    .optional()
})

export const apiKeyIdParamSchema = z.object({
  id: z.string({ error: 'API key ID is required' }).uuid('Invalid API key ID')
})
