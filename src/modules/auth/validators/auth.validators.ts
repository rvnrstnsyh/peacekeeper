import { z } from 'zod'

const emailRule = z.email('Invalid email format').min(4, 'Email must be at least 4 characters').max(255, 'Email must not exceed 255 characters').toLowerCase().trim()

const usernameRule = z
  .string()
  .min(3, 'Username must be at least 3 characters')
  .max(30, 'Username must not exceed 30 characters')
  .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens')
  .trim()

const phoneRule = z
  .string()
  .regex(/^[0-9\s()+-]+$/, 'Invalid phone number format')
  .min(10, 'Phone number must be at least 10 digits')
  .max(20, 'Phone number must not exceed 20 characters')
  .optional()

const nameRule = z
  .string()
  .min(2, 'Name must be at least 2 characters')
  .max(50, 'Name must not exceed 50 characters')
  .regex(/^[a-zA-Z\s\-']+$/, 'Name can only contain letters, spaces, hyphens, and apostrophes')
  .trim()

const base64Rule = (fieldName: string): z.ZodString =>
  z
    .string()
    .min(1, `${fieldName} cannot be empty`)
    .refine((value: string): boolean => {
      try {
        if (value.length % 4 !== 0) return false
        return Buffer.from(Buffer.from(value, 'base64')).toString('base64') === value
      } catch {
        return false
      }
    }, `${fieldName} must be valid base64`)

export const signUpAlphaSchema = z.object({
  request: z.object({
    blindedMessage: base64Rule('Request')
  })
})

export const signUpBetaSchema = z.object({
  credentialIdentifier: base64Rule('Credential identifier'),
  record: z.object({
    clientPublicKey: base64Rule('Client public key'),
    maskingKey: base64Rule('Masking key'),
    envelope: z.object({
      nonce: base64Rule('Nonce'),
      authTag: base64Rule('Auth tag'),
      seed: base64Rule('Seed')
    })
  }),
  email: emailRule,
  username: usernameRule,
  firstName: nameRule.optional(),
  lastName: nameRule.optional(),
  phone: phoneRule.optional(),
  dateOfBirth: z.coerce
    .date({ error: 'Invalid date format (YYYY-MM-DD)' })
    .optional()
    .refine(
      (date: Date | undefined): boolean => {
        if (!date) return true
        const birthDate: Date = new Date(date)
        const today: Date = new Date()
        const age: number = today.getFullYear() - birthDate.getFullYear()
        return age >= 0 && age <= 150
      },
      { message: 'Age must be between 0 and 150 years' }
    ),
  gender: z
    .enum(['male', 'female'], {
      error: (): { message: string } => ({
        message: 'Gender must be either "male" or "female"'
      })
    })
    .optional(),
  address: z.string().min(10, 'Address must be at least 10 characters').max(500, 'Address must not exceed 500 characters').optional()
})

export const signInAlphaSchema = z.object({
  email: emailRule,
  rememberMe: z.boolean({ error: 'rememberMe must be a boolean' }),
  ke1: z.object({
    blindedMessage: base64Rule('Blinded message'),
    clientNonce: base64Rule('Nonce'),
    clientPublicKeyshare: base64Rule('Public keyshare')
  })
})

export const signInBetaSchema = z.object({
  credentialIdentifier: base64Rule('Credential identifier'),
  ke3: z.object({
    clientMac: base64Rule('Client MAC')
  })
})

export const refreshTokenSchema = z.object({
  '__Secure-Refresh-Token': z.string({ error: 'Refresh token is required' }).min(1, 'Refresh token is required')
})

export const forgotPasswordSchema = z.object({
  email: emailRule
})

export const resetPasswordAlphaSchema = z.object({
  resetToken: z.string({ error: 'Reset token is required' }).min(1, 'Reset token is required'),
  request: z.object({
    blindedMessage: base64Rule('Request')
  })
})

export const resetPasswordBetaSchema = z.object({
  credentialIdentifier: base64Rule('Credential identifier'),
  record: z.object({
    clientPublicKey: base64Rule('Client public key'),
    maskingKey: base64Rule('Masking key'),
    envelope: z.object({
      nonce: base64Rule('Nonce'),
      authTag: base64Rule('Auth tag'),
      seed: base64Rule('Seed')
    })
  })
})

export const verifyEmailSchema = z.object({
  'verify-email-token': z.string({ error: 'Verification token is required' }).min(1, 'Verification token is required')
})

export const changePasswordAlphaSchema = z.object({
  request: z.object({
    credentialIdentifier: base64Rule('Credential identifier'),
    oldPasswordKE1: z.object({
      blindedMessage: base64Rule('Blinded message'),
      clientNonce: base64Rule('Nonce'),
      clientPublicKeyshare: base64Rule('Public keyshare')
    }),
    newPasswordRegistrationRequest: z.object({
      blindedMessage: base64Rule('Blinded message')
    })
  })
})

export const changePasswordBetaSchema = z.object({
  credentialIdentifier: base64Rule('Credential identifier'),
  ke3: z.object({
    clientMac: base64Rule('Client MAC')
  }),
  newRecord: z.object({
    clientPublicKey: base64Rule('Client public key'),
    maskingKey: base64Rule('Masking key'),
    envelope: z.object({
      nonce: base64Rule('Nonce'),
      authTag: base64Rule('Auth tag'),
      seed: base64Rule('Seed')
    })
  })
})

export const updateProfileSchema = z.object({
  firstName: nameRule.optional(),
  lastName: nameRule.optional(),
  phone: phoneRule,
  dateOfBirth: z.coerce
    .date('Invalid date format (YYYY-MM-DD)')
    .optional()
    .refine(
      (date: Date | undefined): boolean => {
        if (!date) return true
        const birthDate: Date = new Date(date)
        const today: Date = new Date()
        const age: number = today.getFullYear() - birthDate.getFullYear()
        return age >= 0 && age <= 150
      },
      { message: 'Invalid date of birth' }
    ),
  gender: z.enum(['male', 'female']).optional(),
  address: z.string().min(10, 'Address must be at least 10 characters').max(500, 'Address must not exceed 500 characters').optional(),
  avatar: z.url('Invalid avatar URL').optional()
})
