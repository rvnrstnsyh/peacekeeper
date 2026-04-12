import httpResponse from '@/shared/utils/http-response.utils'

import type { $ZodIssue } from 'zod/v4/core'
import type { Context, MiddlewareHandler, Next } from 'hono'

import { z, ZodError } from 'zod'
import { createMiddleware } from 'hono/factory'
import { logger } from '@/configs/logger.configs'

type ValidationTarget = 'header' | 'body' | 'query' | 'params' | 'cookies'

interface ValidationError {
  field: string
  message: string
}

function formatZodErrors(validation: ZodError): Array<ValidationError> {
  return validation.issues.map(
    (error: $ZodIssue): ValidationError => ({
      field: error.path.join('.'),
      message: error.message
    })
  )
}

export function validateRequest(schema: z.Schema, target: ValidationTarget = 'body'): MiddlewareHandler {
  return createMiddleware(async (ctx: Context<Generics>, next: Next): Promise<Response | void> => {
    try {
      let data: unknown

      // Extract data based on target
      switch (target) {
        case 'header': {
          data = Object.fromEntries(ctx.req.raw.headers.entries())
          break
        }
        case 'body': {
          data = await ctx.req.json()
          break
        }
        case 'query': {
          data = ctx.req.query()
          break
        }
        case 'params': {
          data = ctx.req.param()
          break
        }
        case 'cookies': {
          const cookieHeader: string | undefined = ctx.req.header('Cookie')
          const cookies: Record<string, string> = {}

          if (cookieHeader) {
            cookieHeader.split('; ').forEach((cookieString): void => {
              const [name, ...valueParts]: Array<string> = cookieString.split('=')
              if (name) {
                const value: string = valueParts.join('=')
                cookies[decodeURIComponent(name.trim())] = decodeURIComponent(value || '')
              }
            })
          }
          data = cookies
          break
        }
        default: {
          throw new Error(`Invalid validation target: ${target}`)
        }
      }

      // Validate data against schema
      const validated: unknown = schema.parse(data)
      // Store validated data in context
      const validatedKeyMap = {
        header: 'validatedHeaders',
        body: 'validatedBody',
        query: 'validatedQuery',
        params: 'validatedParams',
        cookies: 'validatedCookies'
      } as const

      type ValidatedTarget = keyof typeof validatedKeyMap

      ctx.set(validatedKeyMap[target as ValidatedTarget], validated)

      await next()
    } catch (error: unknown) {
      if (error instanceof ZodError) {
        const errors: Array<ValidationError> = formatZodErrors(error)

        logger.warning('Validation failed', {
          target,
          errors,
          path: ctx.req.path,
          method: ctx.req.method
        })
        return httpResponse.unprocessableEntity(ctx, 'Validation failed', errors)
      }

      logger.error('Validation middleware error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        target,
        path: ctx.req.path
      })
      return httpResponse.badRequest(ctx, 'Validation error occurred')
    }
  })
}

/**
 * Validate headers
 */
export const validateHeaders = (schema: z.Schema): MiddlewareHandler => {
  return validateRequest(schema, 'header')
}

/**
 * Validate request body
 */
export const validateBody = (schema: z.Schema): MiddlewareHandler => {
  return validateRequest(schema, 'body')
}

/**
 * Validate query parameters
 */
export const validateQuery = (schema: z.Schema): MiddlewareHandler => {
  return validateRequest(schema, 'query')
}

/**
 * Validate route parameters
 */
export const validateParams = (schema: z.Schema): MiddlewareHandler => {
  return validateRequest(schema, 'params')
}

/**
 * Validate cookies
 */
export const validateCookies = (schema: z.Schema): MiddlewareHandler => {
  return validateRequest(schema, 'cookies')
}

export function validateMultiple(validations: { body?: z.Schema; query?: z.Schema; params?: z.Schema; headers?: z.Schema; cookies?: z.Schema }): MiddlewareHandler {
  return createMiddleware(async (ctx: Context<Generics>, next: Next): Promise<Response | void> => {
    const allErrors: Array<ValidationError> = []

    // Validate headers
    if (validations.headers) {
      try {
        const headersData: { [k: string]: string } = Object.fromEntries(Array.from(ctx.req.raw.headers.entries()))
        const validated: unknown = validations.headers.parse(headersData)
        ctx.set('validatedHeaders', validated)
      } catch (error: unknown) {
        if (error instanceof ZodError) {
          allErrors.push(...formatZodErrors(error))
        }
      }
    }

    // Validate body
    if (validations.body) {
      try {
        const bodyData: unknown = await ctx.req.json()
        const validated: unknown = validations.body.parse(bodyData)
        ctx.set('validatedBody', validated)
      } catch (error: unknown) {
        if (error instanceof ZodError) {
          allErrors.push(...formatZodErrors(error))
        }
      }
    }

    // Validate query
    if (validations.query) {
      try {
        const queryData: Record<string, string> = ctx.req.query()
        const validated: unknown = validations.query.parse(queryData)
        ctx.set('validatedQuery', validated)
      } catch (error: unknown) {
        if (error instanceof ZodError) {
          allErrors.push(...formatZodErrors(error))
        }
      }
    }

    // Validate params
    if (validations.params) {
      try {
        const paramsData: { [x: string]: string } = ctx.req.param()
        const validated: unknown = validations.params.parse(paramsData)
        ctx.set('validatedParams', validated)
      } catch (error: unknown) {
        if (error instanceof ZodError) {
          allErrors.push(...formatZodErrors(error))
        }
      }
    }

    // Validate cookies
    if (validations.cookies) {
      try {
        const cookieHeader: string | undefined = ctx.req.header('Cookie')
        const cookies: Record<string, string> = {}

        if (cookieHeader) {
          cookieHeader.split('; ').forEach((cookieString): void => {
            const [name, ...valueParts]: Array<string> = cookieString.split('=')
            if (name) {
              const value: string = valueParts.join('=')
              cookies[decodeURIComponent(name.trim())] = decodeURIComponent(value || '')
            }
          })
        }

        const validated: unknown = validations.cookies.parse(cookies)
        ctx.set('validatedCookies', validated)
      } catch (error: unknown) {
        if (error instanceof ZodError) {
          allErrors.push(...formatZodErrors(error))
        }
      }
    }

    // Return errors if any
    if (allErrors.length > 0) {
      logger.warning('Multi-target validation failed', {
        errors: allErrors,
        path: ctx.req.path,
        method: ctx.req.method
      })
      return httpResponse.unprocessableEntity(ctx, 'Validation failed')
    }
    await next()
  })
}

/**
 * Validate ID parameter (numeric or UUID)
 */
export const validateId: MiddlewareHandler = validateParams(
  z.object({
    userId: z.string().min(1, { message: 'ID is required' })
  })
)

/**
 * Validate pagination query parameters
 */
export const validatePagination: MiddlewareHandler = validateQuery(
  z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(10),
    sortBy: z.string().optional(),
    sortOrder: z.enum(['asc', 'desc']).default('asc')
  })
)

export default validateRequest
