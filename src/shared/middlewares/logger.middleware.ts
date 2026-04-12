import type { Context, MiddlewareHandler, Next } from 'hono'

import { createMiddleware } from 'hono/factory'
import { env } from '@/configs/environment.configs'
import { logger, logRequest } from '@/configs/logger.configs'
import { remoteAddr } from '@/shared/utils/remote-addr.utils'
import { SENSITIVE_KEYS } from '@/shared/constants/common.constants'

interface LoggerOptions {
  skipPaths?: Array<string>
  skipHealthCheck?: boolean
  logRequestBody?: boolean
  logResponseBody?: boolean
  maxBodyLength?: number
  colorize?: boolean
}

function shouldSkipLogging(path: string, options: LoggerOptions): boolean {
  const { skipPaths = [], skipHealthCheck = true } = options

  // Skip health check endpoints
  if (skipHealthCheck && (path === '/health' || path.endsWith('/health'))) {
    return true
  }

  // Skip specified paths
  return skipPaths.some((skipPath) => {
    if (skipPath.endsWith('*')) {
      return path.startsWith(skipPath.slice(0, -1))
    }
    return path === skipPath
  })
}

function sanitizeData(data: unknown, maxLength: number = 1000): unknown {
  if (typeof data === 'string') {
    return data.length > maxLength ? data.substring(0, maxLength) + '...' : data
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizeData(item, maxLength))
  }

  if (typeof data === 'object' && data !== null) {
    const sanitized: Record<string, unknown> = {}

    for (const [key, value] of Object.entries(data)) {
      // Skip sensitive fields
      if (env.isProduction) {
        if (SENSITIVE_KEYS.includes(key.toLowerCase())) {
          sanitized[key] = '[REDACTED]'
          continue
        }
      }

      if (typeof value === 'string') {
        sanitized[key] = value.length > maxLength ? value.substring(0, maxLength) + '...' : value
      } else if (typeof value === 'object' || Array.isArray(value)) {
        sanitized[key] = sanitizeData(value, maxLength)
      } else {
        sanitized[key] = value
      }
    }
    return sanitized
  }
  return data
}

function getStatusColor(status: number): string {
  if (status >= 500) return '\x1b[31m' // Red
  if (status >= 400) return '\x1b[33m' // Yellow
  if (status >= 300) return '\x1b[36m' // Cyan
  if (status >= 200) return '\x1b[32m' // Green
  return '\x1b[0m' // Reset
}

function getMethodColor(method: string): string {
  switch (method) {
    case 'GET':
      return '\x1b[32m' // Green
    case 'POST':
      return '\x1b[33m' // Yellow
    case 'PUT':
      return '\x1b[34m' // Blue
    case 'DELETE':
      return '\x1b[31m' // Red
    case 'PATCH':
      return '\x1b[35m' // Magenta
    default:
      return '\x1b[0m' // Reset
  }
}

export function loggerMiddleware(options: LoggerOptions = {}) {
  const { logRequestBody = false, logResponseBody = false, maxBodyLength = 1000, colorize = true } = options

  return createMiddleware(async (ctx: Context<Generics>, next: Next) => {
    const method: string = ctx.req.method
    const path: string = ctx.req.path

    // Skip logging for certain paths
    if (shouldSkipLogging(path, options)) {
      return next()
    }

    // Extract request info
    let userId: string | undefined
    try {
      userId = ctx.get('session')._id
    } catch (_error) {
      //
    }
    const ip: string = remoteAddr(ctx)
    const userAgent: string = ctx.req.header('user-agent') || 'unknown'
    const requestId: string = ctx.get('requestId') || ctx.req.header('x-request-id') || crypto.randomUUID()

    // Set request ID for tracking
    ctx.set('requestId', requestId)

    // Log request body if enabled
    let requestBody: unknown = undefined
    if (logRequestBody && ['POST', 'PUT', 'PATCH'].includes(method)) {
      try {
        const rawBody: string = await ctx.req.raw.clone().text()
        if (rawBody) {
          requestBody = sanitizeData(JSON.parse(rawBody), maxBodyLength)
        }
      } catch (_error) {
        // Body might not be JSON, skip
      }
    }
    // Execute request
    await next()

    // Calculate duration
    const durationMs: number = performance.now() - ctx.get('requestTime')
    const statusCode: number = ctx.res.status
    // Log response body if enabled
    let responseBody: unknown = undefined
    if (logResponseBody && statusCode < 400) {
      try {
        const rawResponse: string = await ctx.res.clone().text()
        if (rawResponse) {
          responseBody = sanitizeData(JSON.parse(rawResponse), maxBodyLength)
        }
      } catch (_error) {
        // Response might not be JSON, skip
      }
    }

    // Use Winston logger
    logRequest(method, path, statusCode, durationMs, userId)

    // Console output (Hono-style, colorized for development)
    if (env.isDevelopment && colorize) {
      const methodColor: string = getMethodColor(method)
      const statusColor: string = getStatusColor(statusCode)
      const resetColor: string = '\x1b[0m'
      // eslint-disable-next-line no-console
      console.log(`${methodColor}${method.padEnd(7)}${resetColor}` + `${statusColor}${statusCode}${resetColor} ` + `${path} ` + `${durationMs.toFixed(2)}`)
    }
    // Detailed log for Winston
    const level: string = statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warning' : 'http'
    logger.log(level, 'Request completed', {
      requestId,
      method,
      path,
      statusCode,
      durationMs: durationMs.toFixed(2),
      ip,
      userId,
      userAgent,
      requestBody,
      responseBody
    })
  })
}

export function honoLogger(options: LoggerOptions = {}): MiddlewareHandler {
  return loggerMiddleware({
    ...options,
    colorize: true,
    skipHealthCheck: true
  })
}
