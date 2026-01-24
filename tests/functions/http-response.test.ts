import httpResponse from '@/shared/utils/http-response.utils'

import type { Next, Context } from 'hono'
import type { ApiError } from '@/shared/types/http-response.utils.types'

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { etag } from 'hono/etag'
import { timeout } from 'hono/timeout'
import { compress } from 'hono/compress'
import { requestId } from 'hono/request-id'
import { poweredBy } from 'hono/powered-by'
import { startTime, timing } from 'hono/timing'
import { env } from '@/configs/environment.configs'
import { secureHeaders } from 'hono/secure-headers'
import { contextStorage } from 'hono/context-storage'
import { trimTrailingSlash } from 'hono/trailing-slash'
import { describe, it, expect, beforeEach } from 'vitest'
import { allowedOrigins } from '@/shared/utils/common.utils'
import { honoLogger } from '@/shared/middlewares/logger.middleware'

describe('HTTP Response Utilities', (): void => {
  let app: Hono

  beforeEach((): void => {
    app = new Hono()
    // Setup required middlewares in correct order
    app
      .use(poweredBy({ serverName: env.APP_NAME }))
      .use(compress())
      .use(timing({ autoEnd: true, total: false }))
      .use(requestId())
      .use(trimTrailingSlash())
      .use(timeout(30_000))
      .use(etag())
      // CRITICAL: contextStorage must be BEFORE logger middleware
      .use(contextStorage())
      .use(
        honoLogger({
          skipHealthCheck: true,
          skipPaths: ['/favicon.ico', '/robots.txt'],
          logRequestBody: env.isDevelopment,
          logResponseBody: false
        })
      )
      // CRITICAL: Set requestTime BEFORE any routes
      .use('*', async (ctx: Context<Generics>, next: Next): Promise<void> => {
        startTime(ctx, 'Request')
        ctx.set('requestTime', performance.now())
        await next()
      })
      .use(
        cors({
          origin: (origin: string): string | undefined => {
            if (!origin) return undefined
            return allowedOrigins(origin) ? origin : undefined
          },
          allowHeaders: ['Content-Type', 'Authorization'],
          allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
          exposeHeaders: ['Content-Length', 'X-Kuma-Revision'],
          maxAge: 600,
          credentials: true
        })
      )
      .use(secureHeaders())
  })

  const makeRequest = async (path: string, options?: RequestInit) => {
    const response: Response = await app.request(path, options)
    const body = await response.json()
    return { response, body }
  }

  describe('Response Structure', (): void => {
    it('should have consistent base structure for success responses', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Test message'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(200)
      expect(body).toHaveProperty('meta')
      expect(body).toHaveProperty('data')
      expect(body.meta).toHaveProperty('requestId')
      expect(body.meta).toHaveProperty('path', '/test')
      expect(body.meta).toHaveProperty('method', 'GET')
      expect(body.meta).toHaveProperty('status', 200)
      expect(body.meta).toHaveProperty('code', 'OK')
      expect(body.meta).toHaveProperty('timestamp')
      expect(body.meta).toHaveProperty('message', 'Test message')
      expect(body.meta).toHaveProperty('responseTimeMs')
    })

    it('should have consistent base structure for error responses', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.badRequest(ctx, 'Test error'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(400)
      expect(body).toHaveProperty('meta')
      expect(body).not.toHaveProperty('data')
      expect(body.meta).toHaveProperty('requestId')
      expect(body.meta).toHaveProperty('path', '/test')
      expect(body.meta).toHaveProperty('method', 'GET')
      expect(body.meta).toHaveProperty('status', 400)
      expect(body.meta).toHaveProperty('code', 'BAD_REQUEST')
      expect(body.meta).toHaveProperty('timestamp')
      expect(body.meta).toHaveProperty('message', 'Test error')
      expect(body.meta).toHaveProperty('responseTimeMs')
    })

    it('should have valid timestamp format', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Test'))
      const { body } = await makeRequest('/test')

      expect(body.meta.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

      const date = new Date(body.meta.timestamp)
      expect(date.toString()).not.toBe('Invalid Date')
      expect(date.getTime()).toBeLessThanOrEqual(Date.now())
    })

    it('should have numeric responseTimeMs', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Test'))
      const { body } = await makeRequest('/test')

      expect(typeof body.meta.responseTimeMs).toBe('number')
      expect(body.meta.responseTimeMs).toBeGreaterThanOrEqual(0)
      expect(body.meta.responseTimeMs).toBeLessThan(1000)
    })
  })

  describe('2xx - Success Responses', (): void => {
    it('should return 200 OK with data', async (): Promise<void> => {
      const testData = { id: 1, name: 'Test' }
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Success', undefined, testData))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(200)
      expect(body.meta.code).toBe('OK')
      expect(body.meta.message).toBe('Success')
      expect(body.data).toEqual(testData)
    })

    it('should return 200 OK without data', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.okNoData(ctx, 'Success'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(200)
      expect(body.data).toBeNull()
    })

    it('should return 200 OK with metadata', async (): Promise<void> => {
      const testData = [{ id: 1 }, { id: 2 }]
      const metaData = { total: 2, page: 1 }
      app.get('/test', (ctx: Context<Generics>) => httpResponse.okWithMeta(ctx, 'Success', metaData, undefined, testData))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(200)
      expect(body.meta.extra).toEqual(metaData)
      expect(body.data).toEqual(testData)
    })

    it('should return 201 Created', async (): Promise<void> => {
      const newItem = { id: 1, name: 'New Item' }
      app.post('/test', (ctx: Context<Generics>) => httpResponse.created(ctx, 'Resource created', undefined, newItem))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(201)
      expect(body.meta.code).toBe('CREATED')
      expect(body.meta.message).toBe('Resource created')
      expect(body.data).toEqual(newItem)
    })

    it('should return 202 Accepted', async (): Promise<void> => {
      app.post('/test', (ctx: Context<Generics>) => httpResponse.accepted(ctx))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(202)
      expect(body.meta.code).toBe('ACCEPTED')
    })

    it('should return 202 Accepted with data', async (): Promise<void> => {
      const jobData = { jobId: 'abc123', status: 'queued' }
      app.post('/test', (ctx: Context<Generics>) => httpResponse.acceptedWithData(ctx, 'Job queued', undefined, jobData))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(202)
      expect(body.meta.code).toBe('ACCEPTED')
      expect(body.data).toEqual(jobData)
    })

    it('should return 204 No Content', async (): Promise<void> => {
      app.delete('/test', (ctx: Context<Generics>) => httpResponse.noContent(ctx))
      const response: Response = await app.request('/test', { method: 'DELETE' })

      expect(response.status).toBe(204)

      const contentLength = response.headers.get('Content-Length')
      if (contentLength !== null) {
        expect(['0', '']).toContain(contentLength)
      }
    })

    it('should return 206 Partial Content', async (): Promise<void> => {
      const partialData = { items: [1, 2, 3] }
      app.get('/test', (ctx: Context<Generics>) => httpResponse.partialContent(ctx, 'Partial data', 'bytes 0-999/5000', undefined, partialData))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(206)
      expect(body.meta.code).toBe('PARTIAL_CONTENT')
      expect(response.headers.get('Content-Range')).toBe('bytes 0-999/5000')
      expect(body.data).toEqual(partialData)
    })

    it('should return 200 OK with pagination', async (): Promise<void> => {
      const items = [{ id: 1 }, { id: 2 }]
      const pagination = {
        page: 1,
        limit: 10,
        total: 100,
        totalPages: 10
      }
      app.get('/test', (ctx: Context<Generics>) => httpResponse.paginated(ctx, 'Paginated result', pagination, undefined, items))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(200)
      expect(body.meta.extra).toHaveProperty('pagination')
      expect(body.meta.extra.pagination).toEqual(pagination)
      expect(body.data).toEqual(items)
    })
  })

  describe('3xx - Redirection Responses', (): void => {
    it('should return 301 Moved Permanently', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.movedPermanently(ctx, 'Resource moved', 'https://example.com/new'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(301)
      expect(body.meta.code).toBe('MOVED_PERMANENTLY')
      expect(response.headers.get('Location')).toBe('https://example.com/new')
    })

    it('should return 302 Found', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.found(ctx, 'Temporary redirect', 'https://example.com/temp'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(302)
      expect(body.meta.code).toBe('FOUND')
      expect(response.headers.get('Location')).toBe('https://example.com/temp')
    })

    it('should return 303 See Other', async (): Promise<void> => {
      app.post('/test', (ctx: Context<Generics>) => httpResponse.seeOther(ctx, 'See other resource', '/result'))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(303)
      expect(body.meta.code).toBe('SEE_OTHER')
      expect(response.headers.get('Location')).toBe('/result')
    })

    it('should return 304 Not Modified', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.notModified(ctx))
      const response: Response = await app.request('/test')

      expect(response.status).toBe(304)
    })

    it('should return 307 Temporary Redirect', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.temporaryRedirect(ctx, 'Temporary redirect', '/temp'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(307)
      expect(body.meta.code).toBe('TEMPORARY_REDIRECT')
      expect(response.headers.get('Location')).toBe('/temp')
    })

    it('should return 308 Permanent Redirect', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.permanentRedirect(ctx, 'Permanent redirect', '/permanent'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(308)
      expect(body.meta.code).toBe('PERMANENT_REDIRECT')
      expect(response.headers.get('Location')).toBe('/permanent')
    })
  })

  describe('4xx - Client Error Responses', (): void => {
    it('should return 400 Bad Request', async (): Promise<void> => {
      app.post('/test', (ctx: Context<Generics>) => httpResponse.badRequest(ctx, 'Invalid input'))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(400)
      expect(body.meta.code).toBe('BAD_REQUEST')
      expect(body.meta.message).toBe('Invalid input')
    })

    it('should return 400 Bad Request with validation errors', async (): Promise<void> => {
      const errors: ApiError[] = [
        { field: 'email', message: 'Invalid email format' },
        { field: 'password', message: 'Password too short' }
      ]
      app.post('/test', (ctx: Context<Generics>) => httpResponse.badRequest(ctx, 'Validation failed', errors))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(400)
      expect(body.meta.errors).toEqual(errors)
      expect(body.meta.errors).toHaveLength(2)
    })

    it('should return 401 Unauthorized', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.unauthorized(ctx, 'Authentication required'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(401)
      expect(body.meta.code).toBe('UNAUTHORIZED')
      expect(body.meta.message).toBe('Authentication required')
    })

    it('should return 401 Unauthorized with details', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.unauthorized(ctx, 'Token expired', undefined, 'Please login again'))
      const { body } = await makeRequest('/test')

      expect(body.meta.status).toBe(401)
      expect(body.meta.details).toBe('Please login again')
    })

    it('should return 403 Forbidden', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.forbidden(ctx, 'Access denied'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(403)
      expect(body.meta.code).toBe('FORBIDDEN')
      expect(body.meta.message).toBe('Access denied')
    })

    it('should return 404 Not Found', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.notFound(ctx, 'Resource not found'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(404)
      expect(body.meta.code).toBe('NOT_FOUND')
      expect(body.meta.message).toBe('Resource not found')
    })

    it('should return 405 Method Not Allowed', async (): Promise<void> => {
      app.post('/test', (ctx: Context<Generics>) => httpResponse.methodNotAllowed(ctx, 'Method not allowed', ['GET', 'PUT']))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(405)
      expect(body.meta.code).toBe('METHOD_NOT_ALLOWED')
      expect(response.headers.get('Allow')).toBe('GET, PUT')
      expect(body.meta.details).toContain('Allowed methods')
    })

    it('should return 408 Request Timeout', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.requestTimeout(ctx))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(408)
      expect(body.meta.code).toBe('REQUEST_TIMEOUT')
    })

    it('should return 409 Conflict', async (): Promise<void> => {
      const errors: ApiError[] = [{ field: 'email', message: 'Email already exists' }]
      app.post('/test', (ctx: Context<Generics>) => httpResponse.conflict(ctx, 'Resource conflict', errors))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(409)
      expect(body.meta.code).toBe('CONFLICT')
      expect(body.meta.errors).toEqual(errors)
    })

    it('should return 413 Content Too Large', async (): Promise<void> => {
      app.post('/test', (ctx: Context<Generics>) => httpResponse.contentTooLarge(ctx, 'File too large', '10MB'))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(413)
      expect(body.meta.code).toBe('CONTENT_TOO_LARGE')
      expect(body.meta.details).toContain('10MB')
    })

    it('should return 415 Unsupported Media Type', async (): Promise<void> => {
      app.post('/test', (ctx: Context<Generics>) => httpResponse.unsupportedMediaType(ctx, 'Unsupported format', ['application/json', 'application/xml']))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(415)
      expect(body.meta.code).toBe('UNSUPPORTED_MEDIA_TYPE')
      expect(body.meta.details).toContain('application/json')
    })

    it('should return 422 Unprocessable Entity', async (): Promise<void> => {
      const errors: ApiError[] = [{ field: 'age', message: 'Must be a positive number' }]
      app.post('/test', (ctx: Context<Generics>) => httpResponse.unprocessableEntity(ctx, 'Validation failed', errors))
      const { response, body } = await makeRequest('/test', { method: 'POST' })

      expect(response.status).toBe(422)
      expect(body.meta.code).toBe('UNPROCESSABLE_CONTENT')
      expect(body.meta.errors).toEqual(errors)
    })

    it('should return 429 Too Many Requests', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.tooManyRequests(ctx, 'Rate limit exceeded', 60))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(429)
      expect(body.meta.code).toBe('RATE_LIMIT_EXCEEDED')
      expect(response.headers.get('Retry-After')).toBe('60')
      expect(body.meta.details).toContain('60 seconds')
    })
  })

  describe('5xx - Server Error Responses', (): void => {
    it('should return 500 Internal Server Error', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.internalServerError(ctx))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(500)
      expect(body.meta.code).toBe('INTERNAL_SERVER_ERROR')
    })

    it('should return 500 with error details', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.internalServerError(ctx, 'Database connection failed', undefined, 'Connection timeout'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(500)
      expect(body.meta.message).toBe('Database connection failed')
      expect(body.meta.details).toBe('Connection timeout')
    })

    it('should return 501 Not Implemented', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.notImplemented(ctx, 'Feature not implemented'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(501)
      expect(body.meta.code).toBe('NOT_IMPLEMENTED')
      expect(body.meta.message).toBe('Feature not implemented')
    })

    it('should return 502 Bad Gateway', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.badGateway(ctx, 'Upstream service error'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(502)
      expect(body.meta.code).toBe('BAD_GATEWAY')
      expect(body.meta.message).toBe('Upstream service error')
    })

    it('should return 503 Service Unavailable', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.serviceUnavailable(ctx, 'Service under maintenance', 120))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(503)
      expect(body.meta.code).toBe('SERVICE_UNAVAILABLE')
      expect(response.headers.get('Retry-After')).toBe('120')
    })

    it('should return 504 Gateway Timeout', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.gatewayTimeout(ctx, 'Upstream timeout'))
      const { response, body } = await makeRequest('/test')

      expect(response.status).toBe(504)
      expect(body.meta.code).toBe('GATEWAY_TIMEOUT')
      expect(body.meta.message).toBe('Upstream timeout')
    })
  })

  describe('Custom Headers', (): void => {
    it('should include custom headers in response', async (): Promise<void> => {
      const customHeaders = { 'X-Custom-Header': 'test-value' }
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Success', customHeaders))
      const { response } = await makeRequest('/test')

      expect(response.headers.get('X-Custom-Header')).toBe('test-value')
    })

    it('should always include standard headers', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Success'))
      const { response } = await makeRequest('/test')

      const contentType: string | null = response.headers.get('Content-Type')
      expect(contentType).toContain('application/json')

      const responseTime: string | null = response.headers.get('X-Response-Time')
      expect(responseTime).toMatch(/^\d+\.?\d*ms$/)

      expect(response.headers.get('X-Request-Id')).toBeTruthy()
    })

    it('should allow multiple custom headers', async (): Promise<void> => {
      const customHeaders = {
        'X-Custom-1': 'value1',
        'X-Custom-2': 'value2',
        'X-Custom-3': 'value3'
      }
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Success', customHeaders))
      const { response } = await makeRequest('/test')

      expect(response.headers.get('X-Custom-1')).toBe('value1')
      expect(response.headers.get('X-Custom-2')).toBe('value2')
      expect(response.headers.get('X-Custom-3')).toBe('value3')
    })
  })

  describe('Custom Status Codes', (): void => {
    it('should accept custom code parameter', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Custom success', undefined, { test: true }, 'CUSTOM_OK'))
      const { body } = await makeRequest('/test')

      expect(body.meta.code).toBe('CUSTOM_OK')
      expect(body.meta.status).toBe(200)
    })

    it('should use default code when not provided', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.created(ctx, 'Resource created'))
      const { body } = await makeRequest('/test')

      expect(body.meta.code).toBe('CREATED')
    })
  })

  describe('Edge Cases', (): void => {
    it('should handle null data correctly', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Success', undefined, null))
      const { body } = await makeRequest('/test')

      expect(body.data).toBeNull()
    })

    it('should handle undefined data correctly', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Success'))
      const { body } = await makeRequest('/test')

      expect(body.data).toBeNull()
    })

    it('should handle empty error array', async (): Promise<void> => {
      app.post('/test', (ctx: Context<Generics>) => httpResponse.badRequest(ctx, 'Error', []))
      const { body } = await makeRequest('/test', { method: 'POST' })

      expect(body.meta.errors).toBeUndefined()
    })

    it('should handle complex nested data', async (): Promise<void> => {
      const complexData = {
        user: {
          id: 1,
          profile: {
            name: 'Test',
            settings: { theme: 'dark' }
          }
        },
        items: [{ id: 1 }, { id: 2 }]
      }
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Success', undefined, complexData))
      const { body } = await makeRequest('/test')

      expect(body.data).toEqual(complexData)
    })

    it('should handle empty strings', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, '', undefined, ''))
      const { body } = await makeRequest('/test')

      expect(body.meta.message).toBe('')
      expect(body.data).toBe('')
    })
  })

  describe('Request Context', (): void => {
    it('should capture correct request path', async (): Promise<void> => {
      app.get('/api/users/123', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Success'))
      const { body } = await makeRequest('/api/users/123')

      expect(body.meta.path).toBe('/api/users/123')
    })

    it('should capture correct request method', async (): Promise<void> => {
      app.post('/test', (ctx: Context<Generics>) => httpResponse.created(ctx, 'Created'))
      const { body } = await makeRequest('/test', { method: 'POST' })

      expect(body.meta.method).toBe('POST')
    })

    it('should generate unique request IDs', async (): Promise<void> => {
      app.get('/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, 'Success'))

      const { body: body1 } = await makeRequest('/test')
      const { body: body2 } = await makeRequest('/test')

      expect(body1.meta.requestId).toBeTruthy()
      expect(body2.meta.requestId).toBeTruthy()
      expect(body1.meta.requestId).not.toBe(body2.meta.requestId)
    })

    it('should handle different HTTP methods correctly', async (): Promise<void> => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const

      for (const method of methods) {
        app.on([method], '/test', (ctx: Context<Generics>) => httpResponse.ok(ctx, `${method} success`))
      }

      for (const method of methods) {
        const { body } = await makeRequest('/test', { method })
        expect(body.meta.method).toBe(method)
      }
    })
  })
})
