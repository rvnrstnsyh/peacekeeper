import type { Hono } from 'hono'
import type { RouteMetrics, VersionInfo } from '@/shared/core/router-factory.core'

import { initialize } from '@/app'
import { routerFactory } from '@/shared/core/router-factory.core'
import { describe, it, expect, beforeAll, afterEach } from 'vitest'
import { validateSuccessResponse, validateErrorResponse, validateResponseHeaders, validateUniqueRequestIds, createResponseValidator } from '!/helpers/common'

describe('Health Endpoints', (): void => {
  let app: Hono<Generics>

  beforeAll(async (): Promise<void> => {
    app = await initialize()
  })

  afterEach((): void => {
    routerFactory.clearCache()
  })

  describe('GET /', (): void => {
    it('should return API gateway information with correct structure', async (): Promise<void> => {
      const res = await app.request('/')
      expect(res.status).toBe(200)

      const body = await res.json()
      validateSuccessResponse(body, '/', 200, 'OK', { checkData: true })
      validateResponseHeaders(res)
    })

    it('should have all required gateway information fields', async (): Promise<void> => {
      const res = await app.request('/')
      const body = await res.json()

      expect(body.data).toHaveProperty('name')
      expect(body.data).toHaveProperty('version')
      expect(body.data).toHaveProperty('status', 'Online')
      expect(body.data).toHaveProperty('uptimeMs')
      expect(body.data).toHaveProperty('hostname')
      expect(body.data).toHaveProperty('port')
      expect(body.data).toHaveProperty('environment')
      expect(body.data).toHaveProperty('apiVersions')
      expect(body.data).toHaveProperty('statistics')
      expect(body.data).toHaveProperty('systemEndpoints')
    })

    it('should have valid apiVersions array structure', async (): Promise<void> => {
      const res = await app.request('/')
      const body = await res.json()

      expect(Array.isArray(body.data.apiVersions)).toBe(true)

      // Test structure if versions exist
      if (body.data.apiVersions.length > 0) {
        const firstVersion = body.data.apiVersions[0]
        expect(firstVersion).toHaveProperty('version')
        expect(firstVersion).toHaveProperty('prefix')
        expect(firstVersion).toHaveProperty('routes')
        expect(firstVersion).toHaveProperty('deprecated')

        expect(typeof firstVersion.version).toBe('string')
        expect(typeof firstVersion.prefix).toBe('string')
        expect(typeof firstVersion.routes).toBe('number')
        expect(typeof firstVersion.deprecated).toBe('boolean')
        expect(firstVersion.routes).toBeGreaterThanOrEqual(0)
      }
    })

    it('should have valid statistics structure', async (): Promise<void> => {
      const res = await app.request('/')
      const body = await res.json()

      expect(body.data.statistics).toHaveProperty('totalRoutes')
      expect(body.data.statistics).toHaveProperty('preloadedRoutes')

      expect(typeof body.data.statistics.totalRoutes).toBe('number')
      expect(typeof body.data.statistics.preloadedRoutes).toBe('number')

      expect(body.data.statistics.totalRoutes).toBeGreaterThanOrEqual(0)
      expect(body.data.statistics.preloadedRoutes).toBeGreaterThanOrEqual(0)
      expect(body.data.statistics.preloadedRoutes).toBeLessThanOrEqual(body.data.statistics.totalRoutes)
    })

    it('should have system endpoints configuration', async (): Promise<void> => {
      const res = await app.request('/')
      const body = await res.json()

      expect(body.data.systemEndpoints).toHaveProperty('health', '/health')
      expect(typeof body.data.systemEndpoints.health).toBe('string')
    })

    it('should have positive numeric uptimeMs', async (): Promise<void> => {
      const res = await app.request('/')
      const body = await res.json()

      expect(typeof body.data.uptimeMs).toBe('number')
      expect(body.data.uptimeMs).toBeGreaterThan(0)
      expect(body.data.uptimeMs).toBeLessThan(Number.MAX_SAFE_INTEGER)
    })

    it('should have valid server configuration', async (): Promise<void> => {
      const res = await app.request('/')
      const body = await res.json()

      // Hostname validation
      expect(typeof body.data.hostname).toBe('string')
      expect(body.data.hostname.length).toBeGreaterThan(0)

      // Port validation
      expect(typeof body.data.port).toBe('number')
      expect(body.data.port).toBeGreaterThan(0)
      expect(body.data.port).toBeLessThan(65536)

      // Environment validation
      expect(['development', 'test', 'production']).toContain(body.data.environment)
    })

    it('should have consistent response structure on multiple calls', async (): Promise<void> => {
      const responses = await Promise.all([app.request('/'), app.request('/'), app.request('/')])

      expect(responses).toHaveLength(3)
      responses.forEach((res) => expect(res.status).toBe(200))

      const bodies = await Promise.all(responses.map((r) => r.json()))

      // Validate all responses
      bodies.forEach((body) => {
        validateSuccessResponse(body, '/', 200, 'OK', { checkData: true })
      })

      // Ensure unique request IDs
      validateUniqueRequestIds(bodies)

      // Check structure consistency
      const keys1 = Object.keys(bodies[0].data).sort()
      const keys2 = Object.keys(bodies[1].data).sort()
      const keys3 = Object.keys(bodies[2].data).sort()

      expect(keys1).toEqual(keys2)
      expect(keys2).toEqual(keys3)
    })

    it('should return valid JSON content type', async (): Promise<void> => {
      const res = await app.request('/')
      const contentType = res.headers.get('Content-Type')

      expect(contentType).toBeTruthy()
      expect(contentType).toContain('application/json')
    })

    it('should include response time in acceptable range', async (): Promise<void> => {
      const res = await app.request('/')
      const body = await res.json()

      expect(body.meta.responseTimeMs).toBeGreaterThanOrEqual(0)
      expect(body.meta.responseTimeMs).toBeLessThan(1000)
    })
  })

  describe('GET /health', (): void => {
    it('should return health check with correct structure', async (): Promise<void> => {
      const res = await app.request('/health')
      expect(res.status).toBe(200)

      const body = await res.json()
      validateSuccessResponse(body, '/health', 200, 'OK', { checkData: true })
      validateResponseHeaders(res)
      expect(body.meta.message).toBe('Route metrics')
    })

    it('should have versions information', async (): Promise<void> => {
      const res = await app.request('/health')
      const body = await res.json()

      expect(body.data).toHaveProperty('versions')
      expect(Array.isArray(body.data.versions)).toBe(true)

      body.data.versions.forEach((version: VersionInfo) => {
        expect(version).toHaveProperty('version')
        expect(version).toHaveProperty('prefix')
        expect(version).toHaveProperty('routes')
        expect(version).toHaveProperty('deprecated')

        expect(typeof version.version).toBe('string')
        expect(typeof version.prefix).toBe('string')
        expect(typeof version.routes).toBe('number')
        expect(typeof version.deprecated).toBe('boolean')

        expect(version.routes).toBeGreaterThanOrEqual(0)
      })
    })

    it('should have metrics information', async (): Promise<void> => {
      const res = await app.request('/health')
      const body = await res.json()

      expect(body.data).toHaveProperty('metrics')
      expect(body.data.metrics).toHaveProperty('total')
      expect(body.data.metrics).toHaveProperty('slowestRoutes')

      expect(typeof body.data.metrics.total).toBe('number')
      expect(body.data.metrics.total).toBeGreaterThanOrEqual(0)
      expect(Array.isArray(body.data.metrics.slowestRoutes)).toBe(true)
    })

    it('should have valid slowest routes structure', async (): Promise<void> => {
      const res = await app.request('/health')
      const body = await res.json()

      body.data.metrics.slowestRoutes.forEach((route: RouteMetrics) => {
        expect(route).toHaveProperty('path')
        expect(route).toHaveProperty('loadTimeMs')
        expect(route).toHaveProperty('accessCount')

        expect(typeof route.path).toBe('string')
        expect(typeof route.loadTimeMs).toBe('number')
        expect(typeof route.accessCount).toBe('number')

        expect(route.path.length).toBeGreaterThan(0)
        expect(route.loadTimeMs).toBeGreaterThanOrEqual(0)
        expect(route.accessCount).toBeGreaterThanOrEqual(0)
      })
    })

    it('should limit slowest routes to 10 or less', async (): Promise<void> => {
      const res = await app.request('/health')
      const body = await res.json()

      expect(body.data.metrics.slowestRoutes.length).toBeLessThanOrEqual(10)
    })

    it('should have consistent metrics data', async (): Promise<void> => {
      const res = await app.request('/health')
      const body = await res.json()

      const totalRoutes = body.data.metrics.total
      const slowestRoutesCount = body.data.metrics.slowestRoutes.length

      expect(slowestRoutesCount).toBeLessThanOrEqual(totalRoutes)
      expect(slowestRoutesCount).toBeLessThanOrEqual(10)
    })

    it('should return consistent data on multiple calls', async (): Promise<void> => {
      const res1 = await app.request('/health')
      const res2 = await app.request('/health')

      const body1 = await res1.json()
      const body2 = await res2.json()

      // Structure should be the same
      expect(Object.keys(body1.data).sort()).toEqual(Object.keys(body2.data).sort())

      // Request IDs should be different
      expect(body1.meta.requestId).not.toBe(body2.meta.requestId)
    })
  })

  describe('Error Handling', (): void => {
    it('should return 404 for non-existent routes with correct structure', async (): Promise<void> => {
      const res = await app.request('/non-existent-route')
      expect(res.status).toBe(404)

      const body = await res.json()
      validateErrorResponse(body, '/non-existent-route', 404, 'NOT_FOUND')
      validateResponseHeaders(res)
    })

    it('should handle multiple 404 errors consistently', async (): Promise<void> => {
      const paths = ['/error1', '/error2', '/error3']
      const responses = await Promise.all(paths.map((path) => app.request(path)))

      expect(responses).toHaveLength(3)
      responses.forEach((res) => expect(res.status).toBe(404))

      const bodies = await Promise.all(responses.map((r) => r.json()))

      bodies.forEach((body, index) => {
        validateErrorResponse(body, paths[index], 404, 'NOT_FOUND')
      })

      validateUniqueRequestIds(bodies)
    })

    it('should return proper structure for different HTTP methods on non-existent routes', async (): Promise<void> => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE'] as const

      for (const method of methods) {
        const res = await app.request('/non-existent', { method })
        const body = await res.json()

        expect(res.status).toBeGreaterThanOrEqual(400)
        expect(body).toHaveProperty('meta')
        expect(body.meta).toHaveProperty('status')
        expect(body.meta).toHaveProperty('code')
        expect(body.meta.method).toBe(method)
      }
    })

    it('should not include data property in error responses', async (): Promise<void> => {
      const res = await app.request('/not-found-test')
      const body = await res.json()

      expect(body).not.toHaveProperty('data')
      expect(body).toHaveProperty('meta')
    })
  })

  describe('Response Performance', (): void => {
    it('should respond quickly to root endpoint', async (): Promise<void> => {
      const start = performance.now()
      const res = await app.request('/')
      const end = performance.now()

      const body = await res.json()

      expect(end - start).toBeLessThan(200) // Total time < 200ms
      expect(body.meta.responseTimeMs).toBeLessThan(100) // Server time < 100ms
    })

    it('should respond quickly to health endpoint', async (): Promise<void> => {
      const start = performance.now()
      const res = await app.request('/health')
      const end = performance.now()

      const body = await res.json()

      expect(end - start).toBeLessThan(200)
      expect(body.meta.responseTimeMs).toBeLessThan(100)
    })

    it('should handle concurrent requests efficiently', async (): Promise<void> => {
      const start = performance.now()

      const requests = Array(10)
        .fill(null)
        .map((): Response | Promise<Response> => app.request('/'))
      const responses = await Promise.all(requests)

      const end = performance.now()

      expect(responses).toHaveLength(10)
      responses.forEach((res) => expect(res.status).toBe(200))
      expect(end - start).toBeLessThan(500) // All 10 requests < 500ms
    })
  })

  describe('Custom Validator Usage', (): void => {
    it('should validate root endpoint using custom validator', async (): Promise<void> => {
      const validator = createResponseValidator('/', 'GET')
      const res = await app.request('/')
      const body = await res.json()

      validator.validateSuccess(body, 200, 'OK', { checkData: true })
      validator.validateMeta(body.meta)
    })

    it('should validate health endpoint using custom validator', async (): Promise<void> => {
      const validator = createResponseValidator('/health', 'GET')
      const res = await app.request('/health')
      const body = await res.json()

      validator.validateSuccess(body, 200, 'OK', { checkData: true })
      validator.validateMeta(body.meta)
    })

    it('should validate 404 error using custom validator', async (): Promise<void> => {
      const validator = createResponseValidator('/not-found', 'GET')
      const res = await app.request('/not-found')
      const body = await res.json()

      validator.validateError(body, 404, 'NOT_FOUND')
      validator.validateMeta(body.meta)
    })

    it('should validate POST request using custom validator', async (): Promise<void> => {
      const validator = createResponseValidator('/not-found', 'POST')
      const res = await app.request('/not-found', { method: 'POST' })
      const body = await res.json()

      expect(body.meta.method).toBe('POST')
      validator.validateMeta(body.meta)
    })
  })

  describe('Response Headers Validation', (): void => {
    it('should include all standard headers', async (): Promise<void> => {
      const res = await app.request('/')

      expect(res.headers.get('Content-Type')).toContain('application/json')
      expect(res.headers.get('X-Request-Id')).toBeTruthy()
      expect(res.headers.get('X-Response-Time')).toMatch(/^\d+\.?\d*ms$/)
    })

    it('should include security headers', async (): Promise<void> => {
      const res = await app.request('/')

      // Security headers from secureHeaders middleware
      expect(res.headers.get('X-Content-Type-Options')).toBeTruthy()
      expect(res.headers.get('X-Frame-Options')).toBeTruthy()
    })

    it('should include powered by header', async (): Promise<void> => {
      const res = await app.request('/')
      const poweredBy = res.headers.get('X-Powered-By')

      expect(poweredBy).toBeTruthy()
    })
  })

  describe('Data Validation', (): void => {
    it('should return valid uptime calculation', async (): Promise<void> => {
      const res1 = await app.request('/')
      const body1 = await res1.json()

      // Wait a bit
      await new Promise((resolve) => setTimeout(resolve, 100))

      const res2 = await app.request('/')
      const body2 = await res2.json()

      // Second uptime should be greater than or equal to first
      expect(body2.data.uptimeMs).toBeGreaterThanOrEqual(body1.data.uptimeMs)
    })

    it('should return consistent server info', async (): Promise<void> => {
      const res1 = await app.request('/')
      const res2 = await app.request('/')

      const body1 = await res1.json()
      const body2 = await res2.json()

      expect(body1.data.name).toBe(body2.data.name)
      expect(body1.data.version).toBe(body2.data.version)
      expect(body1.data.hostname).toBe(body2.data.hostname)
      expect(body1.data.port).toBe(body2.data.port)
      expect(body1.data.environment).toBe(body2.data.environment)
    })
  })
})
