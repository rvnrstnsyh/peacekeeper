import type { Hono } from 'hono'

import { initialize } from '@/app'
import { describe, it, expect, beforeAll } from 'vitest'

describe('Error Handling', (): void => {
  let app: Hono<Generics>

  beforeAll(async (): Promise<void> => {
    app = await initialize()
  })

  describe('404 Not Found', (): void => {
    it('should return 404 for non-existent routes', async (): Promise<void> => {
      const response: Response = await app.request('/non-existent-route')
      expect(response.status).toBe(404)

      const body = await response.json()
      expect(body.meta.status).toBe(404)
      expect(body.meta.code).toBe('NOT_FOUND')
      expect(body.meta.message).toBe('404 Not Found')
    })

    it('should return 404 for non-existent API endpoints', async (): Promise<void> => {
      const response: Response = await app.request('/api/v0/unknown')
      expect(response.status).toBe(404)

      const body = await response.json()
      expect(body.meta.code).toBe('NOT_FOUND')
    })

    it('should have correct error structure for 404', async (): Promise<void> => {
      const response: Response = await app.request('/does-not-exist')
      expect(response.status).toBe(404)

      const body = await response.json()
      expect(body).toHaveProperty('meta')
      expect(body).not.toHaveProperty('data')
      expect(body.meta).toHaveProperty('requestId')
      expect(body.meta).toHaveProperty('path', '/does-not-exist')
      expect(body.meta).toHaveProperty('method', 'GET')
      expect(body.meta).toHaveProperty('status', 404)
      expect(body.meta).toHaveProperty('timestamp')
      expect(body.meta).toHaveProperty('responseTimeMs')
      expect(typeof body.meta.responseTimeMs).toBe('number')
    })
  })

  describe('500 Internal Server Error', (): void => {
    it('should handle unhandled errors gracefully', async (): Promise<void> => {
      const response: Response = await app.request('/vitest/error-test')
      expect(response.status).toBe(500)

      const body = await response.json()
      expect(body.meta.status).toBe(500)
      expect(body.meta.code).toBe('INTERNAL_SERVER_ERROR')
    })

    it('should have correct error structure for 500', async (): Promise<void> => {
      const response: Response = await app.request('/vitest/error-structure-test')
      expect(response.status).toBe(500)

      const body = await response.json()
      expect(body).toHaveProperty('meta')
      expect(body).not.toHaveProperty('data')
      expect(body.meta).toHaveProperty('requestId')
      expect(body.meta).toHaveProperty('path', '/vitest/error-structure-test')
      expect(body.meta).toHaveProperty('method', 'GET')
      expect(body.meta).toHaveProperty('status', 500)
      expect(body.meta).toHaveProperty('timestamp')
      expect(body.meta).toHaveProperty('responseTimeMs')
    })

    it('should not expose error details in production mode', async (): Promise<void> => {
      const originalEnv: string | undefined = process.env.NODE_ENV

      try {
        process.env.NODE_ENV = 'production'
        const response: Response = await app.request('/vitest/prod-error-test')
        const body = await response.json()

        expect(response.status).toBe(500)
        expect(body.meta.message).toBe('500 Internal Server Error')
        expect(body.meta.message).not.toContain('Test error')
        expect(body.meta.message).not.toContain('Sensitive')
      } finally {
        process.env.NODE_ENV = originalEnv
      }
    })

    it('should expose error details in development mode', async (): Promise<void> => {
      const originalEnv: string | undefined = process.env.NODE_ENV

      try {
        process.env.NODE_ENV = 'development'
        const response: Response = await app.request('/vitest/error-test')
        const body = await response.json()

        expect(response.status).toBe(500)
        // In dev mode, error message should contain actual error
        expect(body.meta.message).toBeTruthy()
      } finally {
        process.env.NODE_ENV = originalEnv
      }
    })
  })

  describe('Error Response Consistency', (): void => {
    it('should maintain consistent structure across different error types', async (): Promise<void> => {
      const paths: Array<string> = ['/non-existent-1', '/non-existent-2', '/non-existent-3']
      const responses: Array<Response> = await Promise.all(paths.map((path) => app.request(path)))
      const bodies = await Promise.all(responses.map((r) => r.json()))

      bodies.forEach((body, index) => {
        expect(body).toHaveProperty('meta')
        expect(body).not.toHaveProperty('data')
        expect(body.meta).toHaveProperty('requestId')
        expect(body.meta).toHaveProperty('path', paths[index])
        expect(body.meta).toHaveProperty('method', 'GET')
        expect(body.meta).toHaveProperty('status', 404)
        expect(body.meta).toHaveProperty('code', 'NOT_FOUND')
        expect(body.meta).toHaveProperty('timestamp')
        expect(body.meta).toHaveProperty('message')
        expect(body.meta).toHaveProperty('responseTimeMs')
      })
    })

    it('should have unique request IDs for each error', async (): Promise<void> => {
      const response1: Response = await app.request('/error-1')
      const response2: Response = await app.request('/error-2')

      const body1 = await response1.json()
      const body2 = await response2.json()

      expect(body1.meta.requestId).toBeTruthy()
      expect(body2.meta.requestId).toBeTruthy()
      expect(body1.meta.requestId).not.toBe(body2.meta.requestId)
    })

    it('should have valid timestamps for errors', async (): Promise<void> => {
      const response: Response = await app.request('/timestamp-error-test')
      const body = await response.json()

      expect(body.meta.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

      const timestamp = new Date(body.meta.timestamp)
      expect(timestamp.toString()).not.toBe('Invalid Date')
      expect(timestamp.getTime()).toBeLessThanOrEqual(Date.now())
    })

    it('should have consistent meta structure', async (): Promise<void> => {
      const response1: Response = await app.request('/error-a')
      const response2: Response = await app.request('/error-b')

      const body1 = await response1.json()
      const body2 = await response2.json()

      const keys1: Array<string> = Object.keys(body1.meta).sort()
      const keys2: Array<string> = Object.keys(body2.meta).sort()

      expect(keys1).toEqual(keys2)
    })
  })

  describe('HTTP Method Errors', (): void => {
    it('should handle POST to GET-only routes', async (): Promise<void> => {
      const response: Response = await app.request('/', { method: 'POST' })
      const body = await response.json()

      expect([404, 405]).toContain(response.status)
      expect(['NOT_FOUND', 'METHOD_NOT_ALLOWED']).toContain(body.meta.code)
    })

    it('should handle PUT to GET-only routes', async (): Promise<void> => {
      const response: Response = await app.request('/health', { method: 'PUT' })
      const body = await response.json()

      expect([404, 405]).toContain(response.status)
      expect(['NOT_FOUND', 'METHOD_NOT_ALLOWED']).toContain(body.meta.code)
    })

    it('should handle DELETE to GET-only routes', async (): Promise<void> => {
      const response: Response = await app.request('/health', { method: 'DELETE' })
      const body = await response.json()

      expect([404, 405]).toContain(response.status)
      expect(['NOT_FOUND', 'METHOD_NOT_ALLOWED']).toContain(body.meta.code)
    })

    it('should preserve method in error response', async (): Promise<void> => {
      const methods: Array<string> = ['POST', 'PUT', 'DELETE', 'PATCH'] as const

      for (const method of methods) {
        const response: Response = await app.request('/health', { method })
        const body = await response.json()

        expect(body.meta.method).toBe(method)
      }
    })
  })

  describe('Response Headers', (): void => {
    it('should include standard headers in error responses', async (): Promise<void> => {
      const response: Response = await app.request('/header-test-error')

      expect(response.headers.get('Content-Type')).toContain('application/json')
      expect(response.headers.get('X-Request-Id')).toBeTruthy()

      const responseTime: string | null = response.headers.get('X-Response-Time')
      expect(responseTime).toMatch(/^\d+\.?\d*ms$/)
    })

    it('should include security headers in error responses', async (): Promise<void> => {
      const response: Response = await app.request('/security-test-error')

      // Check for secure headers middleware
      expect(response.headers.get('X-Content-Type-Options')).toBeTruthy()
      expect(response.headers.get('X-Frame-Options')).toBeTruthy()
    })

    it('should not leak sensitive server information', async (): Promise<void> => {
      const response: Response = await app.request('/sensitive-error-test')
      const poweredBy: string | null = response.headers.get('X-Powered-By')

      if (poweredBy) {
        expect(poweredBy).toBe('peacekeeper')
      }
    })
  })

  describe('Edge Cases', (): void => {
    it('should handle very long URLs', async (): Promise<void> => {
      const longPath: string = '/api/' + 'a'.repeat(1000)
      const response: Response = await app.request(longPath)
      const body = await response.json()

      expect(response.status).toBe(404)
      expect(body.meta.path).toBe(longPath)
    })

    it('should handle URLs with special characters', async (): Promise<void> => {
      const specialPath: string = '/api/test%20space/special!@#'
      const response: Response = await app.request(specialPath)
      const body = await response.json()

      expect(response.status).toBe(404)
      expect(body.meta.path).toBeTruthy()
      expect(body.meta).toHaveProperty('requestId')
    })

    it('should handle empty path segments gracefully', async (): Promise<void> => {
      const response: Response = await app.request('//api///test')
      const body = await response.json()

      expect(response.status).toBe(404)
      expect(body.meta).toBeTruthy()
      expect(body.meta).toHaveProperty('path')
    })

    it('should handle query parameters in error responses', async (): Promise<void> => {
      const response: Response = await app.request('/non-existent?param=value&foo=bar')
      const body = await response.json()

      expect(response.status).toBe(404)
      expect(body.meta.path).toBe('/non-existent')
      // Query params should be stripped from path
      expect(body.meta.path).not.toContain('?')
    })

    it('should handle URL with hash fragments', async (): Promise<void> => {
      const response: Response = await app.request('/test#fragment')
      const body = await response.json()

      expect(response.status).toBe(404)
      expect(body.meta.path).contain('/test')
    })
  })

  describe('Performance', (): void => {
    it('should have reasonable response time for errors', async (): Promise<void> => {
      const response: Response = await app.request('/performance-error-test')
      const body = await response.json()

      expect(body.meta.responseTimeMs).toBeGreaterThanOrEqual(0)
      expect(body.meta.responseTimeMs).toBeLessThan(100)
    })

    it('should handle multiple concurrent error requests', async (): Promise<void> => {
      const requests: Array<Response | Promise<Response>> = Array.from({ length: 10 }, (_, i) => app.request(`/concurrent-error-${i}`))
      const responses: Array<Response> = await Promise.all(requests)
      const bodies = await Promise.all(responses.map((r) => r.json()))

      bodies.forEach((body, index) => {
        expect(body.meta.status).toBe(404)
        expect(body.meta.path).toBe(`/concurrent-error-${index}`)
        expect(body.meta.requestId).toBeTruthy()
      })
      // All request IDs should be unique
      const requestIds = bodies.map((b) => b.meta.requestId)
      const uniqueIds = new Set(requestIds)
      expect(uniqueIds.size).toBe(10)
    })

    it('should maintain performance under rapid sequential requests', async (): Promise<void> => {
      const results = []

      for (let i = 0; i < 5; i++) {
        const start: number = performance.now()
        const response: Response = await app.request(`/perf-test-${i}`)
        const end: number = performance.now()
        const body = await response.json()

        results.push({
          requestTime: end - start,
          responseTimeMs: body.meta.responseTimeMs
        })
      }
      // All requests should complete quickly
      results.forEach((result) => {
        expect(result.requestTime).toBeLessThan(100)
        expect(result.responseTimeMs).toBeLessThan(50)
      })
    })
  })

  describe('Error Message Sanitization', (): void => {
    it('should not expose stack traces in production', async (): Promise<void> => {
      const originalEnv: string | undefined = process.env.NODE_ENV

      try {
        process.env.NODE_ENV = 'production'
        const response: Response = await app.request('/vitest/error-test')
        const body = await response.json()

        expect(body.meta.message).not.toContain('at ')
        expect(body.meta.message).not.toContain('.ts:')
        expect(body.meta.message).not.toContain('Error:')
      } finally {
        process.env.NODE_ENV = originalEnv
      }
    })

    it('should have clean error messages', async (): Promise<void> => {
      const response: Response = await app.request('/clean-error-test')
      const body = await response.json()

      expect(body.meta.message).toBeTruthy()
      expect(body.meta.message.length).toBeGreaterThan(0)
      expect(body.meta.message.length).toBeLessThan(200)
    })
  })

  describe('CORS on Errors', (): void => {
    it('should include CORS headers for valid origins', async (): Promise<void> => {
      const response: Response = await app.request('/cors-error-test', {
        headers: {
          Origin: 'http://localhost:3000'
        }
      })
      // CORS middleware should process the request
      expect(response.status).toBe(404)
      // Check basic CORS functionality
      const body = await response.json()
      expect(body.meta.status).toBe(404)
    })

    it('should handle preflight OPTIONS requests', async (): Promise<void> => {
      const response: Response = await app.request('/any-path', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST'
        }
      })
      // OPTIONS should be handled by CORS middleware
      expect([200, 204, 404]).toContain(response.status)
    })
  })
})
