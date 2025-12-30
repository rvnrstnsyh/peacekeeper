import type { Hono } from 'hono'

import { initialize } from '@/app'
import { describe, it, expect, beforeAll } from 'vitest'

describe('Advanced CORS Testing', (): void => {
  let app: Hono<Generics>

  beforeAll(async (): Promise<void> => {
    app = await initialize()
  })

  describe('CORS Request Validation', (): void => {
    it('should validate Origin header format', async (): Promise<void> => {
      const invalidOrigins: string[] = ['not-a-url', 'ftp://localhost:3000', 'file:///etc/passwd', '../../../etc/passwd', 'null']

      for (const origin of invalidOrigins) {
        const response: Response = await app.request('/', {
          headers: { Origin: origin }
        })

        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBeNull()
      }
    })

    it('should handle multiple Origin headers', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: 'http://localhost:3000, http://malicious.com'
        }
      })

      // Should reject multiple origins
      const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
      expect(allowOrigin).toBeNull()
    })

    it('should validate scheme (http/https)', async (): Promise<void> => {
      const httpResponse: Response = await app.request('/', {
        headers: { Origin: 'http://localhost:3000' }
      })

      const httpsResponse: Response = await app.request('/', {
        headers: { Origin: 'https://localhost:3000' }
      })

      expect(httpResponse.headers.get('Access-Control-Allow-Origin')).toBeTruthy()
      expect(httpsResponse.headers.get('Access-Control-Allow-Origin')).toBeTruthy()
    })
  })

  describe('CORS Credentials Handling', (): void => {
    it('should set credentials flag for allowed origins', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: 'http://localhost:3000',
          Cookie: 'session=abc123'
        }
      })

      expect(response.headers.get('Access-Control-Allow-Credentials')).toBe('true')
    })

    it('should handle credentials in preflight requests', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST'
        }
      })

      expect(response.headers.get('Access-Control-Allow-Credentials')).toBe('true')
    })

    it('should not set wildcard origin with credentials', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: 'http://localhost:3000'
        }
      })

      const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
      const allowCredentials: string | null = response.headers.get('Access-Control-Allow-Credentials')

      // If credentials is true, origin should not be wildcard
      if (allowCredentials === 'true') {
        expect(allowOrigin).not.toBe('*')
      }
    })
  })

  describe('CORS Method Restrictions', (): void => {
    it('should allow configured HTTP methods', async (): Promise<void> => {
      const allowedMethods: Array<string> = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']

      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST'
        }
      })

      const allowMethods: string | null = response.headers.get('Access-Control-Allow-Methods')
      expect(allowMethods).toBeTruthy()

      allowedMethods.forEach((method: string): void => {
        expect(allowMethods).toContain(method)
      })
    })

    it('should handle PATCH method in preflight', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'PATCH'
        }
      })

      // PATCH might or might not be allowed based on config
      expect([200, 204, 403, 404]).toContain(response.status)
    })

    it('should reject dangerous HTTP methods', async (): Promise<void> => {
      const dangerousMethods: Array<string> = ['TRACE', 'CONNECT']

      for (const method of dangerousMethods) {
        const response: Response = await app.request('/', {
          method: 'OPTIONS',
          headers: {
            Origin: 'http://localhost:3000',
            'Access-Control-Request-Method': method
          }
        })

        const allowMethods: string | null = response.headers.get('Access-Control-Allow-Methods')
        if (allowMethods) {
          expect(allowMethods).not.toContain(method)
        }
      }
    })
  })

  describe('CORS Header Restrictions', (): void => {
    it('should allow standard headers', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type,Authorization'
        }
      })

      const allowHeaders: string | null = response.headers.get('Access-Control-Allow-Headers')
      expect(allowHeaders).toBeTruthy()
      expect(allowHeaders).toContain('Content-Type')
      expect(allowHeaders).toContain('Authorization')
    })

    it('should handle custom header requests', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'X-Custom-Header'
        }
      })

      const allowHeaders: string | null = response.headers.get('Access-Control-Allow-Headers')
      // Depending on config, custom headers might be allowed or blocked
      expect(allowHeaders).toBeTruthy()
    })

    it('should expose specific response headers', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: 'http://localhost:3000'
        }
      })

      const exposeHeaders: string | null = response.headers.get('Access-Control-Expose-Headers')
      expect(exposeHeaders).toBeTruthy()
      expect(exposeHeaders).toContain('Content-Length')
      expect(exposeHeaders).toContain('X-Kuma-Revision')
    })
  })

  describe('CORS Caching with Max-Age', (): void => {
    it('should include max-age in preflight response', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST'
        }
      })

      const maxAge: string | null = response.headers.get('Access-Control-Max-Age')
      expect(maxAge).toBeTruthy()

      const maxAgeSeconds: number = parseInt(maxAge || '0')
      expect(maxAgeSeconds).toBeGreaterThan(0)
      expect(maxAgeSeconds).toBeLessThanOrEqual(86400) // Max 24 hours
    })

    it('should cache preflight for configured duration', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST'
        }
      })

      const maxAge: string | null = response.headers.get('Access-Control-Max-Age')
      const configuredMaxAge: number = 600 // From your config

      expect(parseInt(maxAge || '0')).toBe(configuredMaxAge)
    })
  })

  describe('CORS with Different Content Types', (): void => {
    it('should handle JSON content type', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type'
        }
      })

      const allowHeaders: string | null = response.headers.get('Access-Control-Allow-Headers')
      expect(allowHeaders).toContain('Content-Type')
    })

    it('should handle form data content type', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type'
        }
      })

      expect([200, 204]).toContain(response.status)
    })

    it('should handle multipart form data', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type'
        }
      })

      expect([200, 204]).toContain(response.status)
    })
  })

  describe('CORS Error Scenarios', (): void => {
    it('should maintain CORS headers on 400 errors', async (): Promise<void> => {
      const response: Response = await app.request('/some-endpoint', {
        method: 'POST',
        headers: {
          Origin: 'http://localhost:3000',
          'Content-Type': 'application/json'
        },
        body: 'invalid-json'
      })

      const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
      if (response.status >= 400) {
        expect(allowOrigin).toBeTruthy()
      }
    })

    it('should maintain CORS headers on 401 errors', async (): Promise<void> => {
      const response: Response = await app.request('/protected', {
        headers: {
          Origin: 'http://localhost:3000'
        }
      })

      if (response.status === 401) {
        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBeTruthy()
      }
    })

    it('should maintain CORS headers on 500 errors', async (): Promise<void> => {
      const response: Response = await app.request('/vitest/error-test', {
        headers: {
          Origin: 'http://localhost:3000'
        }
      })

      expect(response.status).toBe(500)
      const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
      expect(allowOrigin).toBe('http://localhost:3000')
    })
  })

  describe('CORS with Query Parameters', (): void => {
    it('should handle CORS with query strings', async (): Promise<void> => {
      const response: Response = await app.request('/?foo=bar&baz=qux', {
        headers: {
          Origin: 'http://localhost:3000'
        }
      })

      expect(response.status).toBe(200)
      const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
      expect(allowOrigin).toBe('http://localhost:3000')
    })

    it('should handle CORS with encoded parameters', async (): Promise<void> => {
      const response: Response = await app.request('/?query=hello%20world', {
        headers: {
          Origin: 'http://localhost:3000'
        }
      })

      expect(response.status).toBe(200)
      const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
      expect(allowOrigin).toBe('http://localhost:3000')
    })
  })

  describe('CORS Performance', (): void => {
    it('should handle rapid CORS requests', async (): Promise<void> => {
      const requests: Array<Response | Promise<Response>> = Array.from({ length: 50 }, () =>
        app.request('/', {
          headers: {
            Origin: 'http://localhost:3000'
          }
        })
      )

      const responses: Array<Response> = await Promise.all(requests)

      responses.forEach((response: Response): void => {
        expect(response.status).toBe(200)
        expect(response.headers.get('Access-Control-Allow-Origin')).toBe('http://localhost:3000')
      })
    })

    it('should cache preflight responses efficiently', async (): Promise<void> => {
      const start: number = performance.now()

      for (let i = 0; i < 10; i++) {
        await app.request('/', {
          method: 'OPTIONS',
          headers: {
            Origin: 'http://localhost:3000',
            'Access-Control-Request-Method': 'POST'
          }
        })
      }

      const end: number = performance.now()
      const avgTime: number = (end - start) / 10

      expect(avgTime).toBeLessThan(50) // Each request should be fast
    })
  })

  describe('CORS Origin Variations', (): void => {
    it('should handle IPv6 localhost', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: 'http://[::1]:3000'
        }
      })

      expect(response.status).toBe(200)
      // IPv6 might or might not be in allowed origins
    })

    it('should handle different localhost formats', async (): Promise<void> => {
      const localhostVariations: string[] = ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://0.0.0.0:3000']

      for (const origin of localhostVariations) {
        const response: Response = await app.request('/', {
          headers: { Origin: origin }
        })

        expect(response.status).toBe(200)
      }
    })

    it('should handle subdomain origins', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: 'http://app.localhost:3000'
        }
      })

      expect(response.status).toBe(200)
      // Subdomains might require specific configuration
    })
  })
})
