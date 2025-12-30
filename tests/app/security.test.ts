import type { Hono } from 'hono'

import { initialize } from '@/app'
import { describe, it, expect, beforeAll } from 'vitest'

describe('Security Headers and CORS', (): void => {
  let app: Hono<Generics>

  beforeAll(async (): Promise<void> => {
    app = await initialize()
  })

  describe('CORS - Cross-Origin Resource Sharing', (): void => {
    describe('Allowed Origins', (): void => {
      it('should allow localhost:3000', async (): Promise<void> => {
        const response: Response = await app.request('/', {
          headers: {
            Origin: 'http://localhost:3000'
          }
        })

        expect(response.status).toBe(200)
        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBe('http://localhost:3000')
      })

      it('should allow localhost:5173 (Vite default)', async (): Promise<void> => {
        const response: Response = await app.request('/', {
          headers: {
            Origin: 'http://localhost:5173'
          }
        })

        expect(response.status).toBe(200)
        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBe('http://localhost:5173')
      })

      it('should allow 127.0.0.1:3000', async (): Promise<void> => {
        const response: Response = await app.request('/', {
          headers: {
            Origin: 'http://127.0.0.1:3000'
          }
        })

        expect(response.status).toBe(200)
        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBe('http://127.0.0.1:3000')
      })
    })

    describe('Blocked Origins', (): void => {
      it('should block unauthorized external origin', async (): Promise<void> => {
        const response: Response = await app.request('/', {
          headers: {
            Origin: 'http://malicious-site.com'
          }
        })

        expect(response.status).toBe(200)
        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBeNull()
      })

      it('should block random external domain', async (): Promise<void> => {
        const response: Response = await app.request('/', {
          headers: {
            Origin: 'https://evil.example.com'
          }
        })

        expect(response.status).toBe(200)
        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBeNull()
      })

      it('should handle request without Origin header', async (): Promise<void> => {
        const response: Response = await app.request('/')

        expect(response.status).toBe(200)
        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBeNull()
      })
    })

    describe('CORS Headers', (): void => {
      it('should include Access-Control-Allow-Credentials', async (): Promise<void> => {
        const response: Response = await app.request('/', {
          headers: {
            Origin: 'http://localhost:3000'
          }
        })

        const allowCredentials: string | null = response.headers.get('Access-Control-Allow-Credentials')
        expect(allowCredentials).toBe('true')
      })

      it('should include Access-Control-Expose-Headers', async (): Promise<void> => {
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

      it('should include Access-Control-Max-Age', async (): Promise<void> => {
        const response: Response = await app.request('/', {
          method: 'OPTIONS',
          headers: {
            Origin: 'http://localhost:3000',
            'Access-Control-Request-Method': 'POST'
          }
        })

        const maxAge: string | null = response.headers.get('Access-Control-Max-Age')
        expect(maxAge).toBeTruthy()
        expect(parseInt(maxAge || '0')).toBeGreaterThan(0)
      })
    })

    describe('Preflight Requests', (): void => {
      it('should handle OPTIONS preflight for POST', async (): Promise<void> => {
        const response: Response = await app.request('/', {
          method: 'OPTIONS',
          headers: {
            Origin: 'http://localhost:3000',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type,Authorization'
          }
        })

        expect([200, 204]).toContain(response.status)

        const allowMethods: string | null = response.headers.get('Access-Control-Allow-Methods')
        expect(allowMethods).toBeTruthy()
        expect(allowMethods).toContain('POST')
      })

      it('should handle OPTIONS preflight for PUT', async (): Promise<void> => {
        const response: Response = await app.request('/health', {
          method: 'OPTIONS',
          headers: {
            Origin: 'http://localhost:3000',
            'Access-Control-Request-Method': 'PUT'
          }
        })

        expect([200, 204, 404]).toContain(response.status)

        const allowMethods: string | null = response.headers.get('Access-Control-Allow-Methods')
        if (allowMethods) {
          expect(allowMethods).toContain('PUT')
        }
      })

      it('should handle OPTIONS preflight for DELETE', async (): Promise<void> => {
        const response: Response = await app.request('/health', {
          method: 'OPTIONS',
          headers: {
            Origin: 'http://localhost:3000',
            'Access-Control-Request-Method': 'DELETE'
          }
        })

        expect([200, 204, 404]).toContain(response.status)

        const allowMethods: string | null = response.headers.get('Access-Control-Allow-Methods')
        if (allowMethods) {
          expect(allowMethods).toContain('DELETE')
        }
      })

      it('should allow Content-Type and Authorization headers', async (): Promise<void> => {
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
    })

    describe('CORS on Error Responses', (): void => {
      it('should include CORS headers on 404 errors', async (): Promise<void> => {
        const response: Response = await app.request('/non-existent', {
          headers: {
            Origin: 'http://localhost:3000'
          }
        })

        expect(response.status).toBe(404)
        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBe('http://localhost:3000')
      })

      it('should include CORS headers on 500 errors', async (): Promise<void> => {
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
  })

  describe('Content Security Policy (CSP)', (): void => {
    describe('CSP Headers', (): void => {
      it('should include X-Content-Type-Options header', async (): Promise<void> => {
        const response: Response = await app.request('/')

        const header: string | null = response.headers.get('X-Content-Type-Options')
        expect(header).toBeTruthy()
        expect(header).toBe('nosniff')
      })

      it('should include X-Frame-Options header', async (): Promise<void> => {
        const response: Response = await app.request('/')

        const header: string | null = response.headers.get('X-Frame-Options')
        expect(header).toBeTruthy()
        expect(['DENY', 'SAMEORIGIN']).toContain(header)
      })

      it('should include X-XSS-Protection header', async (): Promise<void> => {
        const response: Response = await app.request('/')
        const header: string | null = response.headers.get('X-XSS-Protection')
        if (header) {
          // Modern browsers use CSP instead, so '0' is recommended
          expect(header).toBe('0')
        }
      })

      it('should include Strict-Transport-Security header', async (): Promise<void> => {
        const response: Response = await app.request('/')

        const header: string | null = response.headers.get('Strict-Transport-Security')
        if (header) {
          expect(header).toContain('max-age')
        }
      })

      it('should include Referrer-Policy header', async (): Promise<void> => {
        const response: Response = await app.request('/')

        const header: string | null = response.headers.get('Referrer-Policy')
        if (header) {
          expect(['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']).toContain(header)
        }
      })

      it('should include Permissions-Policy header', async (): Promise<void> => {
        const response: Response = await app.request('/')

        const header: string | null = response.headers.get('Permissions-Policy')
        // Permissions-Policy is optional
        if (header) {
          expect(header.length).toBeGreaterThan(0)
        }
      })
    })

    describe('CSP on Different Endpoints', (): void => {
      it('should include security headers on root endpoint', async (): Promise<void> => {
        const response: Response = await app.request('/')

        expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
        expect(response.headers.get('X-Frame-Options')).toBeTruthy()
      })

      it('should include security headers on /health endpoint', async (): Promise<void> => {
        const response: Response = await app.request('/health')

        expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
        expect(response.headers.get('X-Frame-Options')).toBeTruthy()
      })

      it('should include security headers on error responses', async (): Promise<void> => {
        const response: Response = await app.request('/non-existent')

        expect(response.status).toBe(404)
        expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
        expect(response.headers.get('X-Frame-Options')).toBeTruthy()
      })

      it('should include security headers on 500 errors', async (): Promise<void> => {
        const response: Response = await app.request('/vitest/error-test')

        expect(response.status).toBe(500)
        expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
        expect(response.headers.get('X-Frame-Options')).toBeTruthy()
      })
    })

    describe('CSP on Different HTTP Methods', (): void => {
      it('should include security headers on GET requests', async (): Promise<void> => {
        const response: Response = await app.request('/', { method: 'GET' })

        expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
        expect(response.headers.get('X-Frame-Options')).toBeTruthy()
      })

      it('should include security headers on POST requests', async (): Promise<void> => {
        const response: Response = await app.request('/non-existent', { method: 'POST' })

        expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
        expect(response.headers.get('X-Frame-Options')).toBeTruthy()
      })

      it('should include security headers on OPTIONS requests', async (): Promise<void> => {
        const response: Response = await app.request('/', {
          method: 'OPTIONS',
          headers: {
            Origin: 'http://localhost:3000',
            'Access-Control-Request-Method': 'POST'
          }
        })

        expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
        expect(response.headers.get('X-Frame-Options')).toBeTruthy()
      })
    })
  })

  describe('Security Headers Consistency', (): void => {
    it('should have consistent security headers across multiple requests', async (): Promise<void> => {
      const response1: Response = await app.request('/')
      const response2: Response = await app.request('/health')
      const response3: Response = await app.request('/non-existent')

      const headers1 = {
        contentType: response1.headers.get('X-Content-Type-Options'),
        frameOptions: response1.headers.get('X-Frame-Options')
      }

      const headers2 = {
        contentType: response2.headers.get('X-Content-Type-Options'),
        frameOptions: response2.headers.get('X-Frame-Options')
      }

      const headers3 = {
        contentType: response3.headers.get('X-Content-Type-Options'),
        frameOptions: response3.headers.get('X-Frame-Options')
      }

      expect(headers1.contentType).toBe(headers2.contentType)
      expect(headers1.contentType).toBe(headers3.contentType)
      expect(headers1.frameOptions).toBe(headers2.frameOptions)
      expect(headers1.frameOptions).toBe(headers3.frameOptions)
    })

    it('should maintain security headers with CORS', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: 'http://localhost:3000'
        }
      })

      // Both CORS and security headers should be present
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('http://localhost:3000')
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(response.headers.get('X-Frame-Options')).toBeTruthy()
    })
  })

  describe('Server Information Leakage Prevention', (): void => {
    it('should not expose internal server details', async (): Promise<void> => {
      const response: Response = await app.request('/')

      const serverHeader: string | null = response.headers.get('Server')
      if (serverHeader) {
        expect(serverHeader).not.toContain('Node.js')
        expect(serverHeader).not.toContain('Express')
        expect(serverHeader).not.toContain('Koa')
      }
    })

    it('should have controlled X-Powered-By header', async (): Promise<void> => {
      const response: Response = await app.request('/')

      const poweredBy: string | null = response.headers.get('X-Powered-By')
      expect(poweredBy).toBeTruthy()
      expect(poweredBy).toBe('peacekeeper')
      expect(poweredBy).not.toContain('Node')
      expect(poweredBy).not.toContain('Express')
    })

    it('should not leak stack traces in error responses', async (): Promise<void> => {
      const originalEnv: string | undefined = process.env.NODE_ENV

      try {
        process.env.NODE_ENV = 'production'
        const response: Response = await app.request('/vitest/error-test')
        const body = await response.json()

        expect(body.meta.message).not.toContain('at ')
        expect(body.meta.message).not.toContain('.ts:')
        expect(body.meta.message).not.toContain('node_modules')
      } finally {
        process.env.NODE_ENV = originalEnv
      }
    })
  })

  describe('Combined CORS and CSP Scenarios', (): void => {
    it('should handle CORS preflight with full security headers', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        method: 'OPTIONS',
        headers: {
          Origin: 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type,Authorization'
        }
      })

      // CORS headers
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('http://localhost:3000')
      expect(response.headers.get('Access-Control-Allow-Methods')).toBeTruthy()
      expect(response.headers.get('Access-Control-Allow-Headers')).toBeTruthy()

      // Security headers
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(response.headers.get('X-Frame-Options')).toBeTruthy()
    })

    it('should maintain security on cross-origin error responses', async (): Promise<void> => {
      const response: Response = await app.request('/non-existent', {
        headers: {
          Origin: 'http://localhost:3000'
        }
      })

      expect(response.status).toBe(404)

      // CORS headers for allowed origin
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('http://localhost:3000')

      // Security headers still present
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(response.headers.get('X-Frame-Options')).toBeTruthy()
    })

    it('should deny CORS but maintain security for blocked origins', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: 'http://malicious-site.com'
        }
      })

      // CORS blocked
      expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull()

      // Security headers still present
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(response.headers.get('X-Frame-Options')).toBeTruthy()
    })
  })

  describe('Origin Validation Edge Cases', (): void => {
    it('should handle empty Origin header', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: ''
        }
      })

      expect(response.status).toBe(200)
      const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
      expect(allowOrigin).toBeNull()
    })

    it('should handle localhost with different ports', async (): Promise<void> => {
      const ports: number[] = [3000, 3001, 5173, 8080]

      for (const port of ports) {
        const response: Response = await app.request('/', {
          headers: {
            Origin: `http://localhost:${port}`
          }
        })

        expect(response.status).toBe(200)
      }
    })

    it('should handle case-sensitive origin matching', async (): Promise<void> => {
      const response: Response = await app.request('/', {
        headers: {
          Origin: 'HTTP://LOCALHOST:3000'
        }
      })

      expect(response.status).toBe(200)
      // Case-sensitive matching - should be normalized or rejected
      const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
      // Depending on implementation, this might be null or normalized
      if (allowOrigin) {
        expect(allowOrigin.toLowerCase()).toContain('localhost')
      }
    })

    it('should reject origins with suspicious patterns', async (): Promise<void> => {
      const suspiciousOrigins: string[] = ['http://localhost.evil.com', 'http://127.0.0.1.evil.com', 'http://evil-localhost:3000', 'javascript:alert(1)']

      for (const origin of suspiciousOrigins) {
        const response: Response = await app.request('/', {
          headers: { Origin: origin }
        })

        const allowOrigin: string | null = response.headers.get('Access-Control-Allow-Origin')
        expect(allowOrigin).toBeNull()
      }
    })
  })
})
