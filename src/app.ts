import logger from '@/config/logger'
import httpResponse from '@/shared/utils/http-response'

import type { Context, Next } from 'hono'
import type { RouteMetrics, VersionInfo } from '@/shared/core/router-factory.core'

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { etag } from 'hono/etag'
import { timeout } from 'hono/timeout'
import { compress } from 'hono/compress'
import { env } from '@/config/environment'
import { requestId } from 'hono/request-id'
import { poweredBy } from 'hono/powered-by'
import { prettyJSON } from 'hono/pretty-json'
import { startTime, timing } from 'hono/timing'
import { secureHeaders } from 'hono/secure-headers'
import { contextStorage } from 'hono/context-storage'
import { allowedOrigins } from '@/shared/utils/common'
import { trimTrailingSlash } from 'hono/trailing-slash'
import { registerEndpoints } from '@/infra/http/endpoints'
import { routerFactory } from '@/shared/core/router-factory.core'
import { honoLogger } from '@/shared/middlewares/logger.middleware'

const app: Hono<Generics> = new Hono<Generics>()

/**
 * Internal initialization guard
 */
let initPromise: Promise<void> | null = null

/**
 * Initialize Hono application (idempotent)
 *
 * - Safe for production
 * - Deterministic for tests
 * - No infrastructure side-effects
 */
export async function initialize(): Promise<Hono<Generics>> {
  if (initPromise) {
    await initPromise
    return app
  }

  initPromise = (async (): Promise<void> => {
    if (env.isDevelopment) {
      app.use(prettyJSON())
    }
    // CRITICAL: Apply Security Headers FIRST (before CORS)
    // This ensures they are present on ALL responses including OPTIONS
    app
      .use(poweredBy({ serverName: 'peacekeeper' }))
      .use(secureHeaders())
      // CRITICAL: Apply CORS AFTER Security Headers
      .use(
        '*',
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
      .get('/', (ctx: Context<Generics>): Response => {
        const versions: VersionInfo[] = routerFactory.getVersionsInfo()
        const metrics: RouteMetrics[] = routerFactory.getMetrics()

        return httpResponse.ok(ctx, 'API Gateway', undefined, {
          name: env.APP_NAME,
          version: env.APP_VERSION,
          status: 'Online',
          uptimeMs: parseFloat((process.uptime() * 1000).toFixed(2)),
          hostname: env.APP_HOSTNAME,
          port: env.APP_PORT,
          environment: env.NODE_ENV,
          apiVersions: versions.map((info) => ({
            version: info.version,
            prefix: info.prefix,
            routes: info.routes,
            deprecated: info.deprecated,
            ...(info.sunsetDate && { sunsetDate: info.sunsetDate })
          })),
          statistics: {
            totalRoutes: metrics.length,
            preloadedRoutes: metrics.filter((m) => m.loadTimeMs > 0).length
          },
          systemEndpoints: {
            health: '/health'
          }
        })
      })
      .get('/health', (ctx: Context<Generics>): Response => {
        const versions: VersionInfo[] = routerFactory.getVersionsInfo()
        const metrics: RouteMetrics[] = routerFactory.getMetrics()
        const slowest: RouteMetrics[] = routerFactory.getSlowestRoutes(10)

        return httpResponse.ok(ctx, 'Route metrics', undefined, {
          versions,
          metrics: {
            total: metrics.length,
            slowestRoutes: slowest.map(
              (metric: RouteMetrics): RouteMetrics => ({
                path: metric.path,
                loadTimeMs: parseFloat(metric.loadTimeMs.toFixed(2)),
                accessCount: metric.accessCount
              })
            )
          }
        })
      })

    if (!env.isProduction) {
      app
        .get('/vitest/error-test', () => {
          throw new Error('Error test')
        })
        .get('/vitest/error-structure-test', () => {
          throw new Error('Structure test')
        })
        .get('/vitest/prod-error-test', () => {
          throw new Error('500 Internal Server Error')
        })
    }

    registerEndpoints()
    await routerFactory.build(app)

    app
      .notFound((ctx: Context<Generics>): Response => {
        return httpResponse.notFound(ctx)
      })
      .onError((error: Error, ctx: Context<Generics>): Response => {
        logger.error(error.message, { path: ctx.req.path })
        return env.isProduction ? httpResponse.internalServerError(ctx) : httpResponse.internalServerError(ctx, error.message)
      })
  })()

  await initPromise
  return app
}

/**
 * Fetch handler for server.ts
 * - No await required
 * - Ensures initialize() completed before first request
 */
export const fetchHandler: typeof app.fetch = async (...args): Promise<Response> => {
  await initialize()
  return app.fetch(...args)
}

export { app }
