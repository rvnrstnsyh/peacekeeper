import logger from '@/configs/logger.configs'

import type { Context, Hono, Next } from 'hono'
import type { RouteConfig, RouteMetrics, RouteModule, VersionConfig, VersionInfo } from '@/shared/types/router-factory.core.types'

export class RouterFactory {
  private versions: Map<string, VersionConfig> = new Map()
  private cache: Map<string, Hono<Generics>> = new Map()
  private preloadPromises: Array<Promise<void>> = []
  private metrics: Map<string, RouteMetrics> = new Map()

  /**
   * Preload a route module into cache
   */
  private async preloadRoute(fullPath: string, route: RouteConfig): Promise<void> {
    const start: number = performance.now()
    try {
      const module: RouteModule = await route.module()
      this.cache.set(fullPath, module.default)
      const loadTimeMs: number = performance.now() - start
      this.metrics.set(fullPath, {
        path: fullPath,
        loadTimeMs,
        accessCount: 0
      })
      logger.info(`Preloaded route: ${fullPath} (${loadTimeMs.toFixed(2)}ms)`)
    } catch (error) {
      logger.error(`Failed to preload route: ${fullPath}`, error)
    }
  }

  /**
   * Add deprecation warning headers for deprecated versions
   */
  private addDeprecationMiddleware(app: Hono<Generics>, config: VersionConfig): void {
    app.use(`${config.prefix}/*`, async (ctx: Context<Generics>, next: Next): Promise<void> => {
      ctx.header('X-API-Deprecated', 'true')
      ctx.header('X-API-Deprecation-Info', `Version ${config.version} is deprecated`)

      if (config.sunsetDate) {
        ctx.header('Sunset', config.sunsetDate.toUTCString())
      }
      await next()
    })
  }

  /**
   * Register a new API version
   */
  public registerVersion(config: VersionConfig): this {
    if (this.versions.has(config.version)) {
      throw new Error(`Version ${config.version} already registered`)
    }

    this.versions.set(config.version, config)

    // Auto-preload critical routes
    config.routes.forEach((route: RouteConfig): void => {
      if (route.preload) {
        this.preloadPromises.push(this.preloadRoute(config.prefix + route.path, route))
      }
    })
    return this
  }

  /**
   * Register a single route to a specific version
   */
  public registerRoute(version: string, route: RouteConfig): this {
    const versionConfig: VersionConfig | undefined = this.versions.get(version)

    if (!versionConfig) {
      throw new Error(`Version ${version} not found. Register version first.`)
    }

    versionConfig.routes.push(route)

    if (route.preload) {
      this.preloadPromises.push(this.preloadRoute(versionConfig.prefix + route.path, route))
    }
    return this
  }

  /**
   * Get performance metrics
   */
  public getMetrics(): RouteMetrics[] {
    return Array.from(this.metrics.values())
  }

  /**
   * Get slowest loading routes
   */
  public getSlowestRoutes(limit = 5): RouteMetrics[] {
    return Array.from(this.metrics.values())
      .sort((a, b) => b.loadTimeMs - a.loadTimeMs)
      .slice(0, limit)
  }

  /**
   * Wait for all preloaded routes
   */
  public async waitForPreload(): Promise<void> {
    if (this.preloadPromises.length > 0) {
      logger.info(`Preloading ${this.preloadPromises.length} critical routes...`)
      await Promise.all(this.preloadPromises)
      logger.info('All critical routes preloaded')
    }
  }

  /**
   * Build all routes into the Hono app
   */
  public async build(app: Hono<Generics>): Promise<void> {
    // Wait for preloaded routes first
    await this.waitForPreload()

    for (const [versionKey, versionConfig] of this.versions) {
      logger.info(`Building ${versionKey} routes...`)

      for (const route of versionConfig.routes) {
        const fullPath = versionConfig.prefix + route.path

        try {
          let router: Hono<Generics> | undefined = this.cache.get(fullPath)
          // Load module if not cached yet
          if (!router) {
            const module: RouteModule = await route.module()
            router = module.default
            this.cache.set(fullPath, router)
          }

          // Mount route to app
          if (router && typeof router.routes === 'object') {
            app.route(fullPath, router)
          } else {
            logger.error(`Invalid router instance for ${fullPath}, router does not have routes property`)
            throw new Error(`Invalid router for ${fullPath}`)
          }

          const deprecatedTag: string = versionConfig.deprecated ? '[DEPRECATED]' : ''
          logger.info(`  ${fullPath} ${deprecatedTag}`)
        } catch (error) {
          logger.error(`  Failed to load route: ${fullPath}`, error)
          throw error
        }
      }

      // Add deprecation warning middleware if version is deprecated
      if (versionConfig.deprecated) {
        this.addDeprecationMiddleware(app, versionConfig)
      }
    }
    logger.info('All routes built successfully')
  }

  /**
   * Get info of registered versions
   */
  public getVersionsInfo(): Array<VersionInfo> {
    return Array.from(this.versions.values()).map(
      (config: VersionConfig): VersionInfo => ({
        version: config.version,
        prefix: config.prefix,
        routes: config.routes.length,
        deprecated: config.deprecated ?? false,
        sunsetDate: config.sunsetDate?.toISOString()
      })
    )
  }

  /**
   * Clear cache (useful for testing)
   */
  public clearCache(): void {
    this.cache.clear()
    this.preloadPromises = []
  }
}

// Singleton instance
export const routerFactory: RouterFactory = new RouterFactory()
