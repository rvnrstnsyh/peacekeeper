import type { Hono, MiddlewareHandler } from 'hono'

export interface RouteModule {
  default: Hono<Generics>
}

export interface RouteConfig {
  /** Relative path from the version root, e.g.: '/auth', '/users' */
  path: string
  /** Dynamic import function for lazy loading */
  module: () => Promise<RouteModule>
  /** Preload during startup? (for critical routes) */
  preload?: boolean
  /** Custom middleware for this route */
  middleware?: Array<MiddlewareHandler>
  /** Description for documentation purposes */
  description?: string
}

export interface VersionConfig {
  /** Version identifier, e.g.: 'v0', 'v1' */
  version: string
  /** Prefix path for this version, e.g.: '/api/v0' */
  prefix: string
  /** Routes registered under this version */
  routes: Array<RouteConfig>
  /** Is this version deprecated? */
  deprecated?: boolean
  /** Sunset date for deprecated versions */
  sunsetDate?: Date
}

export interface VersionInfo {
  version: string
  prefix: string
  routes: number
  deprecated: boolean
  sunsetDate?: string
}

export interface RouteMetrics {
  path: string
  loadTimeMs: number
  lastAccessed?: Date
  accessCount: number
}
