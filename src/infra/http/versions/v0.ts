import type { RouteModule, VersionConfig } from '@/shared/core/router-factory.core'

export const v0Endpoint: VersionConfig = {
  version: 'v0',
  prefix: '/api/v0',
  routes: [
    {
      path: '/auth',
      module: async (): Promise<RouteModule> => (await import('../../../modules/auth/routes.js')).default,
      preload: true,
      description: 'Authentication endpoints'
    }
  ],
  deprecated: false,
  sunsetDate: undefined
}
