import type { RouteModule, VersionConfig } from '@/shared/types/router-factory.core.types'

export const v0Endpoint: VersionConfig = {
  version: 'v0',
  prefix: '/api/v0',
  routes: [
    {
      path: '/auth',
      module: async (): Promise<RouteModule> => (await import('../../../modules/auth/routes.js')).default,
      preload: true,
      description: 'Authentication endpoints'
    },
    {
      path: '/invite',
      module: async (): Promise<RouteModule> => (await import('../../../modules/invite/routes.js')).default,
      preload: true,
      description: 'Invitation code endpoints'
    }
  ],
  deprecated: false,
  sunsetDate: undefined
}
