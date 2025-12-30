import { v0Endpoint } from '@/infra/http/versions/v0'
import { routerFactory } from '@/shared/core/router-factory.core'

/**
 * Register all API versions
 */
export function registerEndpoints(): void {
  // Register v0
  routerFactory.registerVersion({ ...v0Endpoint })
}
