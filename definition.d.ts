import type { User } from '@/database/schema.js'
import type { TimingVariables } from 'hono/timing'
import type { HttpBindings } from '@hono/node-server'
import type { AccessTokenPayload } from '@/types/jwt.types.js'

/**
 * Global type definitions for the application
 * Extends Hono framework types with custom types
 */
declare global {
  /**
   * Server bindings (HTTP or HTTP2)
   * Extend this interface to add custom bindings
   */
  type Bindings = HttpBindings & {
    /* Add custom bindings here if needed */
  }

  /**
   * Context variables available throughout the request lifecycle
   * These can be set by middleware and accessed in route handlers
   *
   * @template T - Type parameter for validated data
   */
  type Variables<T = unknown> = TimingVariables & {
    // System variables
    requestTime: number
    // Validation variables (set by validation middleware)
    validatedHeaders: T
    validatedBody: T
    validatedQuery: T
    validatedParams: T
    validatedCookies: T
    // Authentication variables (set by auth middleware)
    session: AccessTokenPayload
  }

  /**
   * Hono generics configuration
   * Applied to all Hono Context and Handler types
   */
  interface Generics {
    /** Server bindings */
    Bindings: Bindings
    /** Context variables */
    Variables: Variables
  }
}

export {}
