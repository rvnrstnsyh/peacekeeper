/** Individual API error structure */
export interface ApiError {
  readonly field?: string
  readonly message: string
  readonly code?: string
}

/** Base metadata structure */
export interface MetaBase {
  readonly requestId: string
  readonly path: string
  readonly method: string
  readonly status: number
  readonly code: string
  readonly timestamp: string
  readonly responseTimeMs: number
  readonly message: string
}

/** Success metadata (extends base) */
export interface SuccessMeta extends MetaBase {
  readonly extra?: unknown
}

/** Error metadata (extends base) */
export interface ErrorMeta extends MetaBase {
  readonly details?: string
  readonly errors?: ReadonlyArray<ApiError>
}

/** Pagination metadata */
export interface PaginationMeta {
  readonly page: number
  readonly limit: number
  readonly total: number
  readonly totalPages: number
}

/** Success response structure */
export interface SuccessResponse<T = unknown> {
  readonly meta: SuccessMeta
  readonly data: T | null
}

/** Error response structure */
export interface ErrorResponse {
  readonly meta: ErrorMeta
}

/** Custom headers type for Hono compatibility */
export type CustomHeaders = Record<string, string | Array<string>>
