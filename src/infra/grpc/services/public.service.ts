import type { CallOptions, ServiceError } from '@grpc/grpc-js'
import type { PublicClient, HealthResponse } from '@/infra/grpc/stubs/v0/contract'

import { Metadata } from '@grpc/grpc-js'

export interface PublicServiceConfig {
  client: PublicClient
  timeoutMs: number
}

export class PublicService {
  private readonly client: PublicClient
  private readonly timeoutMs: number

  constructor(config: PublicServiceConfig) {
    this.client = config.client
    this.timeoutMs = config.timeoutMs
  }

  public async health(payload: string): Promise<string> {
    const metadata: Metadata = new Metadata()
    const options: Partial<CallOptions> = { deadline: new Date(Date.now() + this.timeoutMs) }

    return new Promise<string>((resolve, reject): void => {
      this.client.health({ payload }, metadata, options, (error: ServiceError | null, response?: HealthResponse): void => {
        if (error) {
          reject(error)
          return
        }
        if (!response) {
          reject(new Error('Empty response from health check'))
          return
        }
        resolve(response.payload.toString())
      })
    })
  }
}
