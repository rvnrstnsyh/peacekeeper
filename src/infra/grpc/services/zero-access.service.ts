import type { CallOptions } from '@grpc/grpc-js'
import type { ZeroAccessClient } from '@/infra/grpc/stubs/v0/contract'

import { Metadata } from '@grpc/grpc-js'

export interface ZeroAccessServiceConfig {
  client: ZeroAccessClient
  timeoutMs: number
}

export class ZeroAccessService {
  private readonly client: ZeroAccessClient
  private readonly timeoutMs: number

  constructor(config: ZeroAccessServiceConfig) {
    this.client = config.client
    this.timeoutMs = config.timeoutMs
  }

  public async health(payload: string): Promise<string> {
    const _metadata: Metadata = new Metadata()
    const _options: Partial<CallOptions> = { deadline: new Date(Date.now() + this.timeoutMs) }

    return new Promise<string>((resolve, reject): void => {
      //
    })
  }
}
