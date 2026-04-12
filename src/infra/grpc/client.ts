import type { Interceptor, InterceptorOptions, NextCall, Listener, Metadata, ClientOptions, ChannelCredentials } from '@grpc/grpc-js'

import { logger } from '@/configs/logger.configs'
import { credentials, InterceptingCall } from '@grpc/grpc-js'
import { PublicService } from '@/infra/grpc/services/public.service'
import { ZeroAccessService } from '@/infra/grpc/services/zero-access.service'
import { PublicClient, ZeroAccessClient } from '@/infra/grpc/stubs/v0/contract'

interface Config {
  hostname: string
  accessToken: () => string | undefined
  timeoutMs?: number
}

export default class GrpcClient {
  private readonly publicClient: PublicClient
  private readonly zeroAccessClient: ZeroAccessClient
  private readonly timeoutMs: number

  public readonly public: PublicService
  public readonly zeroAccess: ZeroAccessService

  constructor(config: Config) {
    const authInterceptor: Interceptor = this.createAuthInterceptor(config.accessToken)
    const clientOptions: ClientOptions = { interceptors: [authInterceptor] }
    const insecureCredentials: ChannelCredentials = credentials.createInsecure()

    this.publicClient = new PublicClient(config.hostname, insecureCredentials, clientOptions)
    this.zeroAccessClient = new ZeroAccessClient(config.hostname, insecureCredentials, clientOptions)
    this.timeoutMs = config.timeoutMs ?? 3000

    this.public = new PublicService({ client: this.publicClient, timeoutMs: this.timeoutMs })
    this.zeroAccess = new ZeroAccessService({ client: this.zeroAccessClient, timeoutMs: this.timeoutMs })
  }

  private createAuthInterceptor(accessTokenFn: () => string | undefined): Interceptor {
    return (options: InterceptorOptions, nextCall: NextCall): InterceptingCall => {
      return new InterceptingCall(nextCall(options), {
        start(metadata: Metadata, listener: Listener, next: (metadata: Metadata, listener: Listener) => void): void {
          const token: string | undefined = accessTokenFn()
          if (token) {
            metadata.add('authorization', `Bearer ${token}`)
          }
          next(metadata, listener)
        }
      })
    }
  }

  public close(): void {
    this.publicClient.close()
    this.zeroAccessClient.close()
    logger.info('gRPC client closed')
  }
}
