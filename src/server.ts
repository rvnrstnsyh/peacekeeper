import 'module-alias/register'

import GrpcClient from '@/infra/grpc/client'

import type { AddressInfo } from 'net'
import type { ServerType } from '@hono/node-server'

import { fetchHandler } from '@/app'
import { serve } from '@hono/node-server'
import { logger } from '@/configs/logger.configs'
import { closeAllWsConnections, ws } from '@/infra/ws/events'
import { env, validateConfig } from '@/configs/environment.configs'
import { connectRedis, disconnectRedis } from '@/configs/redis.configs'
import { connectDatabase, disconnectDatabase } from '@/database/connection'

class Server {
  private server: ServerType | null = null
  private grpcClient: GrpcClient | null = null

  async listen(): Promise<void> {
    try {
      validateConfig()

      await connectDatabase()
      await connectRedis()

      const grpcSocketAddress: string = `${env.GRPC_HOSTNAME}:${env.GRPC_PORT}`
      this.grpcClient = new GrpcClient({
        hostname: grpcSocketAddress,
        accessToken: (): string => env.GRPC_ACCESS_TOKEN,
        timeoutMs: env.GRPC_TIMEOUT
      })

      try {
        if ((await this.grpcClient.public.health(grpcSocketAddress)) === grpcSocketAddress) {
          logger.info(`gRPC server has responded on ${grpcSocketAddress}`)
        }
      } catch (error: unknown) {
        logger.warning('gRPC connection check failed, continue starting the server', {
          reason: error instanceof Error ? error.message : 'ECONNREFUSED'
        })
        // Don't fail the entire server if gRPC is down
      }

      this.server = serve({ fetch: fetchHandler, hostname: env.APP_HOSTNAME, port: env.APP_PORT }, (info: AddressInfo): void => {
        logger.info(`RESTful API listening on ${info.family} http://${info.address}:${info.port}`)
      })

      ws.injectWebSocket(this.server)
      logger.info('WebSocket successfully injected')
      this.setupGracefulShutdown()
    } catch (error: unknown) {
      const errorMessage: string = error instanceof Error ? error.message : 'Unknown error'
      logger.error(`Failed to start server: ${errorMessage}`, error)
      await this.cleanup()
      process.exit(1)
    }
  }

  private setupGracefulShutdown(): void {
    const shutdownHandler = async (signal: string): Promise<void> => {
      logger.info(`${signal} received, shutting down gracefully...`)
      await this.cleanup()
      process.exit(0)
    }

    process.on('SIGTERM', (): Promise<void> => shutdownHandler('SIGTERM'))
    process.on('SIGINT', (): Promise<void> => shutdownHandler('SIGINT'))
    process.on('uncaughtException', (error: Error): void => {
      logger.error('Uncaught Exception:', error)
      shutdownHandler('UNCAUGHT_EXCEPTION')
    })
    process.on('unhandledRejection', (reason: unknown): void => {
      logger.error('Unhandled Rejection:', reason)
      shutdownHandler('UNHANDLED_REJECTION')
    })
  }

  private async cleanup(): Promise<void> {
    logger.info('Starting cleanup process...')

    try {
      // Disconnect Database
      await disconnectDatabase()
      // Disconnect Redis
      await disconnectRedis()
      // Close gRPC client
      if (this.grpcClient) {
        this.grpcClient.close()
      }
      // Close WebSocket connections
      closeAllWsConnections()
      // Close HTTP server
      if (this.server) {
        // Hono's serve doesn't have a direct close method by default
        // But we can set server to null to mark it as closed
        this.server = null
        logger.info('HTTP server closed')
      }
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      logger.error(`Error during cleanup: ${errorMessage}`, error)
    }
  }
}

const server: Server = new Server()

server.listen()
