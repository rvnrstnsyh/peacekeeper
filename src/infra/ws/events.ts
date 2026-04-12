import type { Context } from 'hono'
import type { NodeWebSocket } from '@hono/node-ws'
import type { WSContext, WSMessageReceive } from 'hono/ws'

import { Hono } from 'hono'
import { logger } from '@/configs/logger.configs'
import { createNodeWebSocket } from '@hono/node-ws'

const webSocketApp: Hono<Generics> = new Hono<Generics>()
const ws: NodeWebSocket = createNodeWebSocket({ app: webSocketApp })
// Track active WebSocket connections
const activeConnections: Set<WSContext<WebSocket>> = new Set()

webSocketApp.get(
  '',
  ws.upgradeWebSocket((_ctx: Context<Generics>) => {
    return {
      onOpen(_event: Event, socket: WSContext<WebSocket>): void {
        activeConnections.add(socket)
        logger.info(`WebSocket connection established. Active connections: ${activeConnections.size}`)
      },
      onMessage(_event: MessageEvent<WSMessageReceive>, _socket: WSContext<WebSocket>): void {
        //
      },
      onClose(_event: CloseEvent, socket: WSContext<WebSocket>): void {
        activeConnections.delete(socket)
        logger.info(`WebSocket connection closed. Active connections: ${activeConnections.size}`)
      }
    }
  })
)

// Function to close all active WebSocket connections
function closeAllWsConnections(): void {
  logger.info(`Closing ${activeConnections.size} active WebSocket connections...`)
  activeConnections.forEach((socket) => {
    try {
      socket.close(1000, 'Server shutting down')
    } catch (error) {
      logger.error('Error closing WebSocket connection:', error)
    }
  })
  activeConnections.clear()
  logger.info('WebSocket connections closed')
}

export { webSocketApp, ws, closeAllWsConnections }
