import type { Context } from 'hono'
import type { ConnInfo } from 'hono/conninfo'

import { getConnInfo } from '@hono/node-server/conninfo'

function extractFirstIp(value: string): string {
  // client, proxy1, proxy2
  if (value.includes(',')) {
    return value.split(',')[0].trim()
  }
  // For header RFC Forwarded
  const match: RegExpMatchArray | null = value.match(/for="?([^";]+)"?/)
  if (match?.[1]) return match[1]
  return value.trim()
}

function normalizeIp(ip: string): string {
  // Remove prefix IPv6-mapped IPv4
  if (ip.startsWith('::ffff:')) return ip.substring(7)
  return ip
}

function isValidIp(ip: string): boolean {
  // IPv4
  const ipv4: RegExp = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
  // IPv6
  const ipv6: RegExp = /^(([0-9a-fA-F]{1,4}):){7}([0-9a-fA-F]{1,4})$|^::1$/
  return ipv4.test(ip) || ipv6.test(ip)
}

export function remoteAddr(ctx: Context<Generics>, trustedProxy = true): string {
  const connInfo: ConnInfo = getConnInfo(ctx)
  const socketIp: string | undefined = connInfo?.remote?.address
  const headerCandidates: Array<string> = [
    'cf-connecting-ip', // Cloudflare
    'x-real-ip', // Nginx
    'x-client-ip',
    'x-forwarded-for', // Proxy chain
    'forwarded'
  ]

  if (trustedProxy) {
    for (const header of headerCandidates) {
      const value: string | undefined = ctx.req.header(header)
      if (!value) continue
      const ip: string = extractFirstIp(value)
      if (isValidIp(ip)) return normalizeIp(ip)
    }
  }
  // Fallback: socket / direct connection
  if (socketIp && isValidIp(socketIp)) {
    return normalizeIp(socketIp)
  }
  return 'unknown'
}
