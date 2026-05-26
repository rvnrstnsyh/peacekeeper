import type { ZeroAccessClient, OpaqueKe2 } from '@/infra/grpc/stubs/v0/contract'
import type { KE1, KE2, RegistrationRecord, RegistrationResponse } from '@/shared/types/zero-access.utils.types'
import type { CallOptions, ServiceError, Interceptor, InterceptorOptions, NextCall, Listener } from '@grpc/grpc-js'

import { env } from '@/configs/environment.configs'
import { credentials, InterceptingCall, Metadata } from '@grpc/grpc-js'
import { ZeroAccessClient as ZeroAccessClientImpl } from '@/infra/grpc/stubs/v0/contract'

// ─── Config ───────────────────────────────────────────────────────────────────

export interface ZeroAccessServiceConfig {
  client: ZeroAccessClient
  timeoutMs: number
}

// ─── Conversion helpers ───────────────────────────────────────────────────────

function ke1ToProto(ke1: KE1) {
  return {
    credentialRequest: { blindedMessage: ke1.credentialRequest.blindedMessage },
    authRequest: {
      clientNonce: ke1.authRequest.clientNonce,
      clientX25519PublicKeyshare: ke1.authRequest.clientX25519PublicKeyshare
    }
  }
}

function recordToProto(record: RegistrationRecord) {
  return {
    clientEd25519PublicKey: record.clientED25519PublicKey,
    clientX25519PublicKey: record.clientX25519PublicKey,
    maskingKey: record.maskingKey,
    envelopeNonce: record.envelope.nonce,
    envelopeAuthTag: record.envelope.authTag,
    envelopeSeed: record.envelope.seed
  }
}

function protoKe2ToKe2(protoKe2: NonNullable<OpaqueKe2>): KE2 {
  const cr = protoKe2.credentialResponse
  const ar = protoKe2.authResponse
  if (!cr || !ar) {
    throw new Error('Malformed KE2: missing credentialResponse or authResponse')
  }
  return {
    credentialResponse: {
      evaluatedMessage: cr.evaluatedMessage,
      maskingNonce: cr.maskingNonce,
      maskedResponse: cr.maskedResponse
    },
    authResponse: {
      serverNonce: ar.serverNonce,
      serverX25519PublicKeyshare: ar.serverX25519PublicKeyshare,
      serverMac: ar.serverMac
    }
  }
}

// ─── Service ──────────────────────────────────────────────────────────────────

let _envInstance: ZeroAccessService | null = null

export class ZeroAccessService {
  private readonly client: ZeroAccessClient
  private readonly timeoutMs: number

  constructor(config: ZeroAccessServiceConfig) {
    this.client = config.client
    this.timeoutMs = config.timeoutMs
  }

  /**
   * Return the shared singleton backed by environment variables.
   * The gRPC channel is created only once; subsequent calls return the cached
   * instance so every consumer shares a single connection pool.
   */
  static createFromEnv(): ZeroAccessService {
    if (_envInstance) return _envInstance
    const address: string = `${env.GRPC_HOSTNAME}:${env.GRPC_PORT}`
    const authInterceptor: Interceptor = (_options: InterceptorOptions, nextCall: NextCall) =>
      new InterceptingCall(nextCall(_options), {
        start(metadata: Metadata, listener: Listener, next: (m: Metadata, l: Listener) => void) {
          metadata.add('authorization', `Bearer ${env.GRPC_ACCESS_TOKEN}`)
          next(metadata, listener)
        }
      })
    const client: ZeroAccessClient = new ZeroAccessClientImpl(address, credentials.createInsecure(), {
      interceptors: [authInterceptor]
    })
    _envInstance = new ZeroAccessService({ client, timeoutMs: env.GRPC_TIMEOUT })
    return _envInstance
  }

  // ─── OPAQUE RPCs ───────────────────────────────────────────────────────────

  /** RFC 9807 §5.1.2 — CreateRegistrationResponse (registration step 2/3). */
  createRegistrationResponse(blindedMessage: Uint8Array, credentialIdentifier: Uint8Array): Promise<RegistrationResponse> {
    const metadata: Metadata = new Metadata()
    const options: Partial<CallOptions> = { deadline: new Date(Date.now() + this.timeoutMs) }

    return new Promise<RegistrationResponse>((resolve, reject) => {
      this.client.createRegistrationResponse({ blindedMessage, credentialIdentifier }, metadata, options, (error: ServiceError | null, response) => {
        if (error) {
          reject(error)
          return
        }
        if (!response) {
          reject(new Error('Empty response from createRegistrationResponse'))
          return
        }
        resolve({
          evaluatedMessage: response.evaluatedMessage,
          serverX25519PublicKey: response.serverPublicKey
        })
      })
    })
  }

  /** RFC 9807 §6.2.4 — GenerateKE2 (authentication step 2/4). */
  generateKe2(
    record: RegistrationRecord,
    credentialIdentifier: Uint8Array,
    ke1: KE1,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array
  ): Promise<{ ke2: KE2; expectedClientMac: Uint8Array; sessionKey: Uint8Array }> {
    const metadata: Metadata = new Metadata()
    const options: Partial<CallOptions> = { deadline: new Date(Date.now() + this.timeoutMs) }

    return new Promise((resolve, reject) => {
      this.client.generateKe2(
        {
          record: recordToProto(record),
          credentialIdentifier,
          ke1: ke1ToProto(ke1),
          serverIdentity: serverIdentity ?? new Uint8Array(0),
          clientIdentity: clientIdentity ?? new Uint8Array(0)
        },
        metadata,
        options,
        (error: ServiceError | null, response) => {
          if (error) {
            reject(error)
            return
          }
          if (!response?.ke2) {
            reject(new Error('Empty ke2 in generateKe2 response'))
            return
          }
          resolve({
            ke2: protoKe2ToKe2(response.ke2),
            expectedClientMac: response.expectedClientMac,
            sessionKey: response.sessionKey
          })
        }
      )
    })
  }

  /** RFC 9807 §6.2.6 — ServerFinish: constant-time MAC verification. */
  serverFinish(ke3ClientMac: Uint8Array, expectedClientMac: Uint8Array): Promise<boolean> {
    const metadata: Metadata = new Metadata()
    const options: Partial<CallOptions> = { deadline: new Date(Date.now() + this.timeoutMs) }

    return new Promise<boolean>((resolve, reject) => {
      this.client.serverFinish({ ke3ClientMac, expectedClientMac }, metadata, options, (error: ServiceError | null, response) => {
        if (error) {
          reject(error)
          return
        }
        if (!response) {
          reject(new Error('Empty response from serverFinish'))
          return
        }
        resolve(response.valid)
      })
    })
  }

  /** RFC 9807 combined ChangePassword: old-password AKE + new-password OPRF. */
  createChangePasswordResponse(
    record: RegistrationRecord,
    credentialIdentifier: Uint8Array,
    oldKe1: KE1,
    newBlindedMessage: Uint8Array,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array
  ): Promise<{
    ke2: KE2
    expectedClientMac: Uint8Array
    sessionKey: Uint8Array
    newEvaluatedMessage: Uint8Array
    newServerPublicKey: Uint8Array
  }> {
    const metadata: Metadata = new Metadata()
    const options: Partial<CallOptions> = { deadline: new Date(Date.now() + this.timeoutMs) }

    return new Promise((resolve, reject) => {
      this.client.createChangePasswordResponse(
        {
          record: recordToProto(record),
          credentialIdentifier,
          oldPasswordKe1: ke1ToProto(oldKe1),
          newPasswordRegRequest: { blindedMessage: newBlindedMessage },
          serverIdentity: serverIdentity ?? new Uint8Array(0),
          clientIdentity: clientIdentity ?? new Uint8Array(0)
        },
        metadata,
        options,
        (error: ServiceError | null, response) => {
          if (error) {
            reject(error)
            return
          }
          if (!response?.oldPasswordKe2) {
            reject(new Error('Empty ke2 in createChangePasswordResponse'))
            return
          }
          resolve({
            ke2: protoKe2ToKe2(response.oldPasswordKe2),
            expectedClientMac: response.expectedClientMac,
            sessionKey: response.sessionKey,
            newEvaluatedMessage: response.newEvaluatedMessage,
            newServerPublicKey: response.newServerPublicKey
          })
        }
      )
    })
  }
}
