/* eslint-disable no-console */

import type {
  AuthRequest,
  AuthResponse,
  ChangePasswordClientState,
  ChangePasswordRequest,
  ChangePasswordRequestSerialized,
  ChangePasswordResponse,
  ChangePasswordResponseSerialized,
  CleartextCredentials,
  ClientState,
  CredentialRequest,
  CredentialResponse,
  Envelope,
  KE1,
  KE1Serialized,
  KE2,
  KE2Serialized,
  KE3,
  KE3Serialized,
  OpaqueConfig,
  RegistrationRecord,
  RegistrationRecordSerialized,
  RegistrationRequest,
  RegistrationResponse,
  ServerState
} from '@/shared/types/zero-access.types'

import { hmac } from '@noble/hashes/hmac.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { argon2id } from '@noble/hashes/argon2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { expand, extract } from '@noble/hashes/hkdf.js'
import { ristretto255_hasher } from '@noble/curves/ed25519.js'
import { ed25519, ristretto255, x25519 } from '@noble/curves/ed25519.js'
import { base64ToUint8Array, uint8ArrayToBase64 } from '@/shared/utils/common'

/**
 * OPAQUE: An Asymmetric Password-Authenticated Key Exchange Protocol
 *
 * Implementation of RFC 9807: The OPAQUE Asymmetric PAKE Protocol
 * https://datatracker.ietf.org/doc/html/rfc9807
 *
 * Configuration: ristretto255-SHA512
 * - Group: ristretto255 (RFC 9496)
 * - Hash: SHA-512
 * - KSF: Argon2id (RFC 9106)
 * - KDF: HKDF-SHA512 (RFC 5869)
 * - MAC: HMAC-SHA512 (RFC 2104)
 * - KE: X25519 with 3DH (RFC 7748)
 * Mode: Base mode with internal key mode
 *
 *                 Registration Phase                               Authentication (AKE) Phase
 *
 *     CLIENT                             SERVER             CLIENT                       SERVER
 *  (credentials)                      (parameters)       (credentials)             (parameters, record)
 *  -----------------------------------------------       ----------------------------------------------
 *             REG Request                            |             AKE Message 1
 *             ------------------------->            |              ------------------------->
 *                           REG Response             |                          AKE Message 2
 *             <-------------------------            |              <-------------------------
 *             REG Record                             |             AKE Message 3
 *             ------------------------->            |              ------------------------->
 *  -----------------------------------------------       ----------------------------------------------
 *  exportKey                               record       (exportKey, sessionKey)          sessionKey
 *
 * @version 0.1.0
 * @standard RFC 9807
 */
export class ZeroAccess {
  private readonly CONFIG: OpaqueConfig
  private readonly LOW_ORDER_POINTS: Set<string>

  constructor(context: string = 'OPAQUE-POC') {
    if (!context || context.length === 0) {
      throw new Error('Context string cannot be empty')
    }

    if (context.length > 255) {
      throw new Error('Context string too long (max 255 bytes)')
    }

    if (context.includes('\0')) {
      throw new Error('Context string cannot contain null bytes')
    }

    this.CONFIG = {
      hash: 'sha512',
      kdf: 'hkdf-sha512',
      mac: 'hmac-sha512',
      context,
      Nh: 64, // Hash output length (SHA-512)
      Nn: 32, // Nonce length
      Nm: 64, // MAC output length (HMAC-SHA512)
      Npk: 32, // Public key length (X25519)
      Noe: 32, // OPRF element length (ristretto255)
      Nok: 32, // OPRF key length (ristretto255 scalar)
      Nseed: 32, // Seed length
      Nsk: 32 // Secret key length (X25519)
    }

    // RFC 7748 Section 6.1 - Low-order points for X25519
    this.LOW_ORDER_POINTS = new Set([
      '0000000000000000000000000000000000000000000000000000000000000000',
      '0100000000000000000000000000000000000000000000000000000000000000',
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
      'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'
    ])

    this.validateConfiguration()
  }

  /**
   * Validates the OPAQUE protocol configuration parameters.
   *
   * Ensures all size parameters meet RFC 9807 requirements for the ristretto255-SHA512
   * configuration. This includes validating key lengths, nonce sizes, hash outputs,
   * and MAC lengths against the specification.
   *
   * @throws {Error} If any configuration parameter is invalid or doesn't meet RFC 9807 requirements.
   * @private
   */
  private validateConfiguration(): void {
    const { Nh, Nn, Nm, Npk, Noe, Nok, Nseed, Nsk }: OpaqueConfig = this.CONFIG

    if (Nh <= 0 || Nn <= 0 || Nm <= 0 || Npk <= 0 || Noe <= 0 || Nok <= 0 || Nseed <= 0 || Nsk <= 0) {
      throw new Error('Configuration error: All size parameters must be positive')
    }

    // RFC 9807 requirements for ristretto255-SHA512
    if (Npk !== 32) throw new Error('Npk must be 32 for X25519')
    if (Noe !== 32) throw new Error('Noe must be 32 for ristretto255')
    if (Nok !== 32) throw new Error('Nok must be 32 for ristretto255')
    if (Nsk !== 32) throw new Error('Nsk must be 32 for X25519')
    if (Nseed !== 32) throw new Error('Nseed must be 32')
    if (Nn !== 32) throw new Error('Nn must be 32')
    if (Nh !== 64) throw new Error('Nh must be 64 for SHA-512')
    if (Nm !== 64) throw new Error('Nm must be 64 for HMAC-SHA512')
  }

  /**
   * Validates an X25519 public key for cryptographic correctness and security.
   *
   * Performs several critical security checks per RFC 7748:
   * - Verifies the key is exactly 32 bytes (required for X25519)
   * - Checks against known low-order points that would compromise security
   * - Ensures the key is not the identity element (all zeros)
   *
   * Low-order point validation is essential to prevent small subgroup attacks.
   *
   * @param publicKey - The X25519 public key to validate (must be 32 bytes).
   * @throws {Error} If the key length is invalid, represents a low-order point,
   *   or is the identity element.
   * @see RFC 7748 Section 6.1 - Low-order points for X25519
   * @private
   */
  private validateX25519PublicKey(publicKey: Uint8Array): void {
    if (publicKey.length !== 32) {
      throw new Error('Invalid X25519 public key length: expected 32 bytes')
    }

    const hex: string = Array.from(publicKey)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')

    if (this.LOW_ORDER_POINTS.has(hex)) {
      throw new Error('Invalid X25519 public key: low-order point detected')
    }

    const allZero: boolean = publicKey.every((b) => b === 0)
    if (allZero) {
      throw new Error('Invalid X25519 public key: identity point (all zero)')
    }
  }

  /**
   * Validates a ristretto255 group element for cryptographic correctness.
   *
   * Ensures the provided bytes represent a valid point on the ristretto255 group
   * as required by RFC 9807. Performs deserialization to verify canonical encoding
   * and checks that the element is not the identity element.
   *
   * @param element - The ristretto255 element to validate (must be 32 bytes).
   * @throws {Error} If the element length is invalid, deserialization fails,
   *   or the element is the identity element.
   * @private
   */
  private validateRistretto255Element(element: Uint8Array): void {
    if (element.length !== 32) {
      throw new Error('Invalid ristretto255 element length: expected 32 bytes')
    }

    try {
      const point = ristretto255.Point.fromBytes(element)

      if (point.equals(ristretto255.Point.ZERO)) {
        throw new Error('Invalid ristretto255 element: identity element')
      }
    } catch (error) {
      throw new Error(`Invalid ristretto255 element: deserialization failed - ${error}`)
    }
  }

  /**
   * Validates an OPAQUE envelope structure.
   *
   * Ensures all envelope components meet the expected lengths defined in the
   * protocol configuration. The envelope contains encrypted credential material
   * protected by the password-derived key.
   *
   * @param envelope - The envelope structure to validate.
   * @throws {Error} If any envelope component has an invalid length.
   * @see RFC 9807 Section 4.2 - Envelope structure
   * @private
   */
  private validateEnvelope(envelope: Envelope): void {
    if (envelope.nonce.length !== this.CONFIG.Nn) {
      throw new Error(`Invalid envelope nonce length: expected ${this.CONFIG.Nn} bytes`)
    }

    if (envelope.authTag.length !== this.CONFIG.Nm) {
      throw new Error(`Invalid envelope authTag length: expected ${this.CONFIG.Nm} bytes`)
    }

    if (!envelope.seed || envelope.seed.length !== this.CONFIG.Nseed) {
      throw new Error(`Invalid or missing envelope seed length: expected ${this.CONFIG.Nseed} bytes`)
    }
  }

  /**
   * Validates a Message Authentication Code (MAC) length.
   *
   * Ensures the MAC is the expected length for HMAC-SHA512 (64 bytes)
   * as configured in the protocol.
   *
   * @param mac - The MAC to validate.
   * @throws {Error} If the MAC length doesn't match the expected length.
   * @private
   */
  private validateMAC(mac: Uint8Array): void {
    if (mac.length !== this.CONFIG.Nm) {
      throw new Error(`Invalid MAC length: expected ${this.CONFIG.Nm} bytes`)
    }
  }

  /**
   * Validates a nonce length.
   *
   * Ensures the nonce is the expected length (32 bytes) as required
   * by the protocol configuration.
   *
   * @param nonce - The nonce to validate.
   * @throws {Error} If the nonce length doesn't match the expected length.
   * @private
   */
  private validateNonce(nonce: Uint8Array): void {
    if (nonce.length !== this.CONFIG.Nn) {
      throw new Error(`Invalid nonce length: expected ${this.CONFIG.Nn} bytes`)
    }
  }

  /**
   * HKDF Extract operation for key derivation.
   *
   * Implements the Extract step of HKDF (HMAC-based Key Derivation Function)
   * using SHA-512 as the hash function. This produces a pseudorandom key
   * from input keying material.
   *
   * @param salt - Optional salt value (uses zero-length array if null).
   * @param ikm - Input keying material to extract from.
   * @returns A pseudorandom key suitable for use with HKDF-Expand.
   * @see RFC 9807 Section 3.1 - HKDF
   * @see RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function
   * @private
   */
  private extract(salt: Uint8Array | null, ikm: Uint8Array): Uint8Array {
    const saltBytes: Uint8Array = salt || new Uint8Array(0)
    return extract(sha512, ikm, saltBytes)
  }

  /**
   * HKDF Expand operation for key derivation.
   *
   * Implements the Expand step of HKDF using SHA-512. Expands a pseudorandom
   * key into the desired length of output keying material using application-
   * specific context information.
   *
   * @param prk - Pseudorandom key from HKDF-Extract (at least Nh bytes).
   * @param info - Context and application-specific information (string or bytes).
   * @param length - Desired output length in bytes.
   * @returns Output keying material of the specified length.
   * @see RFC 9807 Section 3.1 - HKDF
   * @see RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function
   * @private
   */
  private expand(prk: Uint8Array, info: Uint8Array | string, length: number): Uint8Array {
    const infoBytes: Uint8Array = typeof info === 'string' ? new TextEncoder().encode(info) : info
    return expand(sha512, prk, infoBytes, length)
  }

  /**
   * Applies memory-hard function (MHF) hardening to OPRF output.
   *
   * Uses Argon2id as the memory-hard function per RFC 9807 recommendations.
   * This provides additional protection against offline attacks by making
   * password verification computationally expensive.
   *
   * Configuration:
   * - Algorithm: Argon2id
   * - Parallelism: 4
   * - Memory: 65536 KB
   * - Iterations: 3
   *
   * @param oprfOutput - The OPRF output to harden.
   * @param params - 16-byte parameter string for the MHF.
   * @returns Hardened output of length Nh bytes.
   * @throws {Error} If params is not exactly 16 bytes or if MHF execution fails.
   * @see RFC 9807 Section 4 - Hardening with memory-hard function
   * @private
   */
  private hardening(oprfOutput: Uint8Array, params: Uint8Array): Uint8Array {
    try {
      if (params.length !== 16) {
        throw new Error('Hardening params must be 16 bytes')
      }

      // Using Argon2id as MHF per RFC 9807 recommendations
      const parallelism: number = 4
      const memorySize: number = 65536
      const iterations: number = 3
      const outputLength: number = this.CONFIG.Nh

      return argon2id(oprfOutput, params, {
        t: iterations,
        m: memorySize,
        p: parallelism
      }).slice(0, outputLength)
    } catch (error) {
      throw new Error(`MHF hardening failed: ${error}`)
    }
  }

  /**
   * OPRF Blind operation - blinds the password for oblivious evaluation.
   *
   * Generates a random blinding scalar and applies it to the password after
   * hashing to the ristretto255 group. This ensures the server cannot learn
   * the password during OPRF evaluation.
   *
   * @param passwordBytes - The password bytes to blind.
   * @returns Object containing:
   *   - blind: The random blinding scalar (must be kept secret)
   *   - blindedElement: The blinded group element to send to server
   * @throws {Error} If blinding produces the identity element or zero scalar.
   * @see RFC 9807 Section 3.2 - OPRF Protocol
   * @see RFC 9497 - HashToGroup for ristretto255
   * @private
   */
  private blind(passwordBytes: Uint8Array): { blind: Uint8Array; blindedElement: Uint8Array } {
    const blind: Uint8Array = randomBytes(32)
    const blindScalar: bigint = this.bytesToScalar(blind)

    if (blindScalar === 0n) {
      throw new Error('Error: Generated zero blind')
    }

    // RFC 9497 - HashToGroup for ristretto255
    const DST: string = 'RFCXXXX-\x00\x00\x03-HashToGroup-ristretto255-SHA512'
    const point = ristretto255_hasher.hashToCurve(passwordBytes, { DST })
    const blindedPoint = point.multiply(blindScalar)

    if (blindedPoint.equals(ristretto255.Point.ZERO)) {
      throw new Error('Error: Blinding produced identity element')
    }
    return { blind, blindedElement: blindedPoint.toBytes() }
  }

  /**
   * OPRF BlindEvaluate operation - server evaluates the blinded element.
   *
   * Multiplies the client's blinded element by the server's OPRF key.
   * This allows the server to contribute to the OPRF output without
   * learning the client's password.
   *
   * @param oprfKey - The server's secret OPRF key (32 bytes).
   * @param blindedElement - The blinded element from the client.
   * @returns The evaluated element to return to the client.
   * @throws {Error} If evaluation produces the identity element or key is invalid.
   * @see RFC 9807 Section 3.2 - OPRF Protocol
   * @private
   */
  private blindEvaluate(oprfKey: Uint8Array, blindedElement: Uint8Array): Uint8Array {
    this.validateRistretto255Element(blindedElement)

    const keyScalar: bigint = this.bytesToScalar(oprfKey)

    if (keyScalar === 0n) {
      throw new Error('OPRF key scalar is zero')
    }

    const blindedPoint = ristretto255.Point.fromBytes(blindedElement)
    const evaluatedPoint = blindedPoint.multiply(keyScalar)

    if (evaluatedPoint.equals(ristretto255.Point.ZERO)) {
      throw new Error('BlindEvaluate produced identity element')
    }
    return evaluatedPoint.toBytes()
  }

  /**
   * OPRF Finalize operation - unblinds and hashes to produce final output.
   *
   * Removes the client's blinding factor from the server's evaluation,
   * then hashes the unblinded result to produce the final OPRF output.
   * This output is used to derive the randomized password.
   *
   * @param passwordBytes - The original password bytes.
   * @param blind - The blinding scalar used in the Blind operation.
   * @param evaluatedElement - The evaluated element from the server.
   * @returns The final OPRF output (64 bytes for SHA-512).
   * @throws {Error} If unblinding produces the identity element or blind is invalid.
   * @see RFC 9807 Section 3.2 - OPRF Protocol
   * @see RFC 9497 - Finalize hash input format
   * @private
   */
  private finalize(passwordBytes: Uint8Array, blind: Uint8Array, evaluatedElement: Uint8Array): Uint8Array {
    this.validateRistretto255Element(evaluatedElement)

    if (blind.length !== 32) {
      throw new Error('Invalid blind length: expected 32 bytes')
    }

    const blindScalar: bigint = this.bytesToScalar(blind)

    if (blindScalar === 0n) {
      throw new Error('Blind scalar is zero')
    }

    const evaluatedPoint = ristretto255.Point.fromBytes(evaluatedElement)

    const n: bigint = ed25519.Point.CURVE().n
    const blindInv: bigint = this.modInverse(blindScalar, n)
    const unblindedPoint = evaluatedPoint.multiply(blindInv)

    if (unblindedPoint.equals(ristretto255.Point.ZERO)) {
      throw new Error('Finalize produced identity element')
    }

    const unblindedBytes: Uint8Array = unblindedPoint.toBytes()
    // RFC 9497 - Finalize hash input format
    const hashInput: Uint8Array = this.concat(this.i2OSP(passwordBytes.length, 2), passwordBytes, this.i2OSP(unblindedBytes.length, 2), unblindedBytes, new TextEncoder().encode('Finalize'))

    return sha512(hashInput)
  }

  /**
   * Derives an OPRF key pair from a seed and context information.
   *
   * Uses HKDF to derive a private key scalar, then computes the corresponding
   * public key on the ristretto255 group. The private key is used by the server
   * for OPRF evaluation.
   *
   * @param seed - The master seed for key derivation.
   * @param info - Context string for domain separation.
   * @returns Object containing:
   *   - privateKey: The OPRF private key (32 bytes)
   *   - publicKey: The OPRF public key (32 bytes, ristretto255 element)
   * @throws {Error} If derived private key is zero.
   * @see RFC 9807 Section 3.2.1 - Derive OPRF key pair
   * @private
   */
  private deriveOprfKeyPair(seed: Uint8Array, info: string): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const derivedSeed: Uint8Array = this.expand(seed, info, this.CONFIG.Nok)
    const privateKeyScalar: bigint = this.bytesToScalar(derivedSeed)

    if (privateKeyScalar === 0n) {
      this.secureZero(derivedSeed)
      throw new Error('Derived OPRF private key is zero')
    }

    const publicKeyPoint = ristretto255.Point.BASE.multiply(privateKeyScalar)
    const publicKey: Uint8Array = publicKeyPoint.toBytes()
    const privateKey: Uint8Array = this.scalarToBytes(privateKeyScalar)

    this.secureZero(derivedSeed)

    return { privateKey, publicKey }
  }

  /**
   * X25519 Diffie-Hellman key agreement.
   *
   * Computes the shared secret between a private key and public key using
   * the X25519 elliptic curve Diffie-Hellman function. This is used in the
   * authenticated key exchange protocol.
   *
   * @param privateKey - The X25519 private key (32 bytes).
   * @param publicKey - The X25519 public key (32 bytes).
   * @returns The shared secret (32 bytes).
   * @throws {Error} If keys are invalid or shared secret is all zeros.
   * @see RFC 7748 - X25519 Elliptic Curve Diffie-Hellman
   * @private
   */
  private diffieHellman(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    if (privateKey.length !== 32) {
      throw new Error('Invalid X25519 private key length: expected 32 bytes')
    }

    this.validateX25519PublicKey(publicKey)

    try {
      const sharedSecret: Uint8Array = x25519.getSharedSecret(privateKey, publicKey)

      if (sharedSecret.every((b) => b === 0)) {
        throw new Error('DH produced invalid shared secret (all zero)')
      }

      return sharedSecret
    } catch (error) {
      throw new Error(`DH operation failed: ${error}`)
    }
  }

  /**
   * Derives a Diffie-Hellman key pair for authentication.
   *
   * Uses HKDF to derive an X25519 private key from a seed, applies the
   * required key clamping, then computes the corresponding public key.
   * These keys are used for the authenticated key exchange.
   *
   * @param seed - The seed for key derivation (32 bytes).
   * @returns Object containing:
   *   - privateKey: The X25519 private key (32 bytes, clamped)
   *   - publicKey: The X25519 public key (32 bytes)
   * @see RFC 9807 Section 3.2.1 - Derive DH key pair
   * @see RFC 7748 - X25519 key derivation
   * @private
   */
  private deriveDiffieHellmanKeyPair(seed: Uint8Array): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const info: string = 'OPAQUE-DeriveAuthKeyPair'
    const derivedSeed: Uint8Array = this.expand(seed, info, this.CONFIG.Nsk)
    const privateKey: Uint8Array = this.clampX25519Key(derivedSeed)
    const publicKey: Uint8Array = x25519.getPublicKey(privateKey)

    this.validateX25519PublicKey(publicKey)
    this.secureZero(derivedSeed)

    return { privateKey, publicKey }
  }

  /**
   * Applies X25519 key clamping as required by RFC 7748.
   *
   * Clamps the private key by:
   * - Clearing the 3 least significant bits of the first byte
   * - Clearing the most significant bit of the last byte
   * - Setting the second-most significant bit of the last byte
   *
   * This ensures the key is a valid X25519 scalar.
   *
   * @param key - The key to clamp (32 bytes).
   * @returns The clamped key (32 bytes).
   * @see RFC 7748 Section 5 - X25519 key clamping
   * @private
   */
  private clampX25519Key(key: Uint8Array): Uint8Array {
    const clamped: Uint8Array = new Uint8Array(key)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return clamped
  }

  /**
   * Creates cleartext credentials structure.
   *
   * Bundles the server and client public keys and identities into a single
   * structure. If identities are not provided, the public keys are used
   * as default identities.
   *
   * @param serverPublicKey - The server's public key.
   * @param clientPublicKey - The client's public key.
   * @param serverIdentity - Optional server identity (defaults to serverPublicKey).
   * @param clientIdentity - Optional client identity (defaults to clientPublicKey).
   * @returns The cleartext credentials structure.
   * @see RFC 9807 Section 4 - Credentials structure
   * @private
   */
  private createCleartextCredentials(serverPublicKey: Uint8Array, clientPublicKey: Uint8Array, serverIdentity?: Uint8Array, clientIdentity?: Uint8Array): CleartextCredentials {
    return {
      serverPublicKey,
      serverIdentity: serverIdentity || serverPublicKey,
      clientPublicKey,
      clientIdentity: clientIdentity || clientPublicKey
    }
  }

  /**
   * Creates an envelope containing encrypted credential material.
   *
   * Derives encryption keys from the randomized password, generates or uses
   * the provided client keypair seed, and creates an authenticated envelope
   * containing the encrypted seed. The envelope is protected by an authentication
   * tag computed over all relevant credential data.
   *
   * @param randomizedPassword - The password-derived key material.
   * @param serverPublicKey - The server's public key.
   * @param serverIdentity - Optional server identity.
   * @param clientIdentity - Optional client identity.
   * @param clientKeypairSeed - Optional seed for client keypair (generated if not provided).
   * @returns Object containing:
   *   - envelope: The encrypted and authenticated envelope
   *   - clientPublicKey: The client's public key
   *   - maskingKey: Key used to mask credential responses
   *   - exportKey: Additional key for application use
   *
   * @see RFC 9807 Section 4.2 - Store envelope (CreateEnvelope)
   * @private
   */
  private store(
    randomizedPassword: Uint8Array,
    serverPublicKey: Uint8Array,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array,
    clientKeypairSeed?: Uint8Array
  ): {
    envelope: Envelope
    clientPublicKey: Uint8Array
    maskingKey: Uint8Array
    exportKey: Uint8Array
  } {
    const envelopeNonce: Uint8Array = randomBytes(this.CONFIG.Nn)
    // Derive keys from randomized password
    const authKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelopeNonce, new TextEncoder().encode('AuthKey')), this.CONFIG.Nh)
    const exportKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelopeNonce, new TextEncoder().encode('ExportKey')), this.CONFIG.Nh)
    const seedEncryptionKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelopeNonce, new TextEncoder().encode('SeedKey')), this.CONFIG.Nseed)
    const maskingKey: Uint8Array = this.expand(randomizedPassword, new TextEncoder().encode('MaskingKey'), this.CONFIG.Nh)
    // Generate or use provided client keypair seed
    const actualSeed: Uint8Array = clientKeypairSeed || randomBytes(this.CONFIG.Nseed)
    const encryptedSeed: Uint8Array = this.xor(actualSeed, seedEncryptionKey)

    const { publicKey: clientPublicKey } = this.deriveDiffieHellmanKeyPair(actualSeed)

    // Construct cleartext credentials
    const serverId: Uint8Array = serverIdentity || serverPublicKey
    const clientId: Uint8Array = clientIdentity || clientPublicKey
    // Create authentication tag
    const authInput: Uint8Array = this.concat(envelopeNonce, encryptedSeed, serverPublicKey, this.i2OSP(serverId.length, 2), serverId, this.i2OSP(clientId.length, 2), clientId)
    const authTag: Uint8Array = hmac(sha512, authKey, authInput)

    this.secureZeroMultiple(seedEncryptionKey, authKey)
    if (!clientKeypairSeed) {
      this.secureZero(actualSeed)
    }

    return {
      envelope: { nonce: envelopeNonce, authTag, seed: encryptedSeed },
      clientPublicKey,
      maskingKey,
      exportKey
    }
  }

  /**
   * Recovers credential material from an envelope.
   *
   * Derives decryption keys from the randomized password, decrypts the client
   * keypair seed from the envelope, and verifies the authentication tag to
   * ensure the password is correct and the envelope hasn't been tampered with.
   *
   * @param randomizedPassword - The password-derived key material.
   * @param serverPublicKey - The server's public key.
   * @param envelope - The envelope to recover from.
   * @param serverIdentity - Optional server identity.
   * @param clientIdentity - Optional client identity.
   * @returns Object containing:
   *   - clientPrivateKey: The recovered client private key
   *   - clientKeypairSeed: The decrypted keypair seed
   *   - cleartextCredentials: The credential structure
   *   - exportKey: Additional key for application use
   *
   * @throws {Error} EnvelopeRecoveryError if password is incorrect or envelope is corrupted.
   * @see RFC 9807 Section 4.2 - Recover envelope (RecoverEnvelope)
   * @private
   */
  private recover(
    randomizedPassword: Uint8Array,
    serverPublicKey: Uint8Array,
    envelope: Envelope,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array
  ): {
    clientPrivateKey: Uint8Array
    clientKeypairSeed: Uint8Array
    cleartextCredentials: CleartextCredentials
    exportKey: Uint8Array
  } {
    this.validateX25519PublicKey(serverPublicKey)
    this.validateEnvelope(envelope)

    // Derive keys from randomized password
    const authKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelope.nonce, new TextEncoder().encode('AuthKey')), this.CONFIG.Nh)
    const exportKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelope.nonce, new TextEncoder().encode('ExportKey')), this.CONFIG.Nh)
    const seedEncryptionKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelope.nonce, new TextEncoder().encode('SeedKey')), this.CONFIG.Nseed)
    // Decrypt client keypair seed
    const clientKeypairSeed: Uint8Array = this.xor(envelope.seed, seedEncryptionKey)

    const { privateKey: clientPrivateKey, publicKey: clientPublicKey } = this.deriveDiffieHellmanKeyPair(clientKeypairSeed)

    // Construct cleartext credentials
    const serverId: Uint8Array = serverIdentity || serverPublicKey
    const clientId: Uint8Array = clientIdentity || clientPublicKey
    // Verify authentication tag
    const expectedTagInput: Uint8Array = this.concat(envelope.nonce, envelope.seed, serverPublicKey, this.i2OSP(serverId.length, 2), serverId, this.i2OSP(clientId.length, 2), clientId)
    const expectedTag: Uint8Array = hmac(sha512, authKey, expectedTagInput)

    if (!this.ctEqual(envelope.authTag, expectedTag)) {
      this.secureZeroMultiple(authKey, exportKey, clientPrivateKey, clientKeypairSeed, seedEncryptionKey)
      throw new Error('EnvelopeRecoveryError: Invalid password or corrupted envelope')
    }

    const cleartextCredentials: CleartextCredentials = {
      clientIdentity: clientId,
      serverIdentity: serverId,
      clientPublicKey,
      serverPublicKey
    }

    this.secureZeroMultiple(seedEncryptionKey, authKey)

    return {
      clientPrivateKey,
      clientKeypairSeed,
      cleartextCredentials,
      exportKey
    }
  }

  /**
   * Creates a credential request for password authentication.
   *
   * Blinds the password and creates the initial credential request message
   * to send to the server during authentication. The blind value must be
   * kept secret by the client.
   *
   * @param password - The user's password.
   * @returns Object containing:
   *   - request: The credential request to send to server
   *   - blind: The blinding factor (must be kept secret)
   * @see RFC 9807 Section 5.1 - Credential request
   * @private
   */
  private createCredentialRequest(password: string): { request: CredentialRequest; blind: Uint8Array } {
    const passwordBytes: Uint8Array = new TextEncoder().encode(password)
    const { blind, blindedElement } = this.blind(passwordBytes)

    this.secureZero(passwordBytes)

    return { request: { blindedMessage: blindedElement }, blind }
  }

  /**
   * Creates a credential response from the server.
   *
   * Evaluates the client's blinded message using the server's OPRF key,
   * then masks the response envelope and server public key to protect
   * against offline attacks. The masking ensures an attacker cannot
   * verify password guesses without online interaction.
   *
   * @param request - The credential request from the client.
   * @param serverPublicKey - The server's public key.
   * @param record - The stored registration record for this credential.
   * @param credentialIdentifier - The identifier for this credential.
   * @param oprfSeed - The server's master OPRF seed.
   * @returns The masked credential response to send to the client.
   * @see RFC 9807 Section 5.1 - Credential response
   * @private
   */
  private createCredentialResponse(request: CredentialRequest, serverPublicKey: Uint8Array, record: RegistrationRecord, credentialIdentifier: Uint8Array, oprfSeed: Uint8Array): CredentialResponse {
    this.validateRistretto255Element(request.blindedMessage)

    // Derive OPRF key from seed and credential identifier
    const seed: Uint8Array = this.expand(oprfSeed, this.concat(credentialIdentifier, new TextEncoder().encode('OprfKey')), this.CONFIG.Nok)

    const { privateKey: oprfKey } = this.deriveOprfKeyPair(seed, 'RFCXXXX-DeriveKeyPair')

    const evaluatedElement: Uint8Array = this.blindEvaluate(oprfKey, request.blindedMessage)
    // Create masked response to protect envelope
    const maskingNonce: Uint8Array = randomBytes(this.CONFIG.Nn)
    const credentialResponsePad: Uint8Array = this.expand(
      record.maskingKey,
      this.concat(maskingNonce, new TextEncoder().encode('CredentialResponsePad')),
      this.CONFIG.Npk + this.CONFIG.Nn + this.CONFIG.Nm + this.CONFIG.Nseed
    )
    const envelopeBytes: Uint8Array = this.concat(record.envelope.nonce, record.envelope.authTag, record.envelope.seed)
    const maskedResponse: Uint8Array = this.xor(credentialResponsePad, this.concat(serverPublicKey, envelopeBytes))

    this.secureZeroMultiple(seed, oprfKey, credentialResponsePad)

    return { evaluatedMessage: evaluatedElement, maskingNonce, maskedResponse }
  }

  /**
   * Retrieves a registration record with constant-time lookup.
   *
   * Performs a constant-time database lookup to retrieve the registration
   * record for a given credential identifier. If no record exists, returns
   * a fake record to prevent timing attacks that could reveal whether a
   * credential exists in the database.
   *
   * @param credentialIdentifier - The identifier to lookup.
   * @param recordStore - The map containing registration records.
   * @returns The registration record (real or fake).
   * @private
   */
  private getRecordWithConstantTiming(credentialIdentifier: Uint8Array, recordStore: Map<string, RegistrationRecord>): RegistrationRecord {
    const key: string = uint8ArrayToBase64(credentialIdentifier)
    const fakeRecord: RegistrationRecord = this.createFakeRegistrationRecord()

    let selectedRecord: RegistrationRecord = fakeRecord

    for (const [storeKey, storeRecord] of recordStore.entries()) {
      const match = this.ctEqualStrings(key, storeKey) ? 1 : 0
      if (match === 1) {
        selectedRecord = storeRecord
      }
    }
    return selectedRecord
  }

  /**
   * Recovers credentials from a masked server response.
   *
   * Finalizes the OPRF to derive the randomized password, applies MHF hardening,
   * unmasks the credential response to extract the envelope, and recovers the
   * client's credential material by decrypting the envelope.
   *
   * @param password - The user's password.
   * @param blind - The blinding factor from credential request.
   * @param response - The masked credential response from server.
   * @param serverIdentity - Optional server identity.
   * @param clientIdentity - Optional client identity.
   * @returns Object containing:
   *   - clientPrivateKey: The client's private key
   *   - clientKeypairSeed: The client's keypair seed
   *   - cleartextCredentials: The credential structure
   *   - exportKey: Additional key for application use
   * @throws {Error} If credential response is invalid or password is incorrect.
   * @see RFC 9807 Section 5.1 - Recover credentials
   * @private
   */
  private recoverCredentials(
    password: string,
    blind: Uint8Array,
    response: CredentialResponse,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array
  ): {
    clientPrivateKey: Uint8Array
    clientKeypairSeed: Uint8Array
    cleartextCredentials: CleartextCredentials
    exportKey: Uint8Array
  } {
    const passwordBytes: Uint8Array = new TextEncoder().encode(password)
    // Finalize OPRF to get output
    const oprfOutput: Uint8Array = this.finalize(passwordBytes, blind, response.evaluatedMessage)
    // Apply hardening (MHF)
    const mhfSalt: Uint8Array = this.expand(oprfOutput, new TextEncoder().encode('OPAQUE-HashToScalar'), 16)
    const hardenedOutput: Uint8Array = this.hardening(oprfOutput, mhfSalt)
    // Derive randomized password
    const randomizedPassword: Uint8Array = this.extract(null, this.concat(oprfOutput, hardenedOutput))
    // Derive masking key to unmask response
    const maskingKey: Uint8Array = this.expand(randomizedPassword, new TextEncoder().encode('MaskingKey'), this.CONFIG.Nh)
    const credentialResponsePad: Uint8Array = this.expand(
      maskingKey,
      this.concat(response.maskingNonce, new TextEncoder().encode('CredentialResponsePad')),
      this.CONFIG.Npk + this.CONFIG.Nn + this.CONFIG.Nm + this.CONFIG.Nseed
    )
    const unmasked: Uint8Array = this.xor(credentialResponsePad, response.maskedResponse)

    if (unmasked.length < this.CONFIG.Npk + this.CONFIG.Nn + this.CONFIG.Nm + this.CONFIG.Nseed) {
      this.secureZeroMultiple(passwordBytes, oprfOutput, mhfSalt, hardenedOutput, randomizedPassword, maskingKey, credentialResponsePad, unmasked)
      throw new Error('Invalid credential response: insufficient data')
    }

    // Extract envelope components
    const serverPublicKey: Uint8Array = unmasked.slice(0, this.CONFIG.Npk)
    const envelopeNonce: Uint8Array = unmasked.slice(this.CONFIG.Npk, this.CONFIG.Npk + this.CONFIG.Nn)
    const authTag: Uint8Array = unmasked.slice(this.CONFIG.Npk + this.CONFIG.Nn, this.CONFIG.Npk + this.CONFIG.Nn + this.CONFIG.Nm)
    const seed: Uint8Array = unmasked.slice(this.CONFIG.Npk + this.CONFIG.Nn + this.CONFIG.Nm)
    const envelope: Envelope = { nonce: envelopeNonce, authTag, seed }
    // Recover credentials from envelope
    const result = this.recover(randomizedPassword, serverPublicKey, envelope, serverIdentity, clientIdentity)

    this.secureZeroMultiple(passwordBytes, oprfOutput, mhfSalt, hardenedOutput, randomizedPassword, maskingKey, credentialResponsePad, unmasked)

    return result
  }

  /**
   * Builds the protocol transcript preamble for key derivation.
   *
   * Constructs a transcript of all protocol messages exchanged so far,
   * including identities, nonces, and key shares. This preamble is used
   * to derive session keys that are cryptographically bound to the entire
   * protocol execution.
   *
   * @param clientIdentity - The client's identity.
   * @param ke1 - The KE1 message from the client.
   * @param serverIdentity - The server's identity.
   * @param credentialResponse - The credential response from server.
   * @param serverNonce - The server's nonce.
   * @param serverPublicKeyshare - The server's ephemeral public key.
   * @returns The encoded preamble bytes.
   * @see RFC 9807 Section 6.2.1 - Preamble construction
   * @private
   */
  private preamble(clientIdentity: Uint8Array, ke1: KE1, serverIdentity: Uint8Array, credentialResponse: CredentialResponse, serverNonce: Uint8Array, serverPublicKeyshare: Uint8Array): Uint8Array {
    const context: Uint8Array = new TextEncoder().encode(this.CONFIG.context)
    const ke1Bytes: Uint8Array = this.concat(ke1.credentialRequest.blindedMessage, ke1.authRequest.clientNonce, ke1.authRequest.clientPublicKeyshare)
    const credRespBytes: Uint8Array = this.concat(credentialResponse.evaluatedMessage, credentialResponse.maskingNonce, credentialResponse.maskedResponse)

    return this.concat(
      new TextEncoder().encode('RFCXXXX'),
      this.i2OSP(context.length, 2),
      context,
      this.i2OSP(clientIdentity.length, 2),
      clientIdentity,
      ke1Bytes,
      this.i2OSP(serverIdentity.length, 2),
      serverIdentity,
      credRespBytes,
      serverNonce,
      serverPublicKeyshare
    )
  }

  /**
   * Expands a secret with a label and context (TLS 1.3 style).
   *
   * Derives keying material from a secret using a labeled expand operation
   * similar to TLS 1.3. The label provides domain separation and the context
   * allows binding to specific protocol state.
   *
   * @param secret - The secret to expand from.
   * @param label - The domain separation label.
   * @param context - Additional context information.
   * @param length - Desired output length in bytes.
   * @returns The derived keying material.
   * @throws {Error} If label/context is too long or length is invalid.
   * @see RFC 9807 Section 6.2.2 - Expand label
   * @private
   */
  private expandLabel(secret: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array {
    if (!label || label.length === 0) {
      throw new Error('Label cannot be empty')
    }

    const labelBytes: Uint8Array = new TextEncoder().encode('RFCXXXX ' + label)

    if (labelBytes.length > 255) {
      throw new Error(`Label too long: "${label}" (max 255 bytes including prefix)`)
    }

    if (context.length > 255) {
      throw new Error(`Context too long: ${context.length} bytes (max 255 bytes)`)
    }

    if (length > 255 * this.CONFIG.Nh) {
      throw new Error(`Requested length too large: ${length} bytes`)
    }

    if (length === 0) {
      throw new Error('Requested length cannot be zero')
    }

    const customLabel: Uint8Array = this.concat(this.i2OSP(length, 2), new Uint8Array([labelBytes.length]), labelBytes, new Uint8Array([context.length]), context)

    return this.expand(secret, customLabel, length)
  }

  /**
   * Derives a secret with transcript hashing.
   *
   * Hashes the transcript if non-empty, then derives a secret using the
   * labeled expand operation. This binds derived secrets to the protocol
   * transcript for authentication.
   *
   * @param secret - The secret to derive from.
   * @param label - The domain separation label.
   * @param transcript - The protocol transcript.
   * @returns The derived secret.
   * @see RFC 9807 Section 6.2.2 - Derive secret
   * @private
   */
  private deriveSecret(secret: Uint8Array, label: string, transcript: Uint8Array): Uint8Array {
    const transcriptHash: Uint8Array = transcript.length > 0 ? sha512(transcript) : transcript
    return this.expandLabel(secret, label, transcriptHash, this.CONFIG.Nh)
  }

  /**
   * Derives all session keys from shared secret and preamble.
   *
   * Uses the HKDF-based key schedule to derive multiple keys from the
   * shared secret established via triple-DH. Produces MAC keys for mutual
   * authentication and a session key for the application.
   *
   * @param ikm - The input keying material (concatenated DH outputs).
   * @param preamble - The protocol transcript preamble.
   * @returns Object containing:
   *   - km2: Server MAC key
   *   - km3: Client MAC key
   *   - sessionKey: Authenticated session key
   * @see RFC 9807 Section 6.2.2 - Key derivation
   * @private
   */
  private deriveKeys(ikm: Uint8Array, preamble: Uint8Array): { km2: Uint8Array; km3: Uint8Array; sessionKey: Uint8Array } {
    const prk: Uint8Array = this.extract(null, ikm)
    const preambleHash: Uint8Array = sha512(preamble)
    const handshakeSecret: Uint8Array = this.deriveSecret(prk, 'HandshakeSecret', preambleHash)
    const sessionKey: Uint8Array = this.deriveSecret(prk, 'SessionKey', preambleHash)
    const km2: Uint8Array = this.deriveSecret(handshakeSecret, 'ServerMAC', new Uint8Array(0))
    const km3: Uint8Array = this.deriveSecret(handshakeSecret, 'ClientMAC', new Uint8Array(0))

    this.secureZeroMultiple(prk, handshakeSecret)

    return { km2, km3, sessionKey }
  }

  /**
   * Concatenates multiple byte arrays into a single array.
   *
   * @param arrays - Variable number of byte arrays to concatenate.
   * @returns A new array containing all input arrays concatenated.
   * @private
   */
  private concat(...arrays: Uint8Array[]): Uint8Array {
    const totalLength: number = arrays.reduce((sum, arr) => sum + arr.length, 0)
    const result: Uint8Array = new Uint8Array(totalLength)

    let offset: number = 0
    for (const arr of arrays) {
      result.set(arr, offset)
      offset += arr.length
    }
    return result
  }

  /**
   * Performs bitwise XOR on two equal-length byte arrays.
   *
   * @param a - First byte array.
   * @param b - Second byte array (must be same length as a).
   * @returns New array where each byte is a[i] XOR b[i].
   * @throws {Error} If input arrays have different lengths.
   * @private
   */
  private xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length !== b.length) {
      throw new Error('XOR inputs must be equal length')
    }
    const result: Uint8Array = new Uint8Array(a.length)
    for (let i = 0; i < a.length; i++) {
      result[i] = a[i] ^ b[i]
    }
    return result
  }

  /**
   * Integer to Octet String Primitive - converts integer to big-endian bytes.
   *
   * Encodes a non-negative integer as a big-endian byte array of specified
   * length. Used for length encoding in protocol messages.
   *
   * @param value - The non-negative integer to encode.
   * @param length - The desired output length in bytes.
   * @returns The big-endian byte representation.
   * @throws {Error} If value is negative, length is non-positive, or value
   *   is too large for the specified length.
   * @see RFC 8017 - I2OSP (Integer to Octet String Primitive)
   * @private
   */
  private i2OSP(value: number, length: number): Uint8Array {
    if (value < 0) {
      throw new Error('i2OSP: value must be non-negative')
    }
    if (length <= 0) {
      throw new Error('i2OSP: length must be positive')
    }
    const result: Uint8Array = new Uint8Array(length)
    for (let i = length - 1; i >= 0; i--) {
      result[i] = value & 0xff
      value >>= 8
    }
    if (value !== 0) {
      throw new Error('i2OSP: value too large for specified length')
    }
    return result
  }

  /**
   * Constant-time equality comparison for byte arrays.
   *
   * Compares two byte arrays in constant time to prevent timing attacks.
   * Always checks all bytes regardless of where a mismatch occurs.
   *
   * @param a - First byte array.
   * @param b - Second byte array.
   * @returns True if arrays are equal, false otherwise.
   * @private
   */
  private ctEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    let result: number = 0
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i]
    }
    return result === 0
  }

  /**
   * Constant-time equality comparison for strings.
   *
   * Compares two strings in constant time to prevent timing attacks.
   * Always checks all characters regardless of where a mismatch occurs.
   *
   * @param a - First string.
   * @param b - Second string.
   * @returns True if strings are equal, false otherwise.
   * @private
   */
  private ctEqualStrings(a: string, b: string): boolean {
    if (a.length !== b.length) return false
    let result: number = 0
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i)
    }
    return result === 0
  }

  /**
   * Computes modular multiplicative inverse using Extended Euclidean Algorithm.
   *
   * Finds the multiplicative inverse of a modulo m, i.e., finds x such that
   * (a * x) mod m = 1. Used for unblinding in the OPRF finalize operation.
   *
   * @param a - The value to invert.
   * @param m - The modulus (must be greater than 1).
   * @returns The modular inverse of a modulo m.
   * @throws {Error} If modulus is invalid, a is zero, or no inverse exists.
   * @private
   */
  private modInverse(a: bigint, m: bigint): bigint {
    if (m === 0n || m === 1n) {
      throw new Error('Modulus must be greater than 1')
    }

    const origA: bigint = a
    a = ((a % m) + m) % m

    if (a === 0n) {
      throw new Error('Cannot compute modular inverse of 0')
    }

    const gcd: { gcd: bigint; x: bigint; y: bigint } = this.extendedGCD(a, m)
    if (gcd.gcd !== 1n) {
      throw new Error(`No modular inverse exists: gcd(${origA}, ${m}) = ${gcd.gcd}`)
    }

    return ((gcd.x % m) + m) % m
  }

  /**
   * Extended Euclidean Algorithm for computing GCD and Bézout coefficients.
   *
   * Computes the greatest common divisor of a and b, along with coefficients
   * x and y such that ax + by = gcd(a, b).
   *
   * @param a - First integer.
   * @param b - Second integer.
   * @returns Object containing:
   *   - gcd: The greatest common divisor
   *   - x: First Bézout coefficient
   *   - y: Second Bézout coefficient
   * @private
   */
  private extendedGCD(a: bigint, b: bigint): { gcd: bigint; x: bigint; y: bigint } {
    if (b === 0n) {
      return { gcd: a, x: 1n, y: 0n }
    }

    const result: { gcd: bigint; x: bigint; y: bigint } = this.extendedGCD(b, a % b)
    return {
      gcd: result.gcd,
      x: result.y,
      y: result.x - (a / b) * result.y
    }
  }

  /**
   * Converts a byte array to a scalar (little-endian).
   *
   * Interprets 32 bytes as a little-endian integer and reduces it modulo
   * the ristretto255 group order. Used for converting random bytes to
   * valid scalars.
   *
   * @param bytes - The byte array to convert (must be 32 bytes).
   * @returns The scalar value modulo the group order.
   * @throws {Error} If bytes is not exactly 32 bytes.
   * @private
   */
  private bytesToScalar(bytes: Uint8Array): bigint {
    if (bytes.length !== 32) {
      throw new Error('Scalar bytes must be 32 bytes')
    }

    let scalar: bigint = 0n

    for (let i = 31; i >= 0; i--) {
      scalar = (scalar << 8n) | BigInt(bytes[i])
    }

    const n: bigint = ed25519.Point.CURVE().n
    return scalar % n
  }

  /**
   * Converts a scalar to a byte array (little-endian).
   *
   * Encodes a bigint scalar as a 32-byte little-endian array after reducing
   * modulo the group order. Used for serializing scalars.
   *
   * @param scalar - The scalar value to convert.
   * @returns The 32-byte little-endian representation.
   * @private
   */
  private scalarToBytes(scalar: bigint): Uint8Array {
    const n: bigint = ed25519.Point.CURVE().n
    const normalized = ((scalar % n) + n) % n
    const bytes: Uint8Array = new Uint8Array(32)
    let s: bigint = normalized

    for (let i = 0; i < 32; i++) {
      bytes[i] = Number(s & 0xffn)
      s >>= 8n
    }
    return bytes
  }

  /**
   * Securely zeros a byte array.
   *
   * Overwrites all bytes with zeros to remove sensitive data from memory.
   * This provides defense-in-depth against memory disclosure attacks.
   *
   * @param array - The array to zero.
   * @private
   */
  private secureZero(array: Uint8Array): void {
    if (array && array.length > 0) {
      array.fill(0)
    }
  }

  /**
   * Securely zeros multiple byte arrays.
   *
   * Convenience method to zero multiple arrays in a single call.
   * Handles undefined arrays gracefully.
   *
   * @param arrays - Variable number of arrays to zero (undefined values are skipped).
   * @private
   */
  private secureZeroMultiple(...arrays: (Uint8Array | undefined)[]): void {
    for (const array of arrays) {
      if (array) {
        this.secureZero(array)
      }
    }
  }

  /**
   * Creates a registration request to begin the registration protocol.
   *
   * The client creates a blinded version of their password and sends it to
   * the server. The blind value must be kept secret and used later to finalize
   * registration.
   *
   * This represents the first step of the OPAQUE registration flow.
   *
   * @param password - The user's password (max 1024 bytes).
   * @returns Object containing:
   *   - request: The registration request to send to server
   *   - blind: The blinding factor (must be kept secret)
   * @throws {Error} If password is empty or exceeds 1024 bytes.
   * @see RFC 9807 Section 5.1.1 - Client creates registration request
   * @public
   */
  public createRegistrationRequest(password: string): { request: RegistrationRequest; blind: Uint8Array } {
    if (!password || password.length === 0) {
      throw new Error('Password cannot be empty')
    }

    const passwordBytes: Uint8Array = new TextEncoder().encode(password)

    if (passwordBytes.length > 1024) {
      this.secureZero(passwordBytes)
      throw new Error('Password too long (max 1024 bytes)')
    }

    const { blind, blindedElement } = this.blind(passwordBytes)

    this.secureZero(passwordBytes)

    return { request: { blindedMessage: blindedElement }, blind }
  }

  /**
   * Creates a registration response from the server.
   *
   * The server evaluates the client's blinded password using its OPRF key
   * derived from the credential identifier. Returns the evaluated element
   * and server's public key.
   *
   * This represents the second step of the OPAQUE registration flow.
   *
   * @param request - The registration request from the client.
   * @param serverPublicKey - The server's long-term public key.
   * @param credentialIdentifier - Unique identifier for this credential (max 256 bytes).
   * @param oprfSeed - The server's master OPRF seed (must be Nh bytes).
   * @returns The registration response to send to client.
   * @throws {Error} If inputs are invalid or credential identifier is too long.
   * @see RFC 9807 Section 5.1.2 - Server creates registration response
   * @public
   */
  public createRegistrationResponse(request: RegistrationRequest, serverPublicKey: Uint8Array, credentialIdentifier: Uint8Array, oprfSeed: Uint8Array): RegistrationResponse {
    this.validateRistretto255Element(request.blindedMessage)
    this.validateX25519PublicKey(serverPublicKey)

    if (credentialIdentifier.length === 0) {
      throw new Error('credentialIdentifier cannot be empty')
    }

    if (credentialIdentifier.length > 256) {
      throw new Error('credentialIdentifier too long (max 256 bytes)')
    }

    if (oprfSeed.length !== this.CONFIG.Nh) {
      throw new Error(`oprfSeed must be ${this.CONFIG.Nh} bytes`)
    }

    const seed: Uint8Array = this.expand(oprfSeed, this.concat(credentialIdentifier, new TextEncoder().encode('OprfKey')), this.CONFIG.Nok)

    const { privateKey: oprfKey } = this.deriveOprfKeyPair(seed, 'RFCXXXX-DeriveKeyPair')

    const evaluatedElement: Uint8Array = this.blindEvaluate(oprfKey, request.blindedMessage)

    this.secureZeroMultiple(seed, oprfKey)

    return { evaluatedMessage: evaluatedElement, serverPublicKey }
  }

  /**
   * Finalizes the registration protocol on the client side.
   *
   * The client unblinds the server's response, applies password hardening,
   * derives the randomized password, and creates an encrypted envelope
   * containing the client's private key material. The resulting registration
   * record is stored by the server.
   *
   * This represents the third and final step of the OPAQUE registration flow.
   *
   * @param password - The user's password.
   * @param blind - The blinding factor from the registration request.
   * @param response - The registration response from the server.
   * @param serverIdentity - Optional server identity (defaults to serverPublicKey).
   * @param clientIdentity - Optional client identity (defaults to clientPublicKey).
   * @returns Object containing:
   *   - record: The registration record to store on server
   *   - exportKey: Additional key for application use
   *   - clientKeypairSeed: The client's keypair seed (should be stored securely)
   * @see RFC 9807 Section 5.1.3 - Client finalizes registration
   * @public
   */
  public finalizeRegistrationRequest(
    password: string,
    blind: Uint8Array,
    response: RegistrationResponse,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array
  ): {
    record: RegistrationRecord
    exportKey: Uint8Array
    clientKeypairSeed: Uint8Array
  } {
    const passwordBytes: Uint8Array = new TextEncoder().encode(password)
    const oprfOutput: Uint8Array = this.finalize(passwordBytes, blind, response.evaluatedMessage)
    // Apply hardening
    const mhfSalt: Uint8Array = this.expand(oprfOutput, new TextEncoder().encode('OPAQUE-HashToScalar'), 16)
    const hardenedOutput: Uint8Array = this.hardening(oprfOutput, mhfSalt)
    const randomizedPassword: Uint8Array = this.extract(null, this.concat(oprfOutput, hardenedOutput))
    const clientKeypairSeed: Uint8Array = randomBytes(this.CONFIG.Nseed)

    const { envelope, clientPublicKey, maskingKey, exportKey } = this.store(randomizedPassword, response.serverPublicKey, serverIdentity, clientIdentity, clientKeypairSeed)

    this.secureZeroMultiple(passwordBytes, oprfOutput, mhfSalt, hardenedOutput, randomizedPassword)

    return {
      record: { clientPublicKey, maskingKey, envelope },
      exportKey,
      clientKeypairSeed
    }
  }

  /**
   * Generates the first message (KE1) of the authentication protocol.
   *
   * The client creates a credential request (blinded password), generates
   * an ephemeral DH keypair, and combines them into KE1. The returned state
   * must be preserved for processing KE2.
   *
   * This initiates the authenticated key exchange (AKE) protocol.
   *
   * @param password - The user's password.
   * @returns Object containing:
   *   - ke1: The KE1 message to send to server
   *   - state: Client state that must be preserved for KE3 generation
   * @see RFC 9807 Section 6.2.3 - Client generates KE1
   * @public
   */
  public generateKE1(password: string): { ke1: KE1; state: ClientState } {
    const { request, blind } = this.createCredentialRequest(password)

    const clientNonce: Uint8Array = randomBytes(this.CONFIG.Nn)
    const clientKeyshareSeed: Uint8Array = randomBytes(this.CONFIG.Nseed)

    const { privateKey: clientSecret, publicKey: clientPublicKeyshare } = this.deriveDiffieHellmanKeyPair(clientKeyshareSeed)

    this.secureZero(clientKeyshareSeed)

    const authRequest: AuthRequest = { clientNonce, clientPublicKeyshare }
    const ke1: KE1 = { credentialRequest: request, authRequest }
    const state: ClientState = { password, blind, clientSecret, ke1 }

    return { ke1, state }
  }

  /**
   * Generates the second message (KE2) of the authentication protocol.
   *
   * The server retrieves the registration record, creates a credential response,
   * generates an ephemeral DH keypair, performs triple-DH to establish a shared
   * secret, derives session keys, and creates a MAC for server authentication.
   *
   * This represents the server's response in the AKE protocol.
   *
   * @param serverIdentity - Optional server identity (defaults to serverPublicKey).
   * @param serverPrivateKey - The server's long-term private key.
   * @param serverPublicKey - The server's long-term public key.
   * @param record - The stored registration record for this credential.
   * @param credentialIdentifier - The identifier for this credential.
   * @param oprfSeed - The server's master OPRF seed.
   * @param ke1 - The KE1 message from the client.
   * @param clientIdentity - Optional client identity (defaults to client's public key).
   * @returns Object containing:
   *   - ke2: The KE2 message to send to client
   *   - state: Server state containing expected client MAC and session key
   * @throws {Error} If any validation fails or keys are invalid.
   * @see RFC 9807 Section 6.2.4 - Server generates KE2
   * @public
   */
  public generateKE2(
    serverIdentity: Uint8Array | undefined,
    serverPrivateKey: Uint8Array,
    serverPublicKey: Uint8Array,
    record: RegistrationRecord,
    credentialIdentifier: Uint8Array,
    oprfSeed: Uint8Array,
    ke1: KE1,
    clientIdentity?: Uint8Array
  ): {
    ke2: KE2
    state: ServerState
  } {
    if (serverPrivateKey.length !== this.CONFIG.Nsk) {
      throw new Error('Invalid server private key length')
    }

    this.validateX25519PublicKey(serverPublicKey)
    this.validateRistretto255Element(ke1.credentialRequest.blindedMessage)
    this.validateNonce(ke1.authRequest.clientNonce)
    this.validateX25519PublicKey(ke1.authRequest.clientPublicKeyshare)
    this.validateX25519PublicKey(record.clientPublicKey)
    this.validateEnvelope(record.envelope)

    if (record.maskingKey.length !== this.CONFIG.Nh) {
      throw new Error('Invalid masking key length')
    }

    if (credentialIdentifier.length === 0) {
      throw new Error('credentialIdentifier cannot be empty')
    }

    if (oprfSeed.length !== this.CONFIG.Nh) {
      throw new Error('Invalid OPRF seed length')
    }

    const credentialResponse: CredentialResponse = this.createCredentialResponse(ke1.credentialRequest, serverPublicKey, record, credentialIdentifier, oprfSeed)
    const cleartextCredentials: CleartextCredentials = this.createCleartextCredentials(serverPublicKey, record.clientPublicKey, serverIdentity, clientIdentity)
    const serverNonce: Uint8Array = randomBytes(this.CONFIG.Nn)
    const serverKeyshareSeed: Uint8Array = randomBytes(this.CONFIG.Nseed)

    const { privateKey: serverPrivateKeyshare, publicKey: serverPublicKeyshare } = this.deriveDiffieHellmanKeyPair(serverKeyshareSeed)

    const preamble: Uint8Array = this.preamble(cleartextCredentials.clientIdentity, ke1, cleartextCredentials.serverIdentity, credentialResponse, serverNonce, serverPublicKeyshare)
    // Triple DH
    const dh1: Uint8Array = this.diffieHellman(serverPrivateKeyshare, ke1.authRequest.clientPublicKeyshare)
    const dh2: Uint8Array = this.diffieHellman(serverPrivateKey, ke1.authRequest.clientPublicKeyshare)
    const dh3: Uint8Array = this.diffieHellman(serverPrivateKeyshare, record.clientPublicKey)
    const ikm: Uint8Array = this.concat(dh1, dh2, dh3)

    const { km2, km3, sessionKey } = this.deriveKeys(ikm, preamble)

    const preambleHash: Uint8Array = sha512(preamble)
    const serverMac: Uint8Array = hmac(sha512, km2, preambleHash)
    const expectedClientMac: Uint8Array = hmac(sha512, km3, sha512(this.concat(preamble, serverMac)))

    this.secureZeroMultiple(serverKeyshareSeed, serverPrivateKeyshare, dh1, dh2, dh3, ikm, km2, km3, preambleHash)

    const authResponse: AuthResponse = {
      serverNonce,
      serverPublicKeyshare,
      serverMac
    }

    const ke2: KE2 = {
      credentialResponse,
      authResponse
    }

    const state: ServerState = {
      expectedClientMac,
      sessionKey
    }

    return { ke2, state }
  }

  /**
   * Generates the third message (KE3) of the authentication protocol.
   *
   * The client recovers credentials from the masked response, verifies the
   * server's MAC to authenticate the server, performs triple-DH, derives
   * session keys, and creates a MAC for client authentication.
   *
   * This represents the final client message in the AKE protocol.
   *
   * @param state - The client state from KE1 generation.
   * @param ke2 - The KE2 message from the server.
   * @param serverIdentity - Optional server identity (must match registration).
   * @param clientIdentity - Optional client identity (must match registration).
   * @returns Object containing:
   *   - ke3: The KE3 message to send to server
   *   - sessionKey: The authenticated session key
   *   - exportKey: Additional key for application use
   *   - clientKeypairSeed: The recovered client keypair seed
   * @throws {Error} ServerAuthenticationError if server MAC verification fails.
   * @see RFC 9807 Section 6.2.5 - Client generates KE3
   * @public
   */
  public generateKE3(
    state: ClientState,
    ke2: KE2,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array
  ): {
    ke3: KE3
    sessionKey: Uint8Array
    exportKey: Uint8Array
    clientKeypairSeed: Uint8Array
  } {
    this.validateRistretto255Element(ke2.credentialResponse.evaluatedMessage)
    this.validateNonce(ke2.credentialResponse.maskingNonce)
    this.validateNonce(ke2.authResponse.serverNonce)
    this.validateX25519PublicKey(ke2.authResponse.serverPublicKeyshare)
    this.validateMAC(ke2.authResponse.serverMac)

    const { clientPrivateKey, clientKeypairSeed, cleartextCredentials, exportKey } = this.recoverCredentials(state.password, state.blind, ke2.credentialResponse, serverIdentity, clientIdentity)

    const preamble: Uint8Array = this.preamble(
      cleartextCredentials.clientIdentity,
      state.ke1,
      cleartextCredentials.serverIdentity,
      ke2.credentialResponse,
      ke2.authResponse.serverNonce,
      ke2.authResponse.serverPublicKeyshare
    )

    // Triple DH
    const dh1: Uint8Array = this.diffieHellman(state.clientSecret, ke2.authResponse.serverPublicKeyshare)
    const dh2: Uint8Array = this.diffieHellman(state.clientSecret, cleartextCredentials.serverPublicKey)
    const dh3: Uint8Array = this.diffieHellman(clientPrivateKey, ke2.authResponse.serverPublicKeyshare)
    const ikm: Uint8Array = this.concat(dh1, dh2, dh3)

    const { km2, km3, sessionKey } = this.deriveKeys(ikm, preamble)

    const preambleHash: Uint8Array = sha512(preamble)
    const expectedServerMac: Uint8Array = hmac(sha512, km2, preambleHash)

    if (!this.ctEqual(ke2.authResponse.serverMac, expectedServerMac)) {
      this.secureZeroMultiple(clientPrivateKey, exportKey, clientKeypairSeed, dh1, dh2, dh3, ikm, km2, km3, sessionKey, preambleHash)
      throw new Error('ServerAuthenticationError: Invalid server MAC')
    }

    const clientMac: Uint8Array = hmac(sha512, km3, sha512(this.concat(preamble, expectedServerMac)))
    const ke3: KE3 = { clientMac }

    this.secureZeroMultiple(clientPrivateKey, dh1, dh2, dh3, ikm, km2, km3, expectedServerMac, preambleHash)

    return { ke3, sessionKey, exportKey, clientKeypairSeed }
  }

  /**
   * Verifies the client's KE3 MAC for authentication.
   *
   * Performs constant-time comparison of the client's MAC against the
   * expected MAC computed during KE2 generation. This authenticates the
   * client to the server.
   *
   * @param ke3ClientMac - The client MAC from the KE3 message.
   * @param expectedClientMac - The expected MAC from server state.
   * @returns True if MACs match (authentication successful), false otherwise.
   * @see RFC 9807 Section 6.2.6 - Server verifies KE3
   * @public
   */
  public verifyKE3(ke3ClientMac: Uint8Array, expectedClientMac: Uint8Array): boolean {
    try {
      if (ke3ClientMac.length !== this.CONFIG.Nm) {
        return false
      }

      if (expectedClientMac.length !== this.CONFIG.Nm) {
        return false
      }

      return this.ctEqual(ke3ClientMac, expectedClientMac)
    } catch (_error) {
      return false
    }
  }

  /**
   * Finalizes server-side authentication after KE3 verification.
   *
   * Verifies the client's MAC in constant time. If verification succeeds,
   * returns the authenticated session key. If verification fails, securely
   * zeros the session key and throws an error.
   *
   * This completes the server's side of the AKE protocol.
   *
   * @param state - The server state from KE2 generation.
   * @param ke3 - The KE3 message from the client.
   * @returns The authenticated session key for this session.
   * @throws {Error} ClientAuthenticationError if client MAC verification fails.
   * @public
   */
  public serverFinish(state: ServerState, ke3: KE3): Uint8Array {
    this.validateMAC(ke3.clientMac)

    if (!this.ctEqual(ke3.clientMac, state.expectedClientMac)) {
      this.secureZero(state.sessionKey)
      throw new Error('ClientAuthenticationError: Invalid client MAC')
    }

    return state.sessionKey
  }

  /**
   * Generates a server keypair for OPAQUE operations.
   *
   * Creates a fresh X25519 keypair for use as the server's long-term
   * authentication keys. The private key should be stored securely by
   * the server.
   *
   * @returns Object containing:
   *   - privateKey: The server's private key (must be kept secret)
   *   - publicKey: The server's public key (shared with clients)
   * @public
   */
  public generateServerKeyPair(): {
    privateKey: Uint8Array
    publicKey: Uint8Array
  } {
    return this.deriveDiffieHellmanKeyPair(randomBytes(this.CONFIG.Nseed))
  }

  /**
   * Creates a fake registration record for timing attack resistance.
   *
   * Generates a structurally valid but cryptographically random registration
   * record. This is used when a credential lookup fails to ensure the protocol
   * execution takes constant time regardless of whether the credential exists.
   *
   * Prevents timing attacks that could enumerate valid usernames/credentials.
   *
   * @returns A fake registration record with random values.
   * @public
   */
  public createFakeRegistrationRecord(): RegistrationRecord {
    const fakeClientPublicKey: Uint8Array = randomBytes(this.CONFIG.Npk)
    const fakeMaskingKey: Uint8Array = randomBytes(this.CONFIG.Nh)
    const fakeEnvelope: Envelope = {
      nonce: randomBytes(this.CONFIG.Nn),
      authTag: randomBytes(this.CONFIG.Nm),
      seed: randomBytes(this.CONFIG.Nseed)
    }

    return {
      clientPublicKey: fakeClientPublicKey,
      maskingKey: fakeMaskingKey,
      envelope: fakeEnvelope
    }
  }

  /**
   * Serializes a registration record to Base64 strings.
   *
   * Converts all binary fields in the registration record to Base64-encoded
   * strings for storage or transmission as JSON.
   *
   * @param record - The registration record to serialize.
   * @returns A serialized version with all fields as Base64 strings.
   * @public
   */
  public serializeRegistrationRecord(record: RegistrationRecord): RegistrationRecordSerialized {
    return {
      clientPublicKey: uint8ArrayToBase64(record.clientPublicKey),
      maskingKey: uint8ArrayToBase64(record.maskingKey),
      envelope: {
        nonce: uint8ArrayToBase64(record.envelope.nonce),
        authTag: uint8ArrayToBase64(record.envelope.authTag),
        seed: uint8ArrayToBase64(record.envelope.seed)
      }
    }
  }

  /**
   * Deserializes a registration record from Base64 strings.
   *
   * Converts Base64-encoded strings back to binary format and validates
   * all field lengths to ensure the record is well-formed.
   *
   * @param record - The serialized registration record.
   * @returns The deserialized registration record with binary fields.
   * @throws {Error} If any required field is missing, invalid, or has incorrect length.
   * @public
   */
  public deserializeRegistrationRecord(record: RegistrationRecordSerialized): RegistrationRecord {
    if (!record.clientPublicKey || !record.maskingKey || !record.envelope) {
      throw new Error('Missing required fields in RegistrationRecord')
    }

    if (!record.envelope.nonce || !record.envelope.authTag || !record.envelope.seed) {
      throw new Error('Missing required fields in envelope')
    }

    try {
      const clientPublicKey: Uint8Array = base64ToUint8Array(record.clientPublicKey)
      const maskingKey: Uint8Array = base64ToUint8Array(record.maskingKey)
      const envelope: Envelope = {
        nonce: base64ToUint8Array(record.envelope.nonce),
        authTag: base64ToUint8Array(record.envelope.authTag),
        seed: base64ToUint8Array(record.envelope.seed)
      }

      this.validateX25519PublicKey(clientPublicKey)

      if (maskingKey.length !== this.CONFIG.Nh) {
        throw new Error('Invalid maskingKey length')
      }

      this.validateEnvelope(envelope)

      return { clientPublicKey, maskingKey, envelope }
    } catch (error) {
      throw new Error(`Failed to deserialize RegistrationRecord: ${error}`)
    }
  }

  /**
   * Serializes a KE1 message to an object with Base64 strings.
   *
   * Converts the KE1 message components to Base64 for transmission.
   *
   * @param ke1 - The KE1 message to serialize.
   * @returns A serialized KE1 with all fields as Base64 strings.
   * @public
   */
  public serializeKE1(ke1: KE1): KE1Serialized {
    return {
      blindedMessage: uint8ArrayToBase64(ke1.credentialRequest.blindedMessage),
      clientNonce: uint8ArrayToBase64(ke1.authRequest.clientNonce),
      clientPublicKeyshare: uint8ArrayToBase64(ke1.authRequest.clientPublicKeyshare)
    }
  }

  /**
   * Deserializes a KE1 message from Base64 strings.
   *
   * Converts Base64-encoded strings back to binary format and validates
   * all field lengths (each component must be 32 bytes).
   *
   * @param serialized - The serialized KE1 message.
   * @returns The deserialized KE1 message with binary fields.
   * @throws {Error} If any field has incorrect length.
   * @public
   */
  public deserializeKE1(serialized: KE1Serialized): KE1 {
    const blindedMessage: Uint8Array = base64ToUint8Array(serialized.blindedMessage)
    const clientNonce: Uint8Array = base64ToUint8Array(serialized.clientNonce)
    const clientPublicKeyshare: Uint8Array = base64ToUint8Array(serialized.clientPublicKeyshare)

    if (blindedMessage.length !== 32) {
      throw new Error(`Invalid blindedMessage length: expected 32, got ${blindedMessage.length}`)
    }
    if (clientNonce.length !== 32) {
      throw new Error(`Invalid clientNonce length: expected 32, got ${clientNonce.length}`)
    }
    if (clientPublicKeyshare.length !== 32) {
      throw new Error(`Invalid clientPublicKeyshare length: expected 32, got ${clientPublicKeyshare.length}`)
    }

    return {
      credentialRequest: { blindedMessage },
      authRequest: { clientNonce, clientPublicKeyshare }
    }
  }

  /**
   * Serializes a KE1 message to a single compact Base64 string.
   *
   * Concatenates all KE1 components and encodes as a single Base64 string
   * for efficient transmission (96 bytes total).
   *
   * @param ke1 - The KE1 message to serialize.
   * @returns A compact Base64-encoded string.
   * @public
   */
  public serializeKE1Compact(ke1: KE1): string {
    const bytes: Uint8Array = this.concat(ke1.credentialRequest.blindedMessage, ke1.authRequest.clientNonce, ke1.authRequest.clientPublicKeyshare)
    return uint8ArrayToBase64(bytes)
  }

  /**
   * Deserializes a KE1 message from a compact Base64 string.
   *
   * Decodes and splits a compact Base64 string back into KE1 components.
   *
   * @param base64 - The compact Base64-encoded KE1.
   * @returns The deserialized KE1 message.
   * @throws {Error} If the string length is not exactly 96 bytes.
   * @public
   */
  public deserializeKE1Compact(base64: string): KE1 {
    const bytes: Uint8Array = base64ToUint8Array(base64)

    if (bytes.length !== 96) {
      throw new Error(`Invalid KE1 length: expected 96, got ${bytes.length}`)
    }

    return {
      credentialRequest: {
        blindedMessage: bytes.slice(0, 32)
      },
      authRequest: {
        clientNonce: bytes.slice(32, 64),
        clientPublicKeyshare: bytes.slice(64, 96)
      }
    }
  }

  /**
   * Serializes a KE2 message to an object with Base64 strings.
   *
   * Converts the KE2 message components to Base64 for transmission.
   *
   * @param ke2 - The KE2 message to serialize.
   * @returns A serialized KE2 with all fields as Base64 strings.
   * @public
   */
  public serializeKE2(ke2: KE2): KE2Serialized {
    return {
      evaluatedMessage: uint8ArrayToBase64(ke2.credentialResponse.evaluatedMessage),
      maskingNonce: uint8ArrayToBase64(ke2.credentialResponse.maskingNonce),
      maskedResponse: uint8ArrayToBase64(ke2.credentialResponse.maskedResponse),
      serverNonce: uint8ArrayToBase64(ke2.authResponse.serverNonce),
      serverPublicKeyshare: uint8ArrayToBase64(ke2.authResponse.serverPublicKeyshare),
      serverMac: uint8ArrayToBase64(ke2.authResponse.serverMac)
    }
  }

  /**
   * Deserializes a KE2 message from Base64 strings.
   *
   * Converts Base64-encoded strings back to binary format and validates
   * all fixed-length fields.
   *
   * @param serialized - The serialized KE2 message.
   * @returns The deserialized KE2 message with binary fields.
   * @throws {Error} If any fixed-length field has incorrect length.
   * @public
   */
  public deserializeKE2(serialized: KE2Serialized): KE2 {
    const evaluatedMessage: Uint8Array = base64ToUint8Array(serialized.evaluatedMessage)
    const maskingNonce: Uint8Array = base64ToUint8Array(serialized.maskingNonce)
    const maskedResponse: Uint8Array = base64ToUint8Array(serialized.maskedResponse)
    const serverNonce: Uint8Array = base64ToUint8Array(serialized.serverNonce)
    const serverPublicKeyshare: Uint8Array = base64ToUint8Array(serialized.serverPublicKeyshare)
    const serverMac: Uint8Array = base64ToUint8Array(serialized.serverMac)

    if (evaluatedMessage.length !== 32) {
      throw new Error(`Invalid evaluatedMessage length: expected 32, got ${evaluatedMessage.length}`)
    }
    if (maskingNonce.length !== 32) {
      throw new Error(`Invalid maskingNonce length: expected 32, got ${maskingNonce.length}`)
    }
    if (serverNonce.length !== 32) {
      throw new Error(`Invalid serverNonce length: expected 32, got ${serverNonce.length}`)
    }
    if (serverPublicKeyshare.length !== 32) {
      throw new Error(`Invalid serverPublicKeyshare length: expected 32, got ${serverPublicKeyshare.length}`)
    }
    if (serverMac.length !== 64) {
      throw new Error(`Invalid serverMac length: expected 64, got ${serverMac.length}`)
    }

    return {
      credentialResponse: { evaluatedMessage, maskingNonce, maskedResponse },
      authResponse: { serverNonce, serverPublicKeyshare, serverMac }
    }
  }

  /**
   * Serializes a KE2 message to a single compact Base64 string.
   *
   * Concatenates all KE2 components and encodes as a single Base64 string
   * for efficient transmission (minimum 193 bytes).
   *
   * @param ke2 - The KE2 message to serialize.
   * @returns A compact Base64-encoded string.
   * @public
   */
  public serializeKE2Compact(ke2: KE2): string {
    const bytes: Uint8Array = this.concat(
      ke2.credentialResponse.evaluatedMessage,
      ke2.credentialResponse.maskingNonce,
      ke2.credentialResponse.maskedResponse,
      ke2.authResponse.serverNonce,
      ke2.authResponse.serverPublicKeyshare,
      ke2.authResponse.serverMac
    )
    return uint8ArrayToBase64(bytes)
  }

  /**
   * Deserializes a KE2 message from a compact Base64 string.
   *
   * Decodes and splits a compact Base64 string back into KE2 components.
   * Handles variable-length maskedResponse field.
   *
   * @param base64 - The compact Base64-encoded KE2.
   * @returns The deserialized KE2 message.
   * @throws {Error} If the string is shorter than minimum length (193 bytes).
   * @public
   */
  public deserializeKE2Compact(base64: string): KE2 {
    const bytes: Uint8Array = base64ToUint8Array(base64)

    if (bytes.length < 193) {
      throw new Error(`Invalid KE2 length: minimum 193 bytes, got ${bytes.length}`)
    }

    let offset = 0

    const evaluatedMessage: Uint8Array = bytes.slice(offset, offset + 32)
    offset += 32

    const maskingNonce: Uint8Array = bytes.slice(offset, offset + 32)
    offset += 32

    const maskedResponseLength: number = bytes.length - offset - 32 - 32 - 64
    const maskedResponse: Uint8Array = bytes.slice(offset, offset + maskedResponseLength)
    offset += maskedResponseLength

    const serverNonce: Uint8Array = bytes.slice(offset, offset + 32)
    offset += 32

    const serverPublicKeyshare: Uint8Array = bytes.slice(offset, offset + 32)
    offset += 32

    const serverMac: Uint8Array = bytes.slice(offset, offset + 64)

    return {
      credentialResponse: { evaluatedMessage, maskingNonce, maskedResponse },
      authResponse: { serverNonce, serverPublicKeyshare, serverMac }
    }
  }

  /**
   * Serializes a KE3 message to an object with Base64 string.
   *
   * Converts the KE3 message (client MAC) to Base64 for transmission.
   *
   * @param ke3 - The KE3 message to serialize.
   * @returns A serialized KE3 with MAC as Base64 string.
   * @public
   */
  public serializeKE3(ke3: KE3): KE3Serialized {
    return {
      clientMac: uint8ArrayToBase64(ke3.clientMac)
    }
  }

  /**
   * Deserializes a KE3 message from Base64 string.
   *
   * Converts Base64-encoded string back to binary format and validates
   * the MAC length (must be 64 bytes).
   *
   * @param serialized - The serialized KE3 message.
   * @returns The deserialized KE3 message with binary MAC.
   * @throws {Error} If MAC length is not exactly 64 bytes.
   * @public
   */
  public deserializeKE3(serialized: KE3Serialized): KE3 {
    const clientMac: Uint8Array = base64ToUint8Array(serialized.clientMac)

    if (clientMac.length !== 64) {
      throw new Error(`Invalid clientMac length: expected 64, got ${clientMac.length}`)
    }

    return { clientMac }
  }

  /**
   * Serializes a KE3 message to a single compact Base64 string.
   *
   * Encodes the client MAC as a Base64 string (64 bytes).
   *
   * @param ke3 - The KE3 message to serialize.
   * @returns A compact Base64-encoded string.
   * @public
   */
  public serializeKE3Compact(ke3: KE3): string {
    return uint8ArrayToBase64(ke3.clientMac)
  }

  /**
   * Deserializes a KE3 message from a compact Base64 string.
   *
   * Decodes a Base64 string back into the client MAC.
   *
   * @param base64 - The compact Base64-encoded KE3.
   * @returns The deserialized KE3 message.
   * @throws {Error} If the string length is not exactly 64 bytes.
   * @public
   */
  public deserializeKE3Compact(base64: string): KE3 {
    const bytes: Uint8Array = base64ToUint8Array(base64)

    if (bytes.length !== 64) {
      throw new Error(`Invalid KE3 length: expected 64, got ${bytes.length}`)
    }

    return { clientMac: bytes }
  }

  /**
   * Creates a password change request from the client.
   *
   * Initiates a password change by creating both an authentication request
   * with the old password (KE1) and a registration request with the new
   * password. The client state must be preserved to finalize the change.
   *
   * This allows atomic password changes with authentication.
   *
   * @param oldPassword - The user's current password.
   * @param newPassword - The user's desired new password.
   * @param credentialIdentifier - The identifier for the credential being changed.
   * @returns Object containing:
   *   - request: The password change request to send to server
   *   - state: Client state that must be preserved for finalization
   * @throws {Error} If either password is empty.
   * @public
   */
  public createChangePasswordRequest(
    oldPassword: string,
    newPassword: string,
    credentialIdentifier: Uint8Array
  ): {
    request: ChangePasswordRequest
    state: ChangePasswordClientState
  } {
    if (!oldPassword || oldPassword.length === 0) {
      throw new Error('Old password cannot be empty')
    }
    if (!newPassword || newPassword.length === 0) {
      throw new Error('New password cannot be empty')
    }

    const { ke1: oldKE1, state: oldState } = this.generateKE1(oldPassword)
    const { request: newRegRequest, blind: newBlind } = this.createRegistrationRequest(newPassword)

    const request: ChangePasswordRequest = {
      credentialIdentifier,
      oldPasswordKE1: oldKE1,
      newPasswordRegistrationRequest: newRegRequest
    }

    const state: ChangePasswordClientState = {
      oldPassword,
      newPassword,
      oldBlind: oldState.blind,
      newBlind,
      clientSecret: oldState.clientSecret,
      oldKE1
    }

    return { request, state }
  }

  /**
   * Serializes a ChangePasswordRequest to an object with Base64 strings.
   *
   * Converts all binary fields in the password change request to Base64-encoded
   * strings for transmission over network or storage as JSON.
   *
   * @param request - The change password request to serialize.
   * @returns A serialized version with all fields as Base64 strings.
   * @public
   */
  public serializeChangePasswordRequest(request: ChangePasswordRequest): ChangePasswordRequestSerialized {
    return {
      credentialIdentifier: uint8ArrayToBase64(request.credentialIdentifier),
      oldPasswordKE1: this.serializeKE1(request.oldPasswordKE1),
      newPasswordRegistrationRequest: {
        blindedMessage: uint8ArrayToBase64(request.newPasswordRegistrationRequest.blindedMessage)
      }
    }
  }

  /**
   * Serializes a ChangePasswordRequest to a compact Base64 string.
   *
   * Concatenates all request components and encodes as a single Base64 string
   * for efficient transmission. The format is:
   * credentialIdLength (2 bytes) || credentialId || KE1 (96 bytes) || blindedMessage (32 bytes)
   *
   * @param request - The change password request to serialize.
   * @returns A compact Base64-encoded string.
   * @throws {Error} If credential identifier is too long (max 65535 bytes).
   * @public
   */
  public serializeChangePasswordRequestCompact(request: ChangePasswordRequest): string {
    if (request.credentialIdentifier.length > 65535) {
      throw new Error('credentialIdentifier too long for compact serialization (max 65535 bytes)')
    }

    const bytes: Uint8Array = this.concat(
      this.i2OSP(request.credentialIdentifier.length, 2),
      request.credentialIdentifier,
      request.oldPasswordKE1.credentialRequest.blindedMessage,
      request.oldPasswordKE1.authRequest.clientNonce,
      request.oldPasswordKE1.authRequest.clientPublicKeyshare,
      request.newPasswordRegistrationRequest.blindedMessage
    )

    return uint8ArrayToBase64(bytes)
  }

  /**
   * Deserializes a ChangePasswordRequest from Base64 strings.
   *
   * Converts Base64-encoded strings back to binary format and validates
   * all field lengths to ensure the request is well-formed.
   *
   * @param serialized - The serialized change password request.
   * @returns The deserialized request with binary fields.
   * @throws {Error} If any required field is missing or has incorrect length.
   * @public
   */
  public deserializeChangePasswordRequest(serialized: ChangePasswordRequestSerialized): ChangePasswordRequest {
    if (!serialized.credentialIdentifier || !serialized.oldPasswordKE1 || !serialized.newPasswordRegistrationRequest) {
      throw new Error('Missing required fields in ChangePasswordRequest')
    }

    try {
      const credentialIdentifier: Uint8Array = base64ToUint8Array(serialized.credentialIdentifier)
      const oldPasswordKE1: KE1 = this.deserializeKE1(serialized.oldPasswordKE1)
      const blindedMessage: Uint8Array = base64ToUint8Array(serialized.newPasswordRegistrationRequest.blindedMessage)

      if (credentialIdentifier.length === 0) {
        throw new Error('credentialIdentifier cannot be empty')
      }

      if (blindedMessage.length !== 32) {
        throw new Error(`Invalid blindedMessage length: expected 32, got ${blindedMessage.length}`)
      }

      return {
        credentialIdentifier,
        oldPasswordKE1,
        newPasswordRegistrationRequest: { blindedMessage }
      }
    } catch (error) {
      throw new Error(`Failed to deserialize ChangePasswordRequest: ${error}`)
    }
  }

  /**
   * Deserializes a ChangePasswordRequest from a compact Base64 string.
   *
   * Decodes and splits a compact Base64 string back into request components.
   *
   * @param base64 - The compact Base64-encoded request.
   * @returns The deserialized change password request.
   * @throws {Error} If the string is too short or has invalid structure.
   * @public
   */
  public deserializeChangePasswordRequestCompact(base64: string): ChangePasswordRequest {
    const bytes: Uint8Array = base64ToUint8Array(base64)

    // Minimum: 2 (length) + 1 (min credId) + 96 (KE1) + 32 (blindedMessage) = 131 bytes
    if (bytes.length < 131) {
      throw new Error(`Invalid ChangePasswordRequest length: minimum 131 bytes, got ${bytes.length}`)
    }

    let offset: number = 0

    // Read credential identifier length
    const credIdLength: number = (bytes[offset] << 8) | bytes[offset + 1]
    offset += 2

    if (bytes.length < 2 + credIdLength + 96 + 32) {
      throw new Error(`Invalid ChangePasswordRequest: insufficient data for credentialId length ${credIdLength}`)
    }

    // Read credential identifier
    const credentialIdentifier: Uint8Array = bytes.slice(offset, offset + credIdLength)
    offset += credIdLength

    // Read KE1 components
    const blindedMessage: Uint8Array = bytes.slice(offset, offset + 32)
    offset += 32

    const clientNonce: Uint8Array = bytes.slice(offset, offset + 32)
    offset += 32

    const clientPublicKeyshare: Uint8Array = bytes.slice(offset, offset + 32)
    offset += 32

    // Read new password registration request
    const newBlindedMessage: Uint8Array = bytes.slice(offset, offset + 32)

    return {
      credentialIdentifier,
      oldPasswordKE1: {
        credentialRequest: { blindedMessage },
        authRequest: { clientNonce, clientPublicKeyshare }
      },
      newPasswordRegistrationRequest: {
        blindedMessage: newBlindedMessage
      }
    }
  }

  /**
   * Creates a password change response from the server.
   *
   * Processes the password change request by generating KE2 for the old
   * password authentication and a registration response for the new password.
   * Uses constant-time record lookup to prevent timing attacks.
   *
   * @param request - The password change request from the client.
   * @param serverIdentity - Optional server identity.
   * @param serverPrivateKey - The server's long-term private key.
   * @param serverPublicKey - The server's long-term public key.
   * @param oprfSeed - The server's master OPRF seed.
   * @param recordStore - The map containing registration records.
   * @param clientIdentity - Optional client identity.
   * @returns Object containing:
   *   - response: The password change response to send to client
   *   - serverState: Server state for KE3 verification
   * @public
   */
  public createChangePasswordResponse(
    request: ChangePasswordRequest,
    serverIdentity: Uint8Array | undefined,
    serverPrivateKey: Uint8Array,
    serverPublicKey: Uint8Array,
    oprfSeed: Uint8Array,
    recordStore: Map<string, RegistrationRecord>,
    clientIdentity?: Uint8Array
  ): { response: ChangePasswordResponse; serverState: ServerState } {
    const record: RegistrationRecord = this.getRecordWithConstantTiming(request.credentialIdentifier, recordStore)

    const { ke2: oldKE2, state: serverState } = this.generateKE2(
      serverIdentity,
      serverPrivateKey,
      serverPublicKey,
      record,
      request.credentialIdentifier,
      oprfSeed,
      request.oldPasswordKE1,
      clientIdentity
    )

    const newRegResponse: RegistrationResponse = this.createRegistrationResponse(request.newPasswordRegistrationRequest, serverPublicKey, request.credentialIdentifier, oprfSeed)

    return {
      response: {
        oldPasswordKE2: oldKE2,
        newPasswordRegistrationResponse: newRegResponse
      },
      serverState
    }
  }

  /**
   * Serializes a ChangePasswordResponse to an object with Base64 strings.
   *
   * Converts all binary fields in the password change response to Base64-encoded
   * strings for transmission over network or storage as JSON.
   *
   * @param response - The change password response to serialize.
   * @returns A serialized version with all fields as Base64 strings.
   * @public
   */
  public serializeChangePasswordResponse(response: ChangePasswordResponse): ChangePasswordResponseSerialized {
    return {
      oldPasswordKE2: this.serializeKE2(response.oldPasswordKE2),
      newPasswordRegistrationResponse: {
        evaluatedMessage: uint8ArrayToBase64(response.newPasswordRegistrationResponse.evaluatedMessage),
        serverPublicKey: uint8ArrayToBase64(response.newPasswordRegistrationResponse.serverPublicKey)
      }
    }
  }

  /**
   * Serializes a ChangePasswordResponse to a compact Base64 string.
   *
   * Concatenates all response components and encodes as a single Base64 string
   * for efficient transmission. The format is:
   * KE2 (variable) || evaluatedMessage (32 bytes) || serverPublicKey (32 bytes)
   *
   * @param response - The change password response to serialize.
   * @returns A compact Base64-encoded string.
   * @public
   */
  public serializeChangePasswordResponseCompact(response: ChangePasswordResponse): string {
    // Serialize KE2 first to get its bytes
    const ke2Bytes: Uint8Array = base64ToUint8Array(this.serializeKE2Compact(response.oldPasswordKE2))
    const bytes: Uint8Array = this.concat(ke2Bytes, response.newPasswordRegistrationResponse.evaluatedMessage, response.newPasswordRegistrationResponse.serverPublicKey)

    return uint8ArrayToBase64(bytes)
  }

  /**
   * Deserializes a ChangePasswordResponse from Base64 strings.
   *
   * Converts Base64-encoded strings back to binary format and validates
   * all field lengths to ensure the response is well-formed.
   *
   * @param serialized - The serialized change password response.
   * @returns The deserialized response with binary fields.
   * @throws {Error} If any required field is missing or has incorrect length.
   * @public
   */
  public deserializeChangePasswordResponse(serialized: ChangePasswordResponseSerialized): ChangePasswordResponse {
    if (!serialized.oldPasswordKE2 || !serialized.newPasswordRegistrationResponse) {
      throw new Error('Missing required fields in ChangePasswordResponse')
    }

    try {
      const oldPasswordKE2: KE2 = this.deserializeKE2(serialized.oldPasswordKE2)
      const evaluatedMessage: Uint8Array = base64ToUint8Array(serialized.newPasswordRegistrationResponse.evaluatedMessage)
      const serverPublicKey: Uint8Array = base64ToUint8Array(serialized.newPasswordRegistrationResponse.serverPublicKey)

      if (evaluatedMessage.length !== 32) {
        throw new Error(`Invalid evaluatedMessage length: expected 32, got ${evaluatedMessage.length}`)
      }

      this.validateX25519PublicKey(serverPublicKey)

      return {
        oldPasswordKE2,
        newPasswordRegistrationResponse: {
          evaluatedMessage,
          serverPublicKey
        }
      }
    } catch (error) {
      throw new Error(`Failed to deserialize ChangePasswordResponse: ${error}`)
    }
  }

  /**
   * Deserializes a ChangePasswordResponse from a compact Base64 string.
   *
   * Decodes and splits a compact Base64 string back into response components.
   *
   * @param base64 - The compact Base64-encoded response.
   * @returns The deserialized change password response.
   * @throws {Error} If the string is too short (minimum 257 bytes).
   * @public
   */
  public deserializeChangePasswordResponseCompact(base64: string): ChangePasswordResponse {
    const bytes: Uint8Array = base64ToUint8Array(base64)

    // Minimum: 193 (KE2 min) + 32 (evaluatedMessage) + 32 (serverPublicKey) = 257 bytes
    if (bytes.length < 257) {
      throw new Error(`Invalid ChangePasswordResponse length: minimum 257 bytes, got ${bytes.length}`)
    }

    // The last 64 bytes are evaluatedMessage (32) + serverPublicKey (32)
    const ke2Length: number = bytes.length - 64
    const ke2Bytes: Uint8Array = bytes.slice(0, ke2Length)
    const oldPasswordKE2: KE2 = this.deserializeKE2Compact(uint8ArrayToBase64(ke2Bytes))
    const evaluatedMessage: Uint8Array = bytes.slice(ke2Length, ke2Length + 32)
    const serverPublicKey: Uint8Array = bytes.slice(ke2Length + 32)

    return {
      oldPasswordKE2,
      newPasswordRegistrationResponse: {
        evaluatedMessage,
        serverPublicKey
      }
    }
  }

  /**
   * Finalizes the password change on the client side.
   *
   * Verifies the server's authentication (via KE3 generation), finalizes
   * the new password registration, and creates the new registration record.
   * Reuses the same client keypair to maintain identity continuity.
   *
   * @param state - The client state from password change request.
   * @param response - The password change response from server.
   * @param serverIdentity - Optional server identity (must match registration).
   * @param clientIdentity - Optional client identity (must match registration).
   * @returns Object containing:
   *   - ke3: The KE3 message for old password authentication
   *   - newRecord: The new registration record to store on server
   *   - exportKey: New export key for the new password
   * @throws {Error} If server authentication fails.
   * @public
   */
  public finalizeChangePassword(
    state: ChangePasswordClientState,
    response: ChangePasswordResponse,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array
  ): {
    ke3: KE3
    newRecord: RegistrationRecord
    exportKey: Uint8Array
  } {
    const {
      ke3,
      clientKeypairSeed,
      exportKey: _exportKey
    } = this.generateKE3(
      {
        password: state.oldPassword,
        blind: state.oldBlind,
        clientSecret: state.clientSecret,
        ke1: state.oldKE1
      },
      response.oldPasswordKE2,
      serverIdentity,
      clientIdentity
    )

    const newPasswordBytes: Uint8Array = new TextEncoder().encode(state.newPassword)
    const oprfOutput: Uint8Array = this.finalize(newPasswordBytes, state.newBlind, response.newPasswordRegistrationResponse.evaluatedMessage)
    const mhfSalt: Uint8Array = this.expand(oprfOutput, new TextEncoder().encode('OPAQUE-HashToScalar'), 16)
    const hardenedOutput: Uint8Array = this.hardening(oprfOutput, mhfSalt)
    const randomizedPassword: Uint8Array = this.extract(null, this.concat(oprfOutput, hardenedOutput))

    const {
      envelope,
      clientPublicKey,
      maskingKey,
      exportKey: newExportKey
    } = this.store(randomizedPassword, response.newPasswordRegistrationResponse.serverPublicKey, serverIdentity, clientIdentity, clientKeypairSeed)

    const newRecord: RegistrationRecord = {
      clientPublicKey,
      maskingKey,
      envelope
    }

    this.secureZeroMultiple(newPasswordBytes, oprfOutput, mhfSalt, hardenedOutput, randomizedPassword, clientKeypairSeed)

    return { ke3, newRecord, exportKey: newExportKey }
  }

  /**
   * Completes the password change protocol by verifying the client's KE3 message,
   * updating the stored registration record, and finalizing the authenticated session.
   *
   * This method represents the final server-side step in a password change flow.
   * It validates the client's MAC contained in the KE3 message to ensure that the
   * client has proven knowledge of the old password-derived secrets established during
   * earlier protocol phases. Upon successful verification, the server replaces the
   * existing registration record with the newly generated one.
   *
   * Security considerations:
   * - If the client MAC verification fails, this method MUST abort immediately and
   *   MUST NOT update any stored credential material.
   * - The session key returned is the authenticated session key derived during the
   *   protocol execution and is bound to this password change operation.
   * - The password change is atomic: either both authentication succeeds and the
   *   new record is stored, or the entire operation fails.
   *
   * @param ke3
   *   The KE3 message sent by the client, containing the client MAC used to authenticate
   *   the final step of the password change protocol.
   * @param serverState
   *   The server-side ephemeral state created during previous protocol steps.
   *   This state includes the expected client MAC and the derived session key.
   * @param newRecord
   *   The newly generated registration record that replaces the old credential
   *   material after a successful password change.
   * @param credentialIdentifier
   *   A stable identifier for the credential (e.g., derived from a user handle or
   *   credential ID). This value is used as the lookup key in the registration record store.
   * @param recordStore
   *   A persistent storage map that holds registration records indexed by the
   *   Base64-encoded credential identifier.
   * @returns
   *   An object indicating successful completion of the password change operation
   *   and the authenticated session key associated with this protocol execution.
   * @throws {Error}
   *   Throws `ClientAuthenticationError` if the client MAC verification fails,
   *   indicating an invalid or malicious password change attempt.
   * @public
   */
  public completeChangePassword(
    ke3: KE3,
    serverState: ServerState,
    newRecord: RegistrationRecord,
    credentialIdentifier: Uint8Array,
    recordStore: Map<string, RegistrationRecord>
  ): { success: boolean; sessionKey: Uint8Array } {
    if (!this.verifyKE3(ke3.clientMac, serverState.expectedClientMac)) {
      throw new Error('ClientAuthenticationError: Invalid client MAC during password change')
    }

    const key: string = uint8ArrayToBase64(credentialIdentifier)
    recordStore.set(key, newRecord)

    return {
      success: true,
      sessionKey: serverState.sessionKey
    }
  }
}

/**
 * Simulates a complete OPAQUE protocol demonstration
 * Shows the full lifecycle: registration, authentication, and password change
 */
export function runOpaqueDemo(): void {
  console.log('='.repeat(80))
  console.log('OPAQUE PROTOCOL DEMONSTRATION')
  console.log('RFC 9807: The OPAQUE Asymmetric PAKE Protocol')
  console.log('='.repeat(80))
  console.log()

  // Initialize OPAQUE with context
  const opaque = new ZeroAccess()

  // Server setup
  console.log('📋 SERVER INITIALIZATION')
  console.log('-'.repeat(80))

  const serverKeyPair = opaque.generateServerKeyPair()
  const oprfSeed = crypto.getRandomValues(new Uint8Array(64))
  const recordStore = new Map<string, RegistrationRecord>()

  console.log('✓ Server keypair generated')
  console.log('✓ OPRF seed generated')
  console.log('✓ Record store initialized')
  console.log()

  // Test credentials
  const username = 'alice@example.com'
  const password = 'MySecureP@ssw0rd123!'
  const credentialId = new TextEncoder().encode(username)

  // ============================================================================
  // PHASE 1: USER REGISTRATION (SIGN UP)
  // ============================================================================
  console.log('🔐 PHASE 1: USER REGISTRATION (SIGN UP)')
  console.log('-'.repeat(80))
  console.log(`Username: ${username}`)
  console.log(`Password: ${'*'.repeat(password.length)}`)
  console.log()

  try {
    // Step 1: Client creates registration request
    console.log('Step 1/3: Client → Server (Registration Request)')
    const { request: regRequest, blind: regBlind } = opaque.createRegistrationRequest(password)
    console.log(`  ✓ Blinded password created`)
    console.log(`  ✓ Blind factor stored locally`)
    console.log()

    // Step 2: Server creates registration response
    console.log('Step 2/3: Server → Client (Registration Response)')
    const regResponse = opaque.createRegistrationResponse(regRequest, serverKeyPair.publicKey, credentialId, oprfSeed)
    console.log(`  ✓ OPRF evaluation completed`)
    console.log(`  ✓ Server public key attached`)
    console.log()

    // Step 3: Client finalizes registration
    console.log('Step 3/3: Client → Server (Registration Record)')
    const { record, exportKey } = opaque.finalizeRegistrationRequest(password, regBlind, regResponse)
    console.log(`  ✓ Randomized password derived`)
    console.log(`  ✓ Credential envelope created`)
    console.log(`  ✓ Export key generated`)
    console.log()

    // Server stores the registration record
    recordStore.set(uint8ArrayToBase64(credentialId), record)
    console.log('✅ REGISTRATION COMPLETE')
    console.log(`  • User: ${username}`)
    console.log(`  • Record stored in database`)
    console.log(`  • Export key: ${uint8ArrayToBase64(exportKey).substring(0, 32)}...`)
    console.log()
    console.log()

    // ============================================================================
    // PHASE 2: USER AUTHENTICATION (SIGN IN)
    // ============================================================================
    console.log('🔓 PHASE 2: USER AUTHENTICATION (SIGN IN)')
    console.log('-'.repeat(80))
    console.log(`Username: ${username}`)
    console.log(`Password: ${'*'.repeat(password.length)}`)
    console.log()

    // Step 1: Client generates KE1
    console.log('Step 1/3: Client → Server (KE1 - Auth Request)')
    const { ke1, state: clientState } = opaque.generateKE1(password)
    console.log(`  ✓ Password blinded`)
    console.log(`  ✓ Client nonce generated`)
    console.log(`  ✓ Client ephemeral keypair created`)
    console.log()

    // Step 2: Server generates KE2
    console.log('Step 2/3: Server → Client (KE2 - Auth Response)')
    const storedRecord = recordStore.get(uint8ArrayToBase64(credentialId))!
    const { ke2, state: serverState } = opaque.generateKE2(
      undefined, // serverIdentity
      serverKeyPair.privateKey,
      serverKeyPair.publicKey,
      storedRecord,
      credentialId,
      oprfSeed,
      ke1,
      undefined // clientIdentity
    )
    console.log(`  ✓ Credential response created`)
    console.log(`  ✓ Server nonce generated`)
    console.log(`  ✓ Server ephemeral keypair created`)
    console.log(`  ✓ Triple-DH computed`)
    console.log(`  ✓ Session key derived`)
    console.log(`  ✓ Server MAC computed`)
    console.log()

    // Step 3: Client generates KE3
    console.log('Step 3/3: Client → Server (KE3 - Auth Finalization)')
    const { ke3, sessionKey: clientSessionKey, exportKey: authExportKey } = opaque.generateKE3(clientState, ke2)
    console.log(`  ✓ Credentials recovered from envelope`)
    console.log(`  ✓ Server MAC verified`)
    console.log(`  ✓ Triple-DH computed`)
    console.log(`  ✓ Session key derived`)
    console.log(`  ✓ Client MAC computed`)
    console.log()

    // Server verifies KE3
    console.log('Server verifying client authentication...')
    const serverSessionKey = opaque.serverFinish(serverState, ke3)
    console.log(`  ✓ Client MAC verified`)
    console.log()

    // Verify session keys match
    const keysMatch = uint8ArrayToBase64(clientSessionKey) === uint8ArrayToBase64(serverSessionKey)

    console.log('✅ AUTHENTICATION COMPLETE')
    console.log(`  • User: ${username}`)
    console.log(`  • Session keys match: ${keysMatch ? '✓ YES' : '✗ NO'}`)
    console.log(`  • Session key: ${uint8ArrayToBase64(clientSessionKey).substring(0, 32)}...`)
    console.log(`  • Export key: ${uint8ArrayToBase64(authExportKey).substring(0, 32)}...`)
    console.log()
    console.log()

    // ============================================================================
    // PHASE 3: PASSWORD CHANGE
    // ============================================================================
    console.log('🔄 PHASE 3: PASSWORD CHANGE')
    console.log('-'.repeat(80))

    const newPassword = 'MyN3wSecur3P@ssw0rd456!'
    console.log(`Username: ${username}`)
    console.log(`Old Password: ${'*'.repeat(password.length)}`)
    console.log(`New Password: ${'*'.repeat(newPassword.length)}`)
    console.log()

    // Step 1: Client creates password change request
    console.log('Step 1/3: Client → Server (Change Password Request)')
    const { request: changeRequest, state: changeState } = opaque.createChangePasswordRequest(password, newPassword, credentialId)
    console.log(`  ✓ Old password authentication started (KE1)`)
    console.log(`  ✓ New password registration started`)
    console.log()

    // Step 2: Server creates password change response
    console.log('Step 2/3: Server → Client (Change Password Response)')
    const { response: changeResponse, serverState: changeServerState } = opaque.createChangePasswordResponse(
      changeRequest,
      undefined,
      serverKeyPair.privateKey,
      serverKeyPair.publicKey,
      oprfSeed,
      recordStore
    )
    console.log(`  ✓ Old password KE2 generated`)
    console.log(`  ✓ New password registration response created`)
    console.log()

    // Step 3: Client finalizes password change
    console.log('Step 3/3: Client → Server (Password Change Finalization)')
    const { ke3: changeKE3, newRecord, exportKey: newExportKey } = opaque.finalizeChangePassword(changeState, changeResponse)
    console.log(`  ✓ Old password authenticated`)
    console.log(`  ✓ New password finalized`)
    console.log(`  ✓ New registration record created`)
    console.log(`  ✓ Client keypair preserved`)
    console.log()

    // Server completes password change
    console.log('Server completing password change...')
    const { success, sessionKey: changeSessionKey } = opaque.completeChangePassword(changeKE3, changeServerState, newRecord, credentialId, recordStore)
    console.log(`  ✓ Client MAC verified`)
    console.log(`  ✓ Registration record updated`)
    console.log()

    console.log('✅ PASSWORD CHANGE COMPLETE')
    console.log(`  • User: ${username}`)
    console.log(`  • Status: ${success ? 'SUCCESS' : 'FAILED'}`)
    console.log(`  • New export key: ${uint8ArrayToBase64(newExportKey).substring(0, 32)}...`)
    console.log(`  • Session key: ${uint8ArrayToBase64(changeSessionKey).substring(0, 32)}...`)
    console.log()
    console.log()

    // ============================================================================
    // VERIFICATION: Login with new password
    // ============================================================================
    console.log('✨ VERIFICATION: Sign In with New Password')
    console.log('-'.repeat(80))

    const { ke1: verifyKE1, state: verifyState } = opaque.generateKE1(newPassword)
    const verifyRecord = recordStore.get(uint8ArrayToBase64(credentialId))!
    const { ke2: verifyKE2, state: verifyServerState } = opaque.generateKE2(undefined, serverKeyPair.privateKey, serverKeyPair.publicKey, verifyRecord, credentialId, oprfSeed, verifyKE1)
    const { ke3: verifyKE3, sessionKey: verifySessionKey } = opaque.generateKE3(verifyState, verifyKE2)
    const verifyServerSessionKey = opaque.serverFinish(verifyServerState, verifyKE3)

    const verifyMatch = uint8ArrayToBase64(verifySessionKey) === uint8ArrayToBase64(verifyServerSessionKey)

    console.log('✅ NEW PASSWORD VERIFICATION COMPLETE')
    console.log(`  • Authentication: ${verifyMatch ? '✓ SUCCESS' : '✗ FAILED'}`)
    console.log(`  • Session established with new password`)
    console.log()

    // ============================================================================
    // SUMMARY
    // ============================================================================
    console.log('='.repeat(80))
    console.log('📊 DEMONSTRATION SUMMARY')
    console.log('='.repeat(80))
    console.log('✓ Registration: User signed up successfully')
    console.log('✓ Authentication: User signed in successfully')
    console.log('✓ Password Change: Password updated successfully')
    console.log('✓ Verification: New password works correctly')
    console.log()
    console.log('Security Properties Demonstrated:')
    console.log('  • Zero-knowledge password proof')
    console.log('  • Forward secrecy via ephemeral keys')
    console.log('  • Mutual authentication (client ↔ server)')
    console.log('  • Password hardening with Argon2id')
    console.log('  • Encrypted credential storage')
    console.log('  • Constant-time operations')
    console.log('='.repeat(80))
  } catch (error) {
    console.error()
    console.error('❌ ERROR OCCURRED:')
    console.error(error)
    console.error()
  }
}

/**
 * Demonstrates a failed authentication attempt with wrong password
 */
export function runFailedAuthDemo(): void {
  console.log()
  console.log('='.repeat(80))
  console.log('🚫 FAILED AUTHENTICATION DEMONSTRATION')
  console.log('='.repeat(80))
  console.log()

  const opaque = new ZeroAccess('Demo-App-v1')
  const serverKeyPair = opaque.generateServerKeyPair()
  const oprfSeed = crypto.getRandomValues(new Uint8Array(64))
  const recordStore = new Map<string, RegistrationRecord>()

  const username = 'bob@example.com'
  const correctPassword = 'CorrectPassword123!'
  const wrongPassword = 'WrongPassword456!'
  const credentialId = new TextEncoder().encode(username)

  try {
    // Registration with correct password
    console.log('Setting up user account...')
    const { request: regRequest, blind: regBlind } = opaque.createRegistrationRequest(correctPassword)
    const regResponse = opaque.createRegistrationResponse(regRequest, serverKeyPair.publicKey, credentialId, oprfSeed)
    const { record } = opaque.finalizeRegistrationRequest(correctPassword, regBlind, regResponse)
    recordStore.set(uint8ArrayToBase64(credentialId), record)
    console.log(`✓ User registered: ${username}`)
    console.log()

    // Attempt authentication with wrong password
    console.log('Attempting authentication with WRONG password...')
    console.log(`Username: ${username}`)
    console.log(`Password: ${wrongPassword} (incorrect)`)
    console.log()

    const { ke1, state: clientState } = opaque.generateKE1(wrongPassword)
    const storedRecord = recordStore.get(uint8ArrayToBase64(credentialId))!
    const { ke2, state: serverState } = opaque.generateKE2(undefined, serverKeyPair.privateKey, serverKeyPair.publicKey, storedRecord, credentialId, oprfSeed, ke1)

    // This will throw an error due to envelope recovery failure
    const { ke3 } = opaque.generateKE3(clientState, ke2)
    opaque.serverFinish(serverState, ke3)

    console.log('❌ Unexpected: Authentication should have failed!')
  } catch (error) {
    console.log('✅ AUTHENTICATION CORRECTLY REJECTED')
    console.log(`  • Error: ${(error as Error).message}`)
    console.log('  • Wrong password detected during envelope recovery')
    console.log('  • Server never learned the attempted password')
    console.log()
  }

  console.log('='.repeat(80))
}

// Run both demonstrations
// runOpaqueDemo()
// runFailedAuthDemo()
