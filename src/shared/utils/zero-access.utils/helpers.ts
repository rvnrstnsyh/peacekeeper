import type { CleartextCredentials, CredentialRequest, CredentialResponse, Envelope, KE1, OpaqueConfig, RegistrationRecord } from '@/shared/types/zero-access.utils.types'

import { hmac } from '@noble/hashes/hmac.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { argon2id } from '@noble/hashes/argon2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { expand, extract } from '@noble/hashes/hkdf.js'
import { uint8ArrayToBase64 } from '@/shared/utils/common.utils'
import { CONFIG, LOW_ORDER_POINTS } from '@/shared/constants/zero-access.constants'
import { ed25519, ristretto255, ristretto255_hasher, x25519 } from '@noble/curves/ed25519.js'

export class Helpers {
  /**
   * Validates the OPAQUE protocol configuration parameters.
   *
   * Ensures all size parameters meet RFC 9807 requirements for the ristretto255-SHA512
   * configuration. This includes validating key lengths, nonce sizes, hash outputs,
   * and MAC lengths against the specification.
   *
   * @throws {Error} If any configuration parameter is invalid or doesn't meet RFC 9807 requirements.
   * @public
   */
  public static validateConfiguration(): void {
    const { Nh, Nn, Nm, Npk, Noe, Nok, Nseed, Nsk }: OpaqueConfig = CONFIG

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
   * @public
   */
  public static validateX25519PublicKey(publicKey: Uint8Array): void {
    if (publicKey.length !== 32) {
      throw new Error('Invalid X25519 public key length: expected 32 bytes')
    }

    const hex: string = Array.from(publicKey)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')

    if (LOW_ORDER_POINTS.has(hex)) {
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
   * @public
   */
  public static validateRistretto255Element(element: Uint8Array): void {
    if (element.length !== 32) {
      throw new Error('Invalid ristretto255 element length: expected 32 bytes')
    }

    try {
      const point = ristretto255.Point.fromBytes(element)

      if (point.equals(ristretto255.Point.ZERO)) {
        throw new Error('Invalid ristretto255 element: identity element')
      }
    } catch (error) {
      throw new Error(`Invalid ristretto255 element: deserialization failed - ${error}`, { cause: error })
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
   * @public
   */
  public static validateEnvelope(envelope: Envelope): void {
    if (envelope.nonce.length !== CONFIG.Nn) {
      throw new Error(`Invalid envelope nonce length: expected ${CONFIG.Nn} bytes`)
    }

    if (envelope.authTag.length !== CONFIG.Nm) {
      throw new Error(`Invalid envelope authTag length: expected ${CONFIG.Nm} bytes`)
    }

    if (!envelope.seed || envelope.seed.length !== CONFIG.Nseed) {
      throw new Error(`Invalid or missing envelope seed length: expected ${CONFIG.Nseed} bytes`)
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
   * @public
   */
  public static validateMAC(mac: Uint8Array): void {
    if (mac.length !== CONFIG.Nm) {
      throw new Error(`Invalid MAC length: expected ${CONFIG.Nm} bytes`)
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
   * @public
   */
  public static validateNonce(nonce: Uint8Array): void {
    if (nonce.length !== CONFIG.Nn) {
      throw new Error(`Invalid nonce length: expected ${CONFIG.Nn} bytes`)
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
   * @public
   */
  public static extract(salt: Uint8Array | null, ikm: Uint8Array): Uint8Array {
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
   * @public
   */
  public static expand(prk: Uint8Array, info: Uint8Array | string, length: number): Uint8Array {
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
   * @public
   */
  public static hardening(oprfOutput: Uint8Array, params: Uint8Array): Uint8Array {
    try {
      if (params.length !== 16) {
        throw new Error('Hardening params must be 16 bytes')
      }

      // Using Argon2id as MHF per RFC 9807 recommendations
      const parallelism: number = 4
      const memorySize: number = 65536
      const iterations: number = 3
      const outputLength: number = CONFIG.Nh

      return argon2id(oprfOutput, params, {
        t: iterations,
        m: memorySize,
        p: parallelism
      }).slice(0, outputLength)
    } catch (error) {
      throw new Error(`MHF hardening failed: ${error}`, { cause: error })
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
   * @public
   */
  public static blind(passwordBytes: Uint8Array): { blind: Uint8Array; blindedElement: Uint8Array } {
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
   * @public
   */
  public static blindEvaluate(oprfKey: Uint8Array, blindedElement: Uint8Array): Uint8Array {
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
   * @public
   */
  public static finalize(passwordBytes: Uint8Array, blind: Uint8Array, evaluatedElement: Uint8Array): Uint8Array {
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
   * @public
   */
  public static deriveOprfKeyPair(seed: Uint8Array, info: string): { privateKey: Uint8Array; publicKey: Uint8Array } {
    // @noble/hashes v2.x requires prk >= HashLen (64 bytes for SHA-512).
    // The seed from Expand is only Nok=32 bytes, so Extract first to produce a 64-byte PRK.
    const prk: Uint8Array = this.extract(null, seed)
    const derivedSeed: Uint8Array = this.expand(prk, info, CONFIG.Nok)
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
   * @public
   */
  public static diffieHellman(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
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
      throw new Error(`DH operation failed: ${error}`, { cause: error })
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
   * @public
   */
  public static deriveDiffieHellmanKeyPair(seed: Uint8Array): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const info: string = 'OPAQUE-DeriveAuthKeyPair'
    // @noble/hashes v2.x requires prk >= HashLen (64 bytes for SHA-512).
    // The seed from randomBytes is only Nseed=32 bytes, so Extract first.
    const prk: Uint8Array = this.extract(null, seed)
    const derivedSeed: Uint8Array = this.expand(prk, info, CONFIG.Nsk)
    const privateKey: Uint8Array = this.clampX25519Key(derivedSeed)
    const publicKey: Uint8Array = x25519.getPublicKey(privateKey)

    this.validateX25519PublicKey(publicKey)
    this.secureZero(derivedSeed)

    return { privateKey, publicKey }
  }

  /**
   * Derives an ED25519 signing key pair from a master seed using HKDF label separation.
   *
   * Uses the label 'ZeroAccess-DeriveSigningKeyPair' to derive an independent sub-seed
   * from the same master seed used for the X25519 ECDH keypair (Option B).
   * This provides each user with a stable ED25519 identity key for digital signatures.
   *
   * @param masterSeed - The 32-byte master seed from the OPAQUE envelope.
   * @returns Object containing:
   *   - privateKey: The ED25519 private seed (32 bytes)
   *   - publicKey: The ED25519 public key (32 bytes, compressed Edwards point)
   * @public
   */
  public static deriveSigningKeyPair(masterSeed: Uint8Array): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const prk: Uint8Array = this.extract(null, masterSeed)
    const signingSubSeed: Uint8Array = this.expand(prk, 'ZeroAccess-DeriveSigningKeyPair', 32)
    this.secureZero(prk)
    const { pointBytes: publicKey } = ed25519.utils.getExtendedPublicKey(signingSubSeed)
    return { privateKey: signingSubSeed, publicKey }
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
   * @public
   */
  public static clampX25519Key(key: Uint8Array): Uint8Array {
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
   * @public
   */
  public static createCleartextCredentials(serverX25519PublicKey: Uint8Array, clientX25519PublicKey: Uint8Array, serverIdentity?: Uint8Array, clientIdentity?: Uint8Array): CleartextCredentials {
    return {
      serverX25519PublicKey,
      serverIdentity: serverIdentity || serverX25519PublicKey,
      clientX25519PublicKey,
      clientIdentity: clientIdentity || clientX25519PublicKey
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
   * @public
   */
  public static store(
    randomizedPassword: Uint8Array,
    serverPublicKey: Uint8Array,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array,
    clientX25519KeypairSeed?: Uint8Array
  ): {
    envelope: Envelope
    clientED25519PublicKey: Uint8Array
    clientX25519PublicKey: Uint8Array
    maskingKey: Uint8Array
    exportKey: Uint8Array
  } {
    const envelopeNonce: Uint8Array = randomBytes(CONFIG.Nn)
    // Derive keys from randomized password
    const authKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelopeNonce, new TextEncoder().encode('AuthKey')), CONFIG.Nh)
    const exportKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelopeNonce, new TextEncoder().encode('ExportKey')), CONFIG.Nh)
    const seedEncryptionKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelopeNonce, new TextEncoder().encode('SeedKey')), CONFIG.Nseed)
    const maskingKey: Uint8Array = this.expand(randomizedPassword, new TextEncoder().encode('MaskingKey'), CONFIG.Nh)
    // Generate or use provided client keypair seed
    const actualSeed: Uint8Array = clientX25519KeypairSeed || randomBytes(CONFIG.Nseed)
    const encryptedSeed: Uint8Array = this.xor(actualSeed, seedEncryptionKey)

    const { publicKey: clientX25519PublicKey } = this.deriveDiffieHellmanKeyPair(actualSeed)
    const { publicKey: clientED25519PublicKey, privateKey: clientED25519PrivateKey } = this.deriveSigningKeyPair(actualSeed)

    // Construct cleartext credentials
    const serverId: Uint8Array = serverIdentity || serverPublicKey
    const clientId: Uint8Array = clientIdentity || clientX25519PublicKey
    // Create authentication tag
    const authInput: Uint8Array = this.concat(envelopeNonce, encryptedSeed, serverPublicKey, this.i2OSP(serverId.length, 2), serverId, this.i2OSP(clientId.length, 2), clientId)
    const authTag: Uint8Array = hmac(sha512, authKey, authInput)

    this.secureZeroMultiple(seedEncryptionKey, authKey, clientED25519PrivateKey)
    if (!clientX25519KeypairSeed) {
      this.secureZero(actualSeed)
    }

    return {
      envelope: { nonce: envelopeNonce, authTag, seed: encryptedSeed },
      clientED25519PublicKey,
      clientX25519PublicKey,
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
   * @public
   */
  public static recover(
    randomizedPassword: Uint8Array,
    serverPublicKey: Uint8Array,
    envelope: Envelope,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array
  ): {
    clientED25519PublicKey: Uint8Array
    clientX25519PrivateKey: Uint8Array
    clientX25519KeypairSeed: Uint8Array
    cleartextCredentials: CleartextCredentials
    exportKey: Uint8Array
  } {
    this.validateX25519PublicKey(serverPublicKey)
    this.validateEnvelope(envelope)

    // Derive keys from randomized password
    const authKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelope.nonce, new TextEncoder().encode('AuthKey')), CONFIG.Nh)
    const exportKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelope.nonce, new TextEncoder().encode('ExportKey')), CONFIG.Nh)
    const seedEncryptionKey: Uint8Array = this.expand(randomizedPassword, this.concat(envelope.nonce, new TextEncoder().encode('SeedKey')), CONFIG.Nseed)
    // Decrypt client keypair seed
    const clientX25519KeypairSeed: Uint8Array = this.xor(envelope.seed, seedEncryptionKey)

    const { privateKey: clientX25519PrivateKey, publicKey: clientX25519PublicKey } = this.deriveDiffieHellmanKeyPair(clientX25519KeypairSeed)
    const { publicKey: clientED25519PublicKey, privateKey: clientED25519PrivateKey } = this.deriveSigningKeyPair(clientX25519KeypairSeed)

    // Construct cleartext credentials
    const serverId: Uint8Array = serverIdentity || serverPublicKey
    const clientId: Uint8Array = clientIdentity || clientX25519PublicKey
    // Verify authentication tag
    const expectedTagInput: Uint8Array = this.concat(envelope.nonce, envelope.seed, serverPublicKey, this.i2OSP(serverId.length, 2), serverId, this.i2OSP(clientId.length, 2), clientId)
    const expectedTag: Uint8Array = hmac(sha512, authKey, expectedTagInput)

    if (!this.ctEqual(envelope.authTag, expectedTag)) {
      this.secureZeroMultiple(authKey, exportKey, clientX25519PrivateKey, clientX25519KeypairSeed, seedEncryptionKey, clientED25519PrivateKey)
      // Envelope Recovery Error: Invalid password or corrupted envelope
      throw new Error('EnvelopeRecoveryError: Invalid password or corrupted envelope')
    }

    const cleartextCredentials: CleartextCredentials = {
      clientIdentity: clientId,
      serverIdentity: serverId,
      clientX25519PublicKey,
      serverX25519PublicKey: serverPublicKey
    }

    this.secureZeroMultiple(seedEncryptionKey, authKey, clientED25519PrivateKey)

    return {
      clientED25519PublicKey,
      clientX25519PrivateKey,
      clientX25519KeypairSeed,
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
   * @public
   */
  public static createCredentialRequest(password: string): { request: CredentialRequest; blind: Uint8Array } {
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
   * @public
   */
  public static createCredentialResponse(
    request: CredentialRequest,
    serverPublicKey: Uint8Array,
    record: RegistrationRecord,
    credentialIdentifier: Uint8Array,
    oprfSeed: Uint8Array
  ): CredentialResponse {
    this.validateRistretto255Element(request.blindedMessage)

    // Derive OPRF key from seed and credential identifier
    const seed: Uint8Array = this.expand(oprfSeed, this.concat(credentialIdentifier, new TextEncoder().encode('OprfKey')), CONFIG.Nok)

    const { privateKey: oprfKey } = this.deriveOprfKeyPair(seed, 'RFCXXXX-DeriveKeyPair')

    const evaluatedElement: Uint8Array = this.blindEvaluate(oprfKey, request.blindedMessage)
    // Create masked response to protect envelope
    const maskingNonce: Uint8Array = randomBytes(CONFIG.Nn)
    const credentialResponsePad: Uint8Array = this.expand(
      record.maskingKey,
      this.concat(maskingNonce, new TextEncoder().encode('CredentialResponsePad')),
      CONFIG.Npk + CONFIG.Nn + CONFIG.Nm + CONFIG.Nseed
    )
    const envelopeBytes: Uint8Array = this.concat(record.envelope.nonce, record.envelope.authTag, record.envelope.seed)
    const maskedResponse: Uint8Array = this.xor(credentialResponsePad, this.concat(serverPublicKey, envelopeBytes))

    this.secureZeroMultiple(seed, oprfKey, credentialResponsePad)

    return { evaluatedMessage: evaluatedElement, maskingNonce, maskedResponse }
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
  public static createFakeRegistrationRecord(): RegistrationRecord {
    const fakeClientPublicKey: Uint8Array = randomBytes(CONFIG.Npk)
    const fakeMaskingKey: Uint8Array = randomBytes(CONFIG.Nh)
    const fakeEnvelope: Envelope = {
      nonce: randomBytes(CONFIG.Nn),
      authTag: randomBytes(CONFIG.Nm),
      seed: randomBytes(CONFIG.Nseed)
    }

    return {
      clientED25519PublicKey: randomBytes(32),
      clientX25519PublicKey: fakeClientPublicKey,
      maskingKey: fakeMaskingKey,
      envelope: fakeEnvelope
    }
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
   * @public
   */
  public static getRecordWithConstantTiming(credentialIdentifier: Uint8Array, recordStore: Map<string, RegistrationRecord>): RegistrationRecord {
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
   * @public
   */
  public static recoverCredentials(
    password: string,
    blind: Uint8Array,
    response: CredentialResponse,
    serverIdentity?: Uint8Array,
    clientIdentity?: Uint8Array
  ): {
    clientED25519PublicKey: Uint8Array
    clientX25519PrivateKey: Uint8Array
    clientX25519KeypairSeed: Uint8Array
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
    const maskingKey: Uint8Array = this.expand(randomizedPassword, new TextEncoder().encode('MaskingKey'), CONFIG.Nh)
    const credentialResponsePad: Uint8Array = this.expand(
      maskingKey,
      this.concat(response.maskingNonce, new TextEncoder().encode('CredentialResponsePad')),
      CONFIG.Npk + CONFIG.Nn + CONFIG.Nm + CONFIG.Nseed
    )
    const unmasked: Uint8Array = this.xor(credentialResponsePad, response.maskedResponse)

    if (unmasked.length < CONFIG.Npk + CONFIG.Nn + CONFIG.Nm + CONFIG.Nseed) {
      this.secureZeroMultiple(passwordBytes, oprfOutput, mhfSalt, hardenedOutput, randomizedPassword, maskingKey, credentialResponsePad, unmasked)
      throw new Error('Invalid credential response: insufficient data')
    }

    // Extract envelope components
    const serverX25519PublicKey: Uint8Array = unmasked.slice(0, CONFIG.Npk)
    const envelopeNonce: Uint8Array = unmasked.slice(CONFIG.Npk, CONFIG.Npk + CONFIG.Nn)
    const authTag: Uint8Array = unmasked.slice(CONFIG.Npk + CONFIG.Nn, CONFIG.Npk + CONFIG.Nn + CONFIG.Nm)
    const seed: Uint8Array = unmasked.slice(CONFIG.Npk + CONFIG.Nn + CONFIG.Nm)
    const envelope: Envelope = { nonce: envelopeNonce, authTag, seed }
    // Recover credentials from envelope
    const result = this.recover(randomizedPassword, serverX25519PublicKey, envelope, serverIdentity, clientIdentity)

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
   * @public
   */
  public static preamble(
    clientIdentity: Uint8Array,
    ke1: KE1,
    serverIdentity: Uint8Array,
    credentialResponse: CredentialResponse,
    serverNonce: Uint8Array,
    serverPublicKeyshare: Uint8Array
  ): Uint8Array {
    const context: Uint8Array = new TextEncoder().encode(CONFIG.context)
    const ke1Bytes: Uint8Array = this.concat(ke1.credentialRequest.blindedMessage, ke1.authRequest.clientNonce, ke1.authRequest.clientX25519PublicKeyshare)
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
   * @public
   */
  public static expandLabel(secret: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array {
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

    if (length > 255 * CONFIG.Nh) {
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
   * @public
   */
  public static deriveSecret(secret: Uint8Array, label: string, transcript: Uint8Array): Uint8Array {
    const transcriptHash: Uint8Array = transcript.length > 0 ? sha512(transcript) : transcript
    return this.expandLabel(secret, label, transcriptHash, CONFIG.Nh)
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
   * @public
   */
  public static deriveKeys(ikm: Uint8Array, preamble: Uint8Array): { km2: Uint8Array; km3: Uint8Array; sessionKey: Uint8Array } {
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
   * @public
   */
  public static concat(...arrays: Uint8Array[]): Uint8Array {
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
   * @public
   */
  public static xor(a: Uint8Array, b: Uint8Array): Uint8Array {
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
   * @public
   */
  public static i2OSP(value: number, length: number): Uint8Array {
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
   * @public
   */
  public static ctEqual(a: Uint8Array, b: Uint8Array): boolean {
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
   * @public
   */
  public static ctEqualStrings(a: string, b: string): boolean {
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
   * @public
   */
  public static modInverse(a: bigint, m: bigint): bigint {
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
   * @public
   */
  public static extendedGCD(a: bigint, b: bigint): { gcd: bigint; x: bigint; y: bigint } {
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
   * @public
   */
  public static bytesToScalar(bytes: Uint8Array): bigint {
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
   * @public
   */
  public static scalarToBytes(scalar: bigint): Uint8Array {
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
   * @public
   */
  public static secureZero(array: Uint8Array): void {
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
   * @public
   */
  public static secureZeroMultiple(...arrays: (Uint8Array | undefined)[]): void {
    for (const array of arrays) {
      if (array) {
        this.secureZero(array)
      }
    }
  }
}
