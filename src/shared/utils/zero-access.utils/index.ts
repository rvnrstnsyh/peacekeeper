import type {
  AuthRequest,
  AuthResponse,
  ChangePasswordClientState,
  ChangePasswordRequest,
  ChangePasswordResponse,
  CleartextCredentials,
  ClientState,
  CredentialResponse,
  KE1,
  KE2,
  KE3,
  RegistrationRecord,
  RegistrationRequest,
  RegistrationResponse,
  ServerState
} from '@/shared/types/zero-access.types'

import { hmac } from '@noble/hashes/hmac.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { uint8ArrayToBase64 } from '@/shared/utils/common'
import { Helpers } from '@/shared/utils/zero-access.utils/helpers'
import { CONFIG } from '@/shared/constants/zero-access.constants'

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
  constructor(context: string = 'OPAQUE-RFC9807-ristretto255-SHA512') {
    if (!context || context.length === 0) {
      throw new Error('Context string cannot be empty')
    }

    if (context.length > 255) {
      throw new Error('Context string too long (max 255 bytes)')
    }

    if (context.includes('\0')) {
      throw new Error('Context string cannot contain null bytes')
    }

    Helpers.validateConfiguration()
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
      Helpers.secureZero(passwordBytes)
      throw new Error('Password too long (max 1024 bytes)')
    }

    const { blind, blindedElement } = Helpers.blind(passwordBytes)

    Helpers.secureZero(passwordBytes)

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
    Helpers.validateRistretto255Element(request.blindedMessage)
    Helpers.validateX25519PublicKey(serverPublicKey)

    if (credentialIdentifier.length === 0) {
      throw new Error('credentialIdentifier cannot be empty')
    }

    if (credentialIdentifier.length > 256) {
      throw new Error('credentialIdentifier too long (max 256 bytes)')
    }

    if (oprfSeed.length !== CONFIG.Nh) {
      throw new Error(`oprfSeed must be ${CONFIG.Nh} bytes`)
    }

    const seed: Uint8Array = Helpers.expand(oprfSeed, Helpers.concat(credentialIdentifier, new TextEncoder().encode('OprfKey')), CONFIG.Nok)

    const { privateKey: oprfKey } = Helpers.deriveOprfKeyPair(seed, 'RFCXXXX-DeriveKeyPair')

    const evaluatedElement: Uint8Array = Helpers.blindEvaluate(oprfKey, request.blindedMessage)

    Helpers.secureZeroMultiple(seed, oprfKey)

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
    const oprfOutput: Uint8Array = Helpers.finalize(passwordBytes, blind, response.evaluatedMessage)
    // Apply hardening
    const mhfSalt: Uint8Array = Helpers.expand(oprfOutput, new TextEncoder().encode('OPAQUE-HashToScalar'), 16)
    const hardenedOutput: Uint8Array = Helpers.hardening(oprfOutput, mhfSalt)
    const randomizedPassword: Uint8Array = Helpers.extract(null, Helpers.concat(oprfOutput, hardenedOutput))
    const clientKeypairSeed: Uint8Array = randomBytes(CONFIG.Nseed)

    const { envelope, clientPublicKey, maskingKey, exportKey } = Helpers.store(randomizedPassword, response.serverPublicKey, serverIdentity, clientIdentity, clientKeypairSeed)

    Helpers.secureZeroMultiple(passwordBytes, oprfOutput, mhfSalt, hardenedOutput, randomizedPassword)

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
    const { request, blind } = Helpers.createCredentialRequest(password)

    const clientNonce: Uint8Array = randomBytes(CONFIG.Nn)
    const clientKeyshareSeed: Uint8Array = randomBytes(CONFIG.Nseed)

    const { privateKey: clientSecret, publicKey: clientPublicKeyshare } = Helpers.deriveDiffieHellmanKeyPair(clientKeyshareSeed)

    Helpers.secureZero(clientKeyshareSeed)

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
    if (serverPrivateKey.length !== CONFIG.Nsk) {
      throw new Error('Invalid server private key length')
    }

    Helpers.validateX25519PublicKey(serverPublicKey)
    Helpers.validateRistretto255Element(ke1.credentialRequest.blindedMessage)
    Helpers.validateNonce(ke1.authRequest.clientNonce)
    Helpers.validateX25519PublicKey(ke1.authRequest.clientPublicKeyshare)
    Helpers.validateX25519PublicKey(record.clientPublicKey)
    Helpers.validateEnvelope(record.envelope)

    if (record.maskingKey.length !== CONFIG.Nh) {
      throw new Error('Invalid masking key length')
    }

    if (credentialIdentifier.length === 0) {
      throw new Error('credentialIdentifier cannot be empty')
    }

    if (oprfSeed.length !== CONFIG.Nh) {
      throw new Error('Invalid OPRF seed length')
    }

    const credentialResponse: CredentialResponse = Helpers.createCredentialResponse(ke1.credentialRequest, serverPublicKey, record, credentialIdentifier, oprfSeed)
    const cleartextCredentials: CleartextCredentials = Helpers.createCleartextCredentials(serverPublicKey, record.clientPublicKey, serverIdentity, clientIdentity)
    const serverNonce: Uint8Array = randomBytes(CONFIG.Nn)
    const serverKeyshareSeed: Uint8Array = randomBytes(CONFIG.Nseed)

    const { privateKey: serverPrivateKeyshare, publicKey: serverPublicKeyshare } = Helpers.deriveDiffieHellmanKeyPair(serverKeyshareSeed)

    const preamble: Uint8Array = Helpers.preamble(cleartextCredentials.clientIdentity, ke1, cleartextCredentials.serverIdentity, credentialResponse, serverNonce, serverPublicKeyshare)
    // Triple DH
    const dh1: Uint8Array = Helpers.diffieHellman(serverPrivateKeyshare, ke1.authRequest.clientPublicKeyshare)
    const dh2: Uint8Array = Helpers.diffieHellman(serverPrivateKey, ke1.authRequest.clientPublicKeyshare)
    const dh3: Uint8Array = Helpers.diffieHellman(serverPrivateKeyshare, record.clientPublicKey)
    const ikm: Uint8Array = Helpers.concat(dh1, dh2, dh3)

    const { km2, km3, sessionKey } = Helpers.deriveKeys(ikm, preamble)

    const preambleHash: Uint8Array = sha512(preamble)
    const serverMac: Uint8Array = hmac(sha512, km2, preambleHash)
    const expectedClientMac: Uint8Array = hmac(sha512, km3, sha512(Helpers.concat(preamble, serverMac)))

    Helpers.secureZeroMultiple(serverKeyshareSeed, serverPrivateKeyshare, dh1, dh2, dh3, ikm, km2, km3, preambleHash)

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
    Helpers.validateRistretto255Element(ke2.credentialResponse.evaluatedMessage)
    Helpers.validateNonce(ke2.credentialResponse.maskingNonce)
    Helpers.validateNonce(ke2.authResponse.serverNonce)
    Helpers.validateX25519PublicKey(ke2.authResponse.serverPublicKeyshare)
    Helpers.validateMAC(ke2.authResponse.serverMac)

    const { clientPrivateKey, clientKeypairSeed, cleartextCredentials, exportKey } = Helpers.recoverCredentials(state.password, state.blind, ke2.credentialResponse, serverIdentity, clientIdentity)

    const preamble: Uint8Array = Helpers.preamble(
      cleartextCredentials.clientIdentity,
      state.ke1,
      cleartextCredentials.serverIdentity,
      ke2.credentialResponse,
      ke2.authResponse.serverNonce,
      ke2.authResponse.serverPublicKeyshare
    )

    // Triple DH
    const dh1: Uint8Array = Helpers.diffieHellman(state.clientSecret, ke2.authResponse.serverPublicKeyshare)
    const dh2: Uint8Array = Helpers.diffieHellman(state.clientSecret, cleartextCredentials.serverPublicKey)
    const dh3: Uint8Array = Helpers.diffieHellman(clientPrivateKey, ke2.authResponse.serverPublicKeyshare)
    const ikm: Uint8Array = Helpers.concat(dh1, dh2, dh3)

    const { km2, km3, sessionKey } = Helpers.deriveKeys(ikm, preamble)

    const preambleHash: Uint8Array = sha512(preamble)
    const expectedServerMac: Uint8Array = hmac(sha512, km2, preambleHash)

    if (!Helpers.ctEqual(ke2.authResponse.serverMac, expectedServerMac)) {
      Helpers.secureZeroMultiple(clientPrivateKey, exportKey, clientKeypairSeed, dh1, dh2, dh3, ikm, km2, km3, sessionKey, preambleHash)
      throw new Error('ServerAuthenticationError: Invalid server MAC')
    }

    const clientMac: Uint8Array = hmac(sha512, km3, sha512(Helpers.concat(preamble, expectedServerMac)))
    const ke3: KE3 = { clientMac }

    Helpers.secureZeroMultiple(clientPrivateKey, dh1, dh2, dh3, ikm, km2, km3, expectedServerMac, preambleHash)

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
      if (ke3ClientMac.length !== CONFIG.Nm) {
        return false
      }

      if (expectedClientMac.length !== CONFIG.Nm) {
        return false
      }

      return Helpers.ctEqual(ke3ClientMac, expectedClientMac)
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
    Helpers.validateMAC(ke3.clientMac)

    if (!Helpers.ctEqual(ke3.clientMac, state.expectedClientMac)) {
      Helpers.secureZero(state.sessionKey)
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
    return Helpers.deriveDiffieHellmanKeyPair(randomBytes(CONFIG.Nseed))
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
    const record: RegistrationRecord = Helpers.getRecordWithConstantTiming(request.credentialIdentifier, recordStore)

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
    const oprfOutput: Uint8Array = Helpers.finalize(newPasswordBytes, state.newBlind, response.newPasswordRegistrationResponse.evaluatedMessage)
    const mhfSalt: Uint8Array = Helpers.expand(oprfOutput, new TextEncoder().encode('OPAQUE-HashToScalar'), 16)
    const hardenedOutput: Uint8Array = Helpers.hardening(oprfOutput, mhfSalt)
    const randomizedPassword: Uint8Array = Helpers.extract(null, Helpers.concat(oprfOutput, hardenedOutput))

    const {
      envelope,
      clientPublicKey,
      maskingKey,
      exportKey: newExportKey
    } = Helpers.store(randomizedPassword, response.newPasswordRegistrationResponse.serverPublicKey, serverIdentity, clientIdentity, clientKeypairSeed)

    const newRecord: RegistrationRecord = {
      clientPublicKey,
      maskingKey,
      envelope
    }

    Helpers.secureZeroMultiple(newPasswordBytes, oprfOutput, mhfSalt, hardenedOutput, randomizedPassword, clientKeypairSeed)

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
