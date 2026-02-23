import type {
  ChangePasswordRequest,
  ChangePasswordRequestSerialized,
  ChangePasswordResponse,
  ChangePasswordResponseSerialized,
  Envelope,
  KE1,
  KE1Serialized,
  KE2,
  KE2Serialized,
  KE3,
  KE3Serialized,
  RegistrationRecord,
  RegistrationRecordSerialized
} from '@/shared/types/zero-access.utils.types'

import { Helpers } from '@/shared/utils/zero-access.utils/helpers'
import { CONFIG } from '@/shared/constants/zero-access.constants'
import { base64ToUint8Array, uint8ArrayToBase64 } from '@/shared/utils/common.utils'

export class Serializer {
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
  public static serializeRegistrationRecord(record: RegistrationRecord): RegistrationRecordSerialized {
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
  public static deserializeRegistrationRecord(record: RegistrationRecordSerialized): RegistrationRecord {
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

      Helpers.validateX25519PublicKey(clientPublicKey)

      if (maskingKey.length !== CONFIG.Nh) {
        throw new Error('Invalid maskingKey length')
      }

      Helpers.validateEnvelope(envelope)

      return { clientPublicKey, maskingKey, envelope }
    } catch (error) {
      throw new Error(`Failed to deserialize RegistrationRecord: ${error}`, { cause: error })
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
  public static serializeKE1(ke1: KE1): KE1Serialized {
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
  public static deserializeKE1(serialized: KE1Serialized): KE1 {
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
  public static serializeKE1Compact(ke1: KE1): string {
    const bytes: Uint8Array = Helpers.concat(ke1.credentialRequest.blindedMessage, ke1.authRequest.clientNonce, ke1.authRequest.clientPublicKeyshare)
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
  public static deserializeKE1Compact(base64: string): KE1 {
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
  public static serializeKE2(ke2: KE2): KE2Serialized {
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
  public static deserializeKE2(serialized: KE2Serialized): KE2 {
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
  public static serializeKE2Compact(ke2: KE2): string {
    const bytes: Uint8Array = Helpers.concat(
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
  public static deserializeKE2Compact(base64: string): KE2 {
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
  public static serializeKE3(ke3: KE3): KE3Serialized {
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
  public static deserializeKE3(serialized: KE3Serialized): KE3 {
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
  public static serializeKE3Compact(ke3: KE3): string {
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
  public static deserializeKE3Compact(base64: string): KE3 {
    const bytes: Uint8Array = base64ToUint8Array(base64)

    if (bytes.length !== 64) {
      throw new Error(`Invalid KE3 length: expected 64, got ${bytes.length}`)
    }

    return { clientMac: bytes }
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
  public static serializeChangePasswordRequest(request: ChangePasswordRequest): ChangePasswordRequestSerialized {
    return {
      credentialIdentifier: uint8ArrayToBase64(request.credentialIdentifier),
      oldPasswordKE1: this.serializeKE1(request.oldPasswordKE1),
      newPasswordRegistrationRequest: {
        blindedMessage: uint8ArrayToBase64(request.newPasswordRegistrationRequest.blindedMessage)
      }
    }
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
  public static deserializeChangePasswordRequest(serialized: ChangePasswordRequestSerialized): ChangePasswordRequest {
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
      throw new Error(`Failed to deserialize ChangePasswordRequest: ${error}`, { cause: error })
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
  public static serializeChangePasswordRequestCompact(request: ChangePasswordRequest): string {
    if (request.credentialIdentifier.length > 65535) {
      throw new Error('credentialIdentifier too long for compact serialization (max 65535 bytes)')
    }

    const bytes: Uint8Array = Helpers.concat(
      Helpers.i2OSP(request.credentialIdentifier.length, 2),
      request.credentialIdentifier,
      request.oldPasswordKE1.credentialRequest.blindedMessage,
      request.oldPasswordKE1.authRequest.clientNonce,
      request.oldPasswordKE1.authRequest.clientPublicKeyshare,
      request.newPasswordRegistrationRequest.blindedMessage
    )

    return uint8ArrayToBase64(bytes)
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
  public static deserializeChangePasswordRequestCompact(base64: string): ChangePasswordRequest {
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
   * Serializes a ChangePasswordResponse to an object with Base64 strings.
   *
   * Converts all binary fields in the password change response to Base64-encoded
   * strings for transmission over network or storage as JSON.
   *
   * @param response - The change password response to serialize.
   * @returns A serialized version with all fields as Base64 strings.
   * @public
   */
  public static serializeChangePasswordResponse(response: ChangePasswordResponse): ChangePasswordResponseSerialized {
    return {
      oldPasswordKE2: this.serializeKE2(response.oldPasswordKE2),
      newPasswordRegistrationResponse: {
        evaluatedMessage: uint8ArrayToBase64(response.newPasswordRegistrationResponse.evaluatedMessage),
        serverPublicKey: uint8ArrayToBase64(response.newPasswordRegistrationResponse.serverPublicKey)
      }
    }
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
  public static deserializeChangePasswordResponse(serialized: ChangePasswordResponseSerialized): ChangePasswordResponse {
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

      Helpers.validateX25519PublicKey(serverPublicKey)

      return {
        oldPasswordKE2,
        newPasswordRegistrationResponse: {
          evaluatedMessage,
          serverPublicKey
        }
      }
    } catch (error) {
      throw new Error(`Failed to deserialize ChangePasswordResponse: ${error}`, { cause: error })
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
  public static serializeChangePasswordResponseCompact(response: ChangePasswordResponse): string {
    // Serialize KE2 first to get its bytes
    const ke2Bytes: Uint8Array = base64ToUint8Array(this.serializeKE2Compact(response.oldPasswordKE2))
    const bytes: Uint8Array = Helpers.concat(ke2Bytes, response.newPasswordRegistrationResponse.evaluatedMessage, response.newPasswordRegistrationResponse.serverPublicKey)

    return uint8ArrayToBase64(bytes)
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
  public static deserializeChangePasswordResponseCompact(base64: string): ChangePasswordResponse {
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
}
