/**
 * OPAQUE protocol configuration parameters.
 *
 * Defines the cryptographic primitives and size parameters for the
 * OPAQUE protocol instance. This implementation uses ristretto255-SHA512
 * configuration as specified in RFC 9807.
 *
 * @see RFC 9807 - OPAQUE specification
 */
export interface OpaqueConfig {
  /** Hash function used throughout the protocol ('sha256' | 'sha512') */
  hash: 'sha256' | 'sha512'
  /** Key derivation function ('hkdf-sha256' | 'hkdf-sha512') */
  kdf: 'hkdf-sha256' | 'hkdf-sha512'
  /** Message authentication code function ('hmac-sha256' | 'hmac-sha512') */
  mac: 'hmac-sha256' | 'hmac-sha512'
  /** Application-specific context string for domain separation (max 255 bytes) */
  context: string
  /** Hash output length in bytes (64 for SHA-512) */
  Nh: number
  /** Nonce length in bytes (32) */
  Nn: number
  /** MAC output length in bytes (64 for HMAC-SHA512) */
  Nm: number
  /** Public key length in bytes (32 for X25519) */
  Npk: number
  /** OPRF element length in bytes (32 for ristretto255) */
  Noe: number
  /** OPRF key length in bytes (32 for ristretto255 scalar) */
  Nok: number
  /** Seed length in bytes (32) */
  Nseed: number
  /** Secret key length in bytes (32 for X25519) */
  Nsk: number
}

/**
 * Registration request message from client to server.
 *
 * Contains the blinded password that the server will evaluate using
 * its OPRF key during the registration protocol.
 *
 * @see RFC 9807 Section 5.1.1 - CreateRegistrationRequest
 */
export interface RegistrationRequest {
  /** Blinded password element (ristretto255 point, 32 bytes) */
  blindedMessage: Uint8Array
}

/**
 * Registration response message from server to client.
 *
 * Contains the OPRF evaluation of the client's blinded password
 * and the server's long-term public key.
 *
 * @see RFC 9807 Section 5.1.2 - CreateRegistrationResponse
 */
export interface RegistrationResponse {
  /** OPRF-evaluated blinded message (ristretto255 point, 32 bytes) */
  evaluatedMessage: Uint8Array
  /** Server's long-term public key (X25519, 32 bytes) */
  serverPublicKey: Uint8Array
}

/**
 * Encrypted envelope containing protected credential material.
 *
 * The envelope encrypts the client's keypair seed using keys derived
 * from the password. It includes an authentication tag to verify
 * password correctness during recovery.
 *
 * @see RFC 9807 Section 4.1.1 - Envelope structure
 */
export interface Envelope {
  /** Random nonce for key derivation (32 bytes) */
  nonce: Uint8Array
  /** Authentication tag verifying envelope integrity (64 bytes for HMAC-SHA512) */
  authTag: Uint8Array
  /** Encrypted client keypair seed (32 bytes) */
  seed: Uint8Array
}

/**
 * Registration record stored by the server for each credential.
 *
 * Contains the client's public key, a masking key for protecting
 * credential responses, and the encrypted envelope. This record is
 * retrieved during authentication.
 *
 * @see RFC 9807 Section 4 - Registration record
 */
export interface RegistrationRecord {
  /** Client's long-term public key (X25519, 32 bytes) */
  clientPublicKey: Uint8Array
  /** Key used to mask credential responses (64 bytes) */
  maskingKey: Uint8Array
  /** Encrypted envelope containing client's private key material */
  envelope: Envelope
}

/**
 * Serialized registration record with Base64-encoded fields.
 *
 * Used for JSON storage or transmission. All binary fields are
 * encoded as Base64 strings.
 */
export interface RegistrationRecordSerialized {
  /** Base64-encoded client public key */
  clientPublicKey: string
  /** Base64-encoded masking key */
  maskingKey: string
  /** Envelope with Base64-encoded fields */
  envelope: {
    /** Base64-encoded nonce */
    nonce: string
    /** Base64-encoded authentication tag */
    authTag: string
    /** Base64-encoded encrypted seed */
    seed: string
  }
}

/**
 * Credential request message during authentication.
 *
 * Contains the blinded password that the server will evaluate
 * using its OPRF key derived from the credential identifier.
 *
 * @see RFC 9807 Section 5.1 - CreateCredentialRequest
 */
export interface CredentialRequest {
  /** Blinded password element (ristretto255 point, 32 bytes) */
  blindedMessage: Uint8Array
}

/**
 * Credential response message from server during authentication.
 *
 * Contains the OPRF evaluation and the masked registration record
 * (server public key and envelope). Masking prevents offline attacks
 * by requiring online interaction to verify password guesses.
 *
 * @see RFC 9807 Section 5.1 - CreateCredentialResponse
 */
export interface CredentialResponse {
  /** OPRF-evaluated blinded message (ristretto255 point, 32 bytes) */
  evaluatedMessage: Uint8Array
  /** Random nonce for masking key derivation (32 bytes) */
  maskingNonce: Uint8Array
  /** Masked server public key and envelope (variable length) */
  maskedResponse: Uint8Array
}

/**
 * Cleartext credentials containing identity information.
 *
 * Includes public keys and optional identity strings for both
 * server and client. These are used during envelope operations
 * and authentication.
 *
 * @see RFC 9807 Section 4 - Cleartext credentials
 */
export interface CleartextCredentials {
  /** Server's long-term public key (X25519, 32 bytes) */
  serverPublicKey: Uint8Array
  /** Server identity (defaults to serverPublicKey if not provided) */
  serverIdentity: Uint8Array
  /** Client's long-term public key (X25519, 32 bytes) */
  clientPublicKey: Uint8Array
  /** Client identity (defaults to clientPublicKey if not provided) */
  clientIdentity: Uint8Array
}

/**
 * Authentication request from client in KE1 message.
 *
 * Contains the client's ephemeral public key and nonce for the
 * authenticated key exchange protocol.
 *
 * @see RFC 9807 Section 6.2.3 - KE1 structure
 */
export interface AuthRequest {
  /** Client's random nonce (32 bytes) */
  clientNonce: Uint8Array
  /** Client's ephemeral public key for this session (X25519, 32 bytes) */
  clientPublicKeyshare: Uint8Array
}

/**
 * Authentication response from server in KE2 message.
 *
 * Contains the server's ephemeral public key, nonce, and MAC
 * for mutual authentication in the key exchange protocol.
 *
 * @see RFC 9807 Section 6.2.4 - KE2 structure
 */
export interface AuthResponse {
  /** Server's random nonce (32 bytes) */
  serverNonce: Uint8Array
  /** Server's ephemeral public key for this session (X25519, 32 bytes) */
  serverPublicKeyshare: Uint8Array
  /** Server's authentication MAC (64 bytes for HMAC-SHA512) */
  serverMac: Uint8Array
}

/**
 * First message (KE1) in the authenticated key exchange protocol.
 *
 * Combines the credential request (blinded password) with the
 * authentication request (ephemeral key and nonce). Sent from
 * client to server to initiate authentication.
 *
 * @see RFC 9807 Section 6.2.3 - Client generates KE1
 */
export interface KE1 {
  /** Credential request containing blinded password */
  credentialRequest: CredentialRequest
  /** Authentication request containing ephemeral key and nonce */
  authRequest: AuthRequest
}

/**
 * Serialized KE1 message with Base64-encoded fields.
 *
 * Used for JSON transmission. All binary fields are encoded
 * as Base64 strings.
 */
export interface KE1Serialized {
  /** Base64-encoded blinded password element */
  blindedMessage: string
  /** Base64-encoded client nonce */
  clientNonce: string
  /** Base64-encoded client ephemeral public key */
  clientPublicKeyshare: string
}

/**
 * Second message (KE2) in the authenticated key exchange protocol.
 *
 * Combines the credential response (OPRF evaluation and masked envelope)
 * with the authentication response (ephemeral key, nonce, and server MAC).
 * Sent from server to client.
 *
 * @see RFC 9807 Section 6.2.4 - Server generates KE2
 */
export interface KE2 {
  /** Credential response containing OPRF evaluation and masked data */
  credentialResponse: CredentialResponse
  /** Authentication response containing ephemeral key and server MAC */
  authResponse: AuthResponse
}

/**
 * Serialized KE2 message with Base64-encoded fields.
 *
 * Used for JSON transmission. All binary fields are encoded
 * as Base64 strings.
 */
export interface KE2Serialized {
  /** Base64-encoded OPRF-evaluated element */
  evaluatedMessage: string
  /** Base64-encoded masking nonce */
  maskingNonce: string
  /** Base64-encoded masked response (variable length) */
  maskedResponse: string
  /** Base64-encoded server nonce */
  serverNonce: string
  /** Base64-encoded server ephemeral public key */
  serverPublicKeyshare: string
  /** Base64-encoded server authentication MAC */
  serverMac: string
}

/**
 * Third message (KE3) in the authenticated key exchange protocol.
 *
 * Contains the client's authentication MAC to prove knowledge of
 * the session key. Sent from client to server to complete mutual
 * authentication.
 *
 * @see RFC 9807 Section 6.2.5 - Client generates KE3
 */
export interface KE3 {
  /** Client's authentication MAC (64 bytes for HMAC-SHA512) */
  clientMac: Uint8Array
}

/**
 * Serialized KE3 message with Base64-encoded MAC.
 *
 * Used for JSON transmission.
 */
export interface KE3Serialized {
  /** Base64-encoded client authentication MAC */
  clientMac: string
}

/**
 * Client-side ephemeral state during authentication.
 *
 * Contains all information the client needs to preserve between
 * sending KE1 and processing KE2 to generate KE3. Must be kept
 * secret and discarded after authentication completes.
 */
export interface ClientState {
  /** The user's password (must be kept secret) */
  password: string
  /** OPRF blinding factor (must be kept secret) */
  blind: Uint8Array
  /** Client's ephemeral private key for this session (must be kept secret) */
  clientSecret: Uint8Array
  /** Copy of the KE1 message for transcript construction */
  ke1: KE1
}

/**
 * Server-side ephemeral state during authentication.
 *
 * Contains the expected client MAC and the derived session key.
 * Used to verify KE3 and finalize the authenticated session.
 * Should be discarded after authentication completes.
 */
export interface ServerState {
  /** Expected client MAC for KE3 verification */
  expectedClientMac: Uint8Array
  /** Derived session key for this authenticated session */
  sessionKey: Uint8Array
}

/**
 * Password change request from client to server.
 *
 * Combines authentication with the old password (KE1) and
 * registration of the new password. Allows atomic password
 * changes with mutual authentication.
 */
export interface ChangePasswordRequest {
  /** Identifier for the credential being changed */
  credentialIdentifier: Uint8Array
  /** KE1 message for authenticating with the old password */
  oldPasswordKE1: KE1
  /** Registration request for the new password */
  newPasswordRegistrationRequest: RegistrationRequest
}

/**
 * Serialized ChangePasswordRequest with Base64-encoded fields.
 *
 * Used for JSON transmission. All binary fields are encoded
 * as Base64 strings.
 */
export interface ChangePasswordRequestSerialized {
  /** Base64-encoded credential identifier */
  credentialIdentifier: string
  /** Serialized KE1 for old password authentication */
  oldPasswordKE1: KE1Serialized
  /** Serialized registration request for new password */
  newPasswordRegistrationRequest: {
    /** Base64-encoded blinded password element */
    blindedMessage: string
  }
}

/**
 * Password change response from server to client.
 *
 * Contains KE2 for old password authentication and a registration
 * response for the new password registration.
 */
export interface ChangePasswordResponse {
  /** KE2 message for old password authentication */
  oldPasswordKE2: KE2
  /** Registration response for new password */
  newPasswordRegistrationResponse: RegistrationResponse
}

/**
 * Serialized ChangePasswordResponse with Base64-encoded fields.
 *
 * Used for JSON transmission. All binary fields are encoded
 * as Base64 strings.
 */
export interface ChangePasswordResponseSerialized {
  /** Serialized KE2 for old password authentication */
  oldPasswordKE2: KE2Serialized
  /** Serialized registration response for new password */
  newPasswordRegistrationResponse: {
    /** Base64-encoded OPRF-evaluated element */
    evaluatedMessage: string
    /** Base64-encoded server public key */
    serverPublicKey: string
  }
}

/**
 * Client-side ephemeral state during password change.
 *
 * Contains all information needed to finalize the password change
 * after receiving the server's response. Includes both old and new
 * password blinding factors.
 */
export interface ChangePasswordClientState {
  /** The user's current (old) password */
  oldPassword: string
  /** The user's desired new password */
  newPassword: string
  /** OPRF blinding factor for old password */
  oldBlind: Uint8Array
  /** OPRF blinding factor for new password */
  newBlind: Uint8Array
  /** Client's ephemeral private key from old password KE1 */
  clientSecret: Uint8Array
  /** Copy of the old password KE1 message */
  oldKE1: KE1
}
