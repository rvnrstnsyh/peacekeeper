# OPAQUE Protocol — Implementation Reference

**Standard:** RFC 9807  
**Suite:** ristretto255-SHA512 · X25519 3DH AKE · ED25519 signing  
**Client implementation:** `nvll/src/helpers/zero-access-client.ts` (`ZeroAccessClient`)  
**Server implementation:** `src/modules/auth/services/auth.service.ts`

---

## Table of Contents

- [OPAQUE Protocol — Implementation Reference](#opaque-protocol--implementation-reference)
  - [Table of Contents](#table-of-contents)
  - [1. Configuration Parameters](#1-configuration-parameters)
  - [2. Registration Flow](#2-registration-flow)
  - [3. Login Flow — 3-Message AKE](#3-login-flow--3-message-ake)
    - [KE1 — Client → Server](#ke1--client--server)
    - [KE2 — Server → Client](#ke2--server--client)
    - [KE3 — Client → Server (envelope recovery + mutual auth)](#ke3--client--server-envelope-recovery--mutual-auth)
  - [4. Full Key Derivation Tree](#4-full-key-derivation-tree)
  - [5. Channel Encryption](#5-channel-encryption)
  - [6. Key Properties Reference](#6-key-properties-reference)
  - [7. Security Properties](#7-security-properties)
  - [8. Legend](#8-legend)

---

## 1. Configuration Parameters

| Parameter | Value                  | Description                        |
| --------- | ---------------------- | ---------------------------------- |
| `hash`    | SHA-512                | Base hash function                 |
| `kdf`     | HKDF-SHA512            | Key derivation function            |
| `mac`     | HMAC-SHA512            | Message authentication code        |
| `Nh`      | 64 bytes               | Hash output length                 |
| `Nn`      | 32 bytes               | Nonce length                       |
| `Nm`      | 64 bytes               | MAC output length                  |
| `Npk`     | 32 bytes               | Public key length (X25519)         |
| `Noe`     | 32 bytes               | OPRF element length (ristretto255) |
| `Nok`     | 32 bytes               | OPRF key length                    |
| `Nseed`   | 32 bytes               | Seed length                        |
| `Nsk`     | 32 bytes               | Secret key length                  |
| MHF       | Argon2id               | Memory-hard function               |
| Argon2id  | m=65536 KB · t=3 · p=4 | MHF parameters                     |
| context   | `"OPAQUE-POC"`         | Protocol context string            |

---

## 2. Registration Flow

```
Client                                              Server
──────                                              ──────
password
  │
  ├─ UTF-8 encode
  ├─ H(pw) → ristretto255 point     [HashToGroup, DST: "RFCXXXX-\x00\x00\x03-HashToGroup-..."]
  ├─ r = randomScalar(32 B)          ← blind scalar (secret, kept by client)
  └─ blindedMessage = H(pw) × r
                        │
                        ├──────────── RegistrationRequest { blindedMessage } ──────────────►
                        │
                        │           evaluatedMessage = blindedMessage × serverOprfKey
                        │
                        ◄──────── RegistrationResponse { evaluatedMessage, serverX25519PublicKey }

  unblinded = evaluatedMessage × r⁻¹  (mod ristretto255 order)
  oprfOutput = SHA-512( i2OSP(len(pw))    ∥ pw
                      ∥ i2OSP(len(unblinded)) ∥ unblinded
                      ∥ "Finalize" )   → 64 B

  mhfSalt        = HKDF-Expand(oprfOutput, "OPAQUE-HashToScalar", 16 B)
  hardenedOutput = Argon2id(oprfOutput, mhfSalt)                         → 64 B

  randomizedPassword = HKDF-Extract(salt=∅, ikm= oprfOutput ∥ hardenedOutput)  → 64 B
  │
  │   envelopeNonce = randomBytes(32 B)
  │
  ├─ HKDF-Expand(rp, envelopeNonce ∥ "AuthKey",   64) → AuthKey    (64 B)  ┐
  ├─ HKDF-Expand(rp, envelopeNonce ∥ "ExportKey", 64) → ExportKey  (64 B)  │ sibling outputs
  ├─ HKDF-Expand(rp, envelopeNonce ∥ "SeedKey",   32) → SeedKey    (32 B)  │ from same rp
  └─ HKDF-Expand(rp, "MaskingKey", ∥              64) → MaskingKey (64 B)  ┘

  Seed = randomBytes(32 B)           ← master keypair seed  [NEW registration]
       = existingSeed                ← reused               [password CHANGE]

  encryptedSeed = Seed ⊕ SeedKey     ← one-time-pad, stored in Envelope

  ┌── Keypair derivation from Seed ─────────────────────────────────────────┐
  │                                                                         │
  │  subSeed_dh  = HKDF-Expand(Seed, "OPAQUE-DeriveAuthKeyPair",  32)       │
  │  x25519Priv  = clamp(subSeed_dh)                [RFC 7748 clamping]     │
  │  x25519Pub   = X25519(x25519Priv)                                       │
  │                                                                         │
  │  subSeed_sig = HKDF-Expand(Seed, "ZeroAccess-DeriveSigningKeyPair", 32) │
  │  ed25519Priv = subSeed_sig                                              │
  │  ed25519Pub  = ED25519-GetPublicKey(ed25519Priv)                        │
  └─────────────────────────────────────────────────────────────────────────┘

  authTag = HMAC-SHA512(AuthKey,
                        envelopeNonce ∥ encryptedSeed ∥ serverX25519Pub
                        ∥ i2OSP(len(serverId)) ∥ serverId
                        ∥ i2OSP(len(clientId)) ∥ clientId)    → 64 B

  Envelope = { nonce: envelopeNonce, authTag, seed: encryptedSeed }

                        ├──────────── RegistrationRecord ──────────────────────────────────►
                        │             { x25519Pub, ed25519Pub,
                        │               maskingKey, Envelope }

  ╔══════════════════════════════════════════════╗
  ║  Client keeps:  ExportKey (in memory)        ║
  ║                 Seed      (zeroed after use) ║
  ╚══════════════════════════════════════════════╝
```

> **Password change:** `existingSeed` is passed to `finalizeRegistrationRequest` so the keypair (X25519 + ED25519) remains identical across password changes. Only `randomizedPassword`, `AuthKey`, `ExportKey`, `SeedKey`, and `MaskingKey` change.

---

## 3. Login Flow — 3-Message AKE

### KE1 — Client → Server

```
Client
──────
password
  │
  ├─ blind(password) → blindedMessage, blind
  ├─ clientNonce    = randomBytes(32 B)
  ├─ clientEphSeed  = randomBytes(32 B)
  │   clientEphPriv = clamp(HKDF-Expand(clientEphSeed, "OPAQUE-DeriveAuthKeyPair", 32))
  │   clientEphPub  = X25519(clientEphPriv)
  │
  └─ state = { password, blind, clientEphPriv, ke1 }

──────────────────────────────────────────────────────────────────────────────►
KE1 = {
  credentialRequest: { blindedMessage },
  authRequest:       { clientNonce, clientEphPub }
}
```

### KE2 — Server → Client

```
Server
──────
  evaluatedMessage = blindedMessage × serverOprfKey

  credRespPad = HKDF-Expand(
    maskingKey,
    maskingNonce ∥ "CredentialResponsePad",
    Npk + Nn + Nm + Nseed B)
  maskedResponse = credRespPad ⊕ (serverX25519Pub ∥ Envelope)

  serverNonce   = randomBytes(32 B)
  serverEphPriv = clamp(HKDF-Expand(seed, "OPAQUE-DeriveAuthKeyPair", 32))
  serverEphPub  = X25519(serverEphPriv)

  [3DH — server side]
  dh1 = X25519(serverEphPriv, clientEphPub)   ← ephemeral ↔ ephemeral
  dh2 = X25519(serverLTPriv,  clientEphPub)   ← static    ↔ ephemeral
  dh3 = X25519(serverEphPriv, clientLTPub)    ← ephemeral ↔ static
  ikm = dh1 ∥ dh2 ∥ dh3

  prk             = HKDF-Extract(∅, ikm)
  SessionKey      = DeriveSecret(prk, "SessionKey",      hash(preamble))
  HandshakeSecret = DeriveSecret(prk, "HandshakeSecret", hash(preamble))
  km2             = DeriveSecret(HandshakeSecret, "ServerMAC", "")
  serverMac       = HMAC-SHA512(km2, SHA512(preamble))

◄─────────────────────────────────────────────────────────────────────────────
KE2 = {
  credentialResponse: { evaluatedMessage, maskingNonce, maskedResponse },
  authResponse:       { serverNonce, serverEphPub, serverMac }
}
```

### KE3 — Client → Server (envelope recovery + mutual auth)

```
Client
──────
  ── Envelope Recovery ──────────────────────────────────────────────────

  oprfOutput         = SHA-512(finalize(password, blind, evaluatedMessage))
  mhfSalt            = HKDF-Expand(oprfOutput, "OPAQUE-HashToScalar", 16)
  hardenedOutput     = Argon2id(oprfOutput, mhfSalt)
  randomizedPassword = HKDF-Extract(∅, oprfOutput ∥ hardenedOutput)

  MaskingKey  = HKDF-Expand(rp, "MaskingKey", 64)
  credRespPad = HKDF-Expand(MaskingKey, maskingNonce ∥ "CredentialResponsePad", …)
  unmasked    = credRespPad ⊕ maskedResponse
    → serverX25519Pub  (32 B)
    → envelopeNonce    (32 B) ┐
    → authTag          (64 B) ├─ Envelope
    → encryptedSeed    (32 B) ┘

  AuthKey   = HKDF-Expand(rp, envelopeNonce ∥ "AuthKey",   64)
  ExportKey = HKDF-Expand(rp, envelopeNonce ∥ "ExportKey", 64)  ← recovered
  SeedKey   = HKDF-Expand(rp, envelopeNonce ∥ "SeedKey",   32)

  Seed = encryptedSeed ⊕ SeedKey    ← Private Key Seed (32 B) recovered

  Verify envelope integrity:
    expectedTag = HMAC-SHA512(AuthKey,
                              envelopeNonce ∥ encryptedSeed ∥ serverX25519Pub ∥ ids)
    ctEqual(authTag, expectedTag)  →  ✗ abort / ✓ continue

  ── Keypair recovery from Seed ──────────────────────────────────────────

  x25519Priv  = clamp(HKDF-Expand(Seed, "OPAQUE-DeriveAuthKeyPair", 32))
  ed25519Priv = HKDF-Expand(Seed, "ZeroAccess-DeriveSigningKeyPair", 32)
                 (not used in AKE — for signatures only)

  ── Triple-DH (3DH) ─────────────────────────────────────────────────────

  dh1 = X25519(clientEphPriv, serverEphPub)    ← ephemeral ↔ ephemeral
  dh2 = X25519(clientEphPriv, serverX25519Pub) ← ephemeral ↔ static
  dh3 = X25519(x25519Priv,    serverEphPub)    ← static    ↔ ephemeral
  ikm = dh1 ∥ dh2 ∥ dh3                        → 96 B

  ── Key Schedule (TLS 1.3-style) ────────────────────────────────────────

  preamble = "RFCXXXX"
           ∥ i2OSP(len(ctx))      ∥ ctx
           ∥ i2OSP(len(clientId)) ∥ clientId ∥ KE1-bytes
           ∥ i2OSP(len(serverId)) ∥ serverId ∥ KE2-credResp-bytes
           ∥ serverNonce ∥ serverEphPub

  prk             = HKDF-Extract(∅, ikm)
  preambleHash    = SHA-512(preamble)

  SessionKey      = DeriveSecret(prk, "SessionKey",      preambleHash)  → 64 B
  HandshakeSecret = DeriveSecret(prk, "HandshakeSecret", preambleHash)  → 64 B
  km2             = DeriveSecret(HandshakeSecret, "ServerMAC", "")      → 64 B
  km3             = DeriveSecret(HandshakeSecret, "ClientMAC", "")      → 64 B

  DeriveSecret(s, label, ctx) =
    HKDF-Expand(s,
      i2OSP(64, 2)
      ∥ i2OSP(len("RFCXXXX " + label), 1) ∥ "RFCXXXX " + label
      ∥ i2OSP(len(SHA512(ctx)), 1)        ∥ SHA512(ctx),
      64)

  ── Mutual Authentication ────────────────────────────────────────────────

  Verify server:
    ctEqual(serverMac, HMAC-SHA512(km2, preambleHash))  →  ✗ abort

  Compute client MAC:
    clientMac = HMAC-SHA512(km3, SHA512(preamble ∥ serverMac))

──────────────────────────────────────────────────────────────────────────────►
KE3 = { clientMac }
                                    Server verifies clientMac  ← client auth
                                    Session established ✓

  ╔══════════════════════════════════════════════════════════════╗
  ║  Client final outputs:                                       ║
  ║    SessionKey      (64 B)  — ephemeral, rotates every login  ║
  ║    ExportKey       (64 B)  — stable per password             ║
  ║    Seed            (32 B)  — stable per password             ║
  ║    serverX25519Pub (32 B)  — for key pinning                 ║
  ╚══════════════════════════════════════════════════════════════╝
```

---

## 4. Full Key Derivation Tree

```
password  (user input)
  │
  ├─ HashToGroup (ristretto255, SHA-512 DST)
  ├─ × r  (random blind scalar)
  └─ blindedMessage
          │
          │  ────── OPRF round-trip with server ──────
          │  server evaluates: blindedMessage × serverOprfKey
          │  client unblinds:  evaluatedMessage × r⁻¹
          ↓
  oprfOutput  (64 B, SHA-512 Finalize)
  │
  ├─ HKDF-Expand("OPAQUE-HashToScalar", 16) → mhfSalt
  │       ↓
  │  Argon2id(oprfOutput, mhfSalt)           [m=65536 KB · t=3 · p=4]
  │       ↓
  │  hardenedOutput  (64 B)
  │
  └─ HKDF-Extract(∅, oprfOutput ∥ hardenedOutput)
          ↓
     randomizedPassword  (64 B)             ◄── central derivation point
          │
          │  (all branches below: HKDF-Expand with distinct labels + envelopeNonce)
          │
          ├── nonce ∥ "AuthKey"    → AuthKey     (64 B)
          │    Purpose: HMAC-SHA512 to seal / verify Envelope integrity.
          │    authTag = HMAC-SHA512(AuthKey, nonce∥seed∥serverPK∥ids)
          │    Verified on every login. Aborts if wrong password.
          │
          ├── nonce ∥ "ExportKey"  → ExportKey   (64 B)                [KDF]
          │    Stable per password. Never sent to server. Never stored.
          │    Purpose: application-level E2E encryption, sub-key derivation.
          │    Revealed in identity panel (requires OPAQUE re-authentication).
          │
          ├── nonce ∥ "SeedKey"    → SeedKey     (32 B)
          │    Used once as a one-time-pad key for the Seed.
          │    encryptedSeed (in Envelope) = Seed ⊕ SeedKey
          │    Recovered on login: Seed = encryptedSeed ⊕ SeedKey
          │             ↓
          │        Private Key Seed  (32 B)                            [SEED]
          │             │  Master keypair secret. Never sent to server.
          │             │  Zeroed from memory immediately after use.
          │             │
          │             ├── HKDF-Expand("OPAQUE-DeriveAuthKeyPair", 32)
          │             │     → clamp (RFC 7748) → x25519PrivateKey   (32 B)  [ENC]
          │             │     → X25519-GetPublicKey
          │             │              → x25519PublicKey              (32 B)  [ENC]
          │             │                      │
          │             │              ─────── 3DH (Triple Diffie-Hellman) ──────────
          │             │                      │
          │             │   dh1 = X25519(clientEphPriv, serverEphPub)  eph ↔ eph
          │             │   dh2 = X25519(clientEphPriv, serverLTPub)   eph ↔ static
          │             │   dh3 = X25519(x25519Priv,    serverEphPub)  static ↔ eph
          │             │   ikm = dh1 ∥ dh2 ∥ dh3  (96 B)
          │             │                      │
          │             │         HKDF-Extract(∅, ikm) → prk
          │             │                      │
          │             │     ┌────────────────┴─────────────────────┐
          │             │     │                                      │
          │             │   DeriveSecret(prk, "SessionKey", ⋯)    DeriveSecret(prk, "HandshakeSecret", ⋯)
          │             │     ↓                                      ↓
          │             │   SessionKey  (64 B)               [KEX]  HandshakeSecret  (64 B)
          │             │   Ephemeral. Rotates each login.           │
          │             │   Server holds the same copy.              ├── DeriveSecret(…, "ServerMAC", "")
          │             │   Used for channel encryption.             │     → km2 → HMAC verify server
          │             │   (HKDF-SHA256 → AES-256-GCM key)          └── DeriveSecret(…, "ClientMAC", "")
          │             │                                                  → km3 → HMAC prove client
          │             │
          │             └── HKDF-Expand("ZeroAccess-DeriveSigningKeyPair", 32)
          │                   → ed25519PrivateKey  (32 B)             [SIG]
          │                   → ED25519-GetPublicKey
          │                            → ed25519PublicKey            (32 B)  [SIG]
          │                   Stable per password. Never sent to server.
          │                   Purpose: digital signatures.
          │
          └── "MaskingKey"            → MaskingKey  (64 B)
               Stable per password. Stored in RegistrationRecord (server).
               Purpose: hides Envelope inside KE2 maskedResponse.
               maskedResponse = credRespPad ⊕ (serverX25519Pub ∥ Envelope)
```

---

## 5. Channel Encryption

After a successful login, `SessionKey` is used to establish an encrypted application channel between client and server for sensitive API routes.

```
SessionKey  (64 B, from 3DH)
  │
  └─ HKDF-SHA256(SessionKey, "peacekeeper-channel-enc-v1", salt=[], 32)
          ↓
     AES-256-GCM key  (32 B)

Wire format  (both request body and response body):
  { "enc": "<base64( nonce[12 B] ∥ ciphertext ∥ GCM-tag[16 B] )>" }

Signal header:
  X-Channel: 1     (present on both encrypted request and response)

Channel ID (_sid):
  Generated at signInBeta / changePasswordBeta: randomBytes(16).toString('hex')
  Embedded in JWT access + refresh tokens as _sid claim.
  Redis key: channel_key:{channelId}  →  base64(sessionKey)
  TTL: matches refresh token TTL. Extended on token refresh.
  Deleted on sign-out.

Protected routes (server middleware: chanEnc):
  POST  /auth/change-password/alpha
  POST  /auth/change-password/beta
  GET   /auth/profile
  POST  /auth/resend-verification
  POST  /auth/sign-out

Client allowlist (CHANNEL_ENC_PATHS):
  /change-password/alpha
  /change-password/beta
  /profile
  /resend-verification
  /sign-out
```

---

## 6. Key Properties Reference

| Key                 | Size | Stable?      | Server holds?    | Zeroed after use?             | Purpose                                |
| ------------------- | ---- | ------------ | ---------------- | ----------------------------- | -------------------------------------- |
| Private Key Seed    | 32 B | Per password | Never            | Yes                           | Master secret; source of both keypairs |
| x25519 private key  | 32 B | Per password | Never            | Yes                           | 3DH key exchange                       |
| x25519 public key   | 32 B | Per password | Stored in record | No                            | Identity / DH peer key                 |
| ed25519 private key | 32 B | Per password | Never            | Yes                           | Digital signatures                     |
| ed25519 public key  | 32 B | Per password | Stored in record | No                            | Signature verification                 |
| Export Key          | 64 B | Per password | Never            | No (held in memory)           | App-level E2E, sub-key derivation      |
| Session Key         | 64 B | Per login    | Yes (Redis, TTL) | No (stored in sessionStorage) | Channel encryption (AES-256-GCM)       |
| MaskingKey          | 64 B | Per password | Yes (in record)  | N/A                           | Hides envelope in KE2                  |
| AuthKey             | 64 B | Per login    | Never            | Yes                           | Envelope MAC verification              |
| SeedKey             | 32 B | Per login    | Never            | Yes                           | One-time XOR pad for Seed              |

---

## 7. Security Properties

| Property                                 | Mechanism                                                                                                             |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **Password never leaves client**         | OPRF: server evaluates on blinded input; never sees plaintext password                                                |
| **Offline dictionary attack resistance** | Argon2id (m=65536 KB, t=3, p=4) applied to OPRF output                                                                |
| **Forward secrecy**                      | Session Key derived from ephemeral DH components (dh1, dh2, dh3 all include at least one ephemeral key)               |
| **Mutual authentication**                | km2 proves server identity; km3 proves client identity; both via HMAC-SHA512 over full transcript                     |
| **Envelope integrity**                   | authTag = HMAC-SHA512(AuthKey, envelope contents + identities); wrong password → wrong AuthKey → tag mismatch → abort |
| **Key separation**                       | All derived keys use distinct HKDF labels; no key is reused across purposes                                           |
| **Transcript binding**                   | SessionKey and HandshakeSecret derived over SHA-512(preamble) covering all protocol messages                          |
| **Low-order point rejection**            | X25519 public keys checked against known low-order points and identity element                                        |
| **Constant-time comparison**             | `ctEqual()` used for all MAC comparisons to prevent timing attacks                                                    |
| **Key pinning**                          | `serverX25519Pub` recovered from envelope on every login; compare against published server key to detect MITM         |
| **Password change atomicity**            | Seed reused across password changes → keypair identity preserved; only envelope key material changes                  |

---

## 8. Legend

| Symbol               | Meaning                                                                                                   |
| -------------------- | --------------------------------------------------------------------------------------------------------- |
| `[SIG]`              | Used for digital signatures (ED25519)                                                                     |
| `[ENC]`              | Used for asymmetric encryption / key exchange (X25519)                                                    |
| `[KEX]`              | Key exchange output — ephemeral session key (3DH result)                                                  |
| `[KDF]`              | Used as key derivation input / application-level sub-key source                                           |
| `[SEED]`             | Master secret from which all keypairs are deterministically derived                                       |
| `∥`                  | Byte concatenation                                                                                        |
| `⊕`                  | XOR                                                                                                       |
| `r⁻¹`                | Modular inverse of blind scalar                                                                           |
| `clamp`              | RFC 7748 X25519 key clamping (bits 0–2 of byte 0 cleared; bit 7 of byte 31 cleared; bit 6 of byte 31 set) |
| Stable per password  | Same value on every login while password unchanged                                                        |
| Ephemeral            | Different value on every login; provides forward secrecy                                                  |
| Never sent to server | Client-only; zeroed from memory after use                                                                 |
