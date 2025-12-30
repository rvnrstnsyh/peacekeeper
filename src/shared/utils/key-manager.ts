/* eslint-disable no-console */

import type { JWK, KeyObject } from 'jose'

import { join } from 'path'
import { access, mkdir, readFile, writeFile } from 'fs/promises'
import { exportJWK, exportPKCS8, exportSPKI, generateKeyPair } from 'jose'

/**
 * Dual Key Management System for Node.js using JOSE
 * - Generate Ed25519 key pairs for EdDSA/JWT (signing)
 * - Generate X25519 key pairs for ECDH (encryption/key exchange)
 * - Save keys in single JSON file with JWK and PEM formats
 * - Rotate keys while preserving old ones
 */

interface SigningKeyPair {
  sec: JWK // secret (private key)
  pub: JWK // public key
  pkcs8: string // private key PEM
  spki: string // public key PEM
  at: string // created at timestamp
  v: number // version
  t: 'SIG' // type: signing
}

interface EncryptionKeyPair {
  sec: JWK // secret (private key)
  pub: JWK // public key
  pkcs8: string // private key PEM
  spki: string // public key PEM
  at: string // created at timestamp
  v: number // version
  t: 'ENC' // type: encryption
}

interface KeyStore {
  _version: number
  s: Array<SigningKeyPair> // signing keys
  e: Array<EncryptionKeyPair> // encryption keys
}

interface KeyManagerOptions {
  keysDir?: string
  keystoreFilename?: string
  silent?: boolean // disable console logs
}

/**
 * KeyManager Class - Dual Key Management System
 *
 * @example
 * ```typescript
 * // Basic usage
 * const keyManager = new KeyManager()
 * await keyManager.rotateKeys()
 * const signingKey = await keyManager.getLatestSigningKey()
 *
 * // Custom directory
 * const keyManager = new KeyManager({ keysDir: './my-keys' })
 *
 * // Silent mode (no console logs)
 * const keyManager = new KeyManager({ silent: true })
 * ```
 */
export class KeyManager {
  private keysDir: string
  private keyStoreFile: string
  private silent: boolean

  constructor(options: KeyManagerOptions = {}) {
    this.keysDir = options.keysDir || './.keys'
    this.keyStoreFile = join(this.keysDir, options.keystoreFilename || 'keystore.json')
    this.silent = options.silent || false
  }

  /**
   * Log message to console (respects silent mode)
   */
  private log(message: string): void {
    if (!this.silent) {
      console.log(message)
    }
  }

  /**
   * Check if file or directory exists
   */
  private async exists(path: string): Promise<boolean> {
    try {
      await access(path)
      return true
    } catch {
      return false
    }
  }

  /**
   * Initialize keys directory
   */
  private async initKeysDirectory(): Promise<void> {
    await mkdir(this.keysDir, { recursive: true })
    this.log(`Keys directory ready (${this.keysDir})`)
  }

  /**
   * Load existing keystore or create new one
   */
  async loadKeyStore(): Promise<KeyStore> {
    try {
      if (await this.exists(this.keyStoreFile)) {
        const data: string = await readFile(this.keyStoreFile, 'utf-8')
        const parsed: unknown = JSON.parse(data)

        // Type guard for KeyStore
        if (
          parsed !== null &&
          typeof parsed === 'object' &&
          '_version' in parsed &&
          's' in parsed &&
          'e' in parsed &&
          typeof parsed._version === 'number' &&
          Array.isArray(parsed.s) &&
          Array.isArray(parsed.e)
        ) {
          return parsed as KeyStore
        }
      }
    } catch (_error) {
      this.log('Could not load keystore, creating new one')
    }
    return {
      _version: 0,
      s: [],
      e: []
    }
  }

  /**
   * Save keystore to file
   */
  private async saveKeyStore(keyStore: KeyStore): Promise<void> {
    await writeFile(this.keyStoreFile, JSON.stringify(keyStore, null, 2), 'utf-8')
  }

  /**
   * Generate Ed25519 key pair for EdDSA signatures using JOSE
   * Returns both JWK and PEM formats
   */
  private async createSigningKeyPair(): Promise<{
    privateKey: JWK
    publicKey: JWK
    privateKeyPem: string
    publicKeyPem: string
  }> {
    // Generate Ed25519 key pair with JOSE
    const {
      privateKey,
      publicKey
    }: {
      privateKey: KeyObject
      publicKey: KeyObject
    } = await generateKeyPair('EdDSA', { extractable: true })

    // Export to JWK format
    const privateJwk: JWK = await exportJWK(privateKey)
    const publicJwk: JWK = await exportJWK(publicKey)

    // Export to PEM format (PKCS8 for private, SPKI for public)
    const privatePem: string = await exportPKCS8(privateKey)
    const publicPem: string = await exportSPKI(publicKey)

    return {
      privateKey: privateJwk,
      publicKey: publicJwk,
      privateKeyPem: privatePem,
      publicKeyPem: publicPem
    }
  }

  /**
   * Generate X25519 key pair for ECDH key exchange using JOSE
   * Returns both JWK and PEM formats
   */
  private async createEncryptionKeyPair(): Promise<{
    privateKey: JWK
    publicKey: JWK
    privateKeyPem: string
    publicKeyPem: string
  }> {
    // Generate X25519 key pair with JOSE
    const {
      privateKey,
      publicKey
    }: {
      privateKey: KeyObject
      publicKey: KeyObject
    } = await generateKeyPair('ECDH-ES', { crv: 'X25519', extractable: true })

    // Export to JWK format
    const privateJwk: JWK = await exportJWK(privateKey)
    const publicJwk: JWK = await exportJWK(publicKey)

    // Export to PEM format (PKCS8 for private, SPKI for public)
    const privatePem: string = await exportPKCS8(privateKey)
    const publicPem: string = await exportSPKI(publicKey)

    return {
      privateKey: privateJwk,
      publicKey: publicJwk,
      privateKeyPem: privatePem,
      publicKeyPem: publicPem
    }
  }

  /**
   * Generate and save new key pairs (both signing and encryption)
   */
  private async createNewKeyPairs(): Promise<KeyStore> {
    await this.initKeysDirectory()

    const keyStore: KeyStore = await this.loadKeyStore()
    const newVersion: number = keyStore._version + 1

    this.log(`\nGenerating key pairs (version ${newVersion})...`)

    // Generate Ed25519 signing key
    this.log('  → Generating Ed25519 signing key...')
    const signingKeys = await this.createSigningKeyPair()

    // Generate X25519 encryption key
    this.log('  → Generating X25519 encryption key...')
    const encryptionKeys = await this.createEncryptionKeyPair()

    // Add signing key to keystore
    const newSigningKey: SigningKeyPair = {
      sec: signingKeys.privateKey,
      pub: signingKeys.publicKey,
      pkcs8: signingKeys.privateKeyPem,
      spki: signingKeys.publicKeyPem,
      at: new Date().toISOString(),
      v: newVersion,
      t: 'SIG'
    }

    // Add encryption key to keystore
    const newEncryptionKey: EncryptionKeyPair = {
      sec: encryptionKeys.privateKey,
      pub: encryptionKeys.publicKey,
      pkcs8: encryptionKeys.privateKeyPem,
      spki: encryptionKeys.publicKeyPem,
      at: new Date().toISOString(),
      v: newVersion,
      t: 'ENC'
    }

    keyStore.s.push(newSigningKey)
    keyStore.e.push(newEncryptionKey)
    keyStore._version = newVersion

    // Save keystore
    await this.saveKeyStore(keyStore)

    this.log('Key pairs successfully generated (JWK + PEM formats)\n')

    return keyStore
  }

  /**
   * Rotate keys - generate new key pairs while keeping old ones
   */
  async rotateKeys(): Promise<KeyStore> {
    const keyStore: KeyStore = await this.loadKeyStore()

    if (keyStore.s.length === 0 || keyStore.e.length === 0) {
      this.log('No existing keys found, creating first key pairs...')
      return await this.createNewKeyPairs()
    }

    this.log(`\nRotating keys from version ${keyStore._version}...`)
    this.log(`Preserving ${keyStore.s.length} previous signing key(s)`)
    this.log(`Preserving ${keyStore.e.length} previous encryption key(s)`)

    const newKeyStore: KeyStore = await this.createNewKeyPairs()

    this.log('Key rotation complete:')
    this.log(`  - Latest version: ${newKeyStore._version}`)
    this.log(`  - Total signing keys: ${newKeyStore.s.length}`)
    this.log(`  - Total encryption keys: ${newKeyStore.e.length}`)

    const previousVersions: string =
      newKeyStore.s
        .slice(0, -1)
        .map((k: SigningKeyPair) => `v${k.v}`)
        .join(', ') || 'none'

    this.log(`  - Previous versions: ${previousVersions}\n`)

    return newKeyStore
  }

  /**
   * List all stored keys
   */
  async listKeys(): Promise<void> {
    const keyStore: KeyStore = await this.loadKeyStore()

    if (keyStore.s.length === 0 && keyStore.e.length === 0) {
      this.log('No keys found in keystore')
      return
    }

    // Display signing keys
    if (keyStore.s.length > 0) {
      this.log('Ed25519 - EdDSA/JWT (signing):')
      this.log('─'.repeat(70))

      keyStore.s.forEach((key: SigningKeyPair) => {
        const isLatest: boolean = key.v === keyStore._version
        const marker: string = isLatest ? '  ✓ ' : '    '
        this.log(`${marker} │ v${key.v} - at: ${new Date(key.at).toLocaleString()}`)
        this.log(`     │       x: ${key.pub.x?.substring(0, 32)}...`)
      })
      this.log('─'.repeat(70))
      this.log(`Total: ${keyStore.s.length} signing key pair(s)\n`)
    }

    // Display encryption keys
    if (keyStore.e.length > 0) {
      this.log('X25519 - ECDH (encryption/key exchange):')
      this.log('─'.repeat(70))

      keyStore.e.forEach((key: EncryptionKeyPair) => {
        const isLatest: boolean = key.v === keyStore._version
        const marker: string = isLatest ? '  ✓ ' : '    '
        this.log(`${marker} │ v${key.v} - at: ${new Date(key.at).toLocaleString()}`)
        this.log(`     │       x: ${key.pub.x?.substring(0, 32)}...`)
      })
      this.log('─'.repeat(70))
      this.log(`Total: ${keyStore.e.length} encryption key pair(s)\n`)
    }
  }

  /**
   * Get latest signing key (for JWT signing)
   */
  async getLatestSigningKey(): Promise<SigningKeyPair | null> {
    const keyStore: KeyStore = await this.loadKeyStore()

    if (keyStore.s.length === 0) {
      return null
    }

    const latestKey: SigningKeyPair | undefined = keyStore.s.find((k: SigningKeyPair) => k.v === keyStore._version)

    return latestKey || null
  }

  /**
   * Get latest encryption key (for key exchange)
   */
  async getLatestEncryptionKey(): Promise<EncryptionKeyPair | null> {
    const keyStore: KeyStore = await this.loadKeyStore()

    if (keyStore.e.length === 0) {
      return null
    }

    const latestKey: EncryptionKeyPair | undefined = keyStore.e.find((k: EncryptionKeyPair) => k.v === keyStore._version)

    return latestKey || null
  }

  /**
   * Get signing key by version (for JWT verification)
   */
  async getSigningKeyByVersion(version: number): Promise<SigningKeyPair | null> {
    const keyStore: KeyStore = await this.loadKeyStore()
    const key: SigningKeyPair | undefined = keyStore.s.find((k: SigningKeyPair) => k.v === version)
    return key || null
  }

  /**
   * Get encryption key by version (for decryption)
   */
  async getEncryptionKeyByVersion(version: number): Promise<EncryptionKeyPair | null> {
    const keyStore: KeyStore = await this.loadKeyStore()
    const key: EncryptionKeyPair | undefined = keyStore.e.find((k: EncryptionKeyPair) => k.v === version)
    return key || null
  }

  /**
   * Get all latest keys
   */
  async getLatestKeys(): Promise<{
    signing: SigningKeyPair | null
    encryption: EncryptionKeyPair | null
  }> {
    return {
      signing: await this.getLatestSigningKey(),
      encryption: await this.getLatestEncryptionKey()
    }
  }

  /**
   * Get all signing keys
   */
  async getAllSigningKeys(): Promise<SigningKeyPair[]> {
    const keyStore: KeyStore = await this.loadKeyStore()
    return keyStore.s
  }

  /**
   * Get all encryption keys
   */
  async getAllEncryptionKeys(): Promise<EncryptionKeyPair[]> {
    const keyStore: KeyStore = await this.loadKeyStore()
    return keyStore.e
  }

  /**
   * Get keystore version
   */
  async getVersion(): Promise<number> {
    const keyStore: KeyStore = await this.loadKeyStore()
    return keyStore._version
  }

  /**
   * Check if keystore has keys
   */
  async hasKeys(): Promise<boolean> {
    const keyStore: KeyStore = await this.loadKeyStore()
    return keyStore.s.length > 0 && keyStore.e.length > 0
  }
}

// Export types for external use
export type { EncryptionKeyPair, KeyManagerOptions, KeyStore, SigningKeyPair }

// CLI usage
const isMainModule: boolean = typeof require !== 'undefined' && require.main === module
if (isMainModule) {
  ;(async () => {
    const keyManager: KeyManager = new KeyManager()

    switch (process.argv[2]) {
      case 'rotate':
        await keyManager.rotateKeys()
        break
      case 'list':
        await keyManager.listKeys()
        break
      case 'latest': {
        const keys = await keyManager.getLatestKeys()
        if (keys.signing || keys.encryption) {
          console.log('\nLatest Keys:')
          console.log('═'.repeat(70))
          if (keys.signing) {
            console.log('\nSigning Key (Ed25519):')
            console.log(JSON.stringify(keys.signing, null, 2))
          }
          if (keys.encryption) {
            console.log('\nEncryption Key (X25519):')
            console.log(JSON.stringify(keys.encryption, null, 2))
          }
          console.log('')
        } else {
          console.log('No keys found')
        }
        break
      }
      case 'signing': {
        const signingKey = await keyManager.getLatestSigningKey()
        if (signingKey) {
          console.log('\nLatest Signing Key (Ed25519):')
          console.log(JSON.stringify(signingKey, null, 2))
        } else {
          console.log('No signing key found')
        }
        break
      }
      case 'encryption': {
        const encryptionKey = await keyManager.getLatestEncryptionKey()
        if (encryptionKey) {
          console.log('\nLatest Encryption Key (X25519):')
          console.log(JSON.stringify(encryptionKey, null, 2))
        } else {
          console.log('No encryption key found')
        }
        break
      }
      default:
        console.log('Usage:')
        console.log('  tsx key-manager rotate       # Rotate both keys (keeps old ones)')
        console.log('  tsx key-manager list         # List all stored keys')
        console.log('  tsx key-manager latest       # Show both latest keys')
        console.log('  tsx key-manager signing      # Show latest signing key only')
        console.log('  tsx key-manager encryption   # Show latest encryption key only')
        console.log('')
        console.log('Or with ts-node:')
        console.log('  ts-node key-manager rotate')
        console.log('')
    }
  })()
}
