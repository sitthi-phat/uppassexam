/**
 * UpPass Secure Bridge — Client-side E2E Encryption Library
 *
 * Hybrid Encryption: RSA-OAEP (key wrapping) + AES-256-GCM (payload)
 *
 * Security properties:
 *  - AES-256-GCM: authenticated encryption (confidentiality + integrity)
 *  - RSA-OAEP: padding-oracle-resistant key wrapping
 *  - Transient symmetric key: unique per submission, never reused
 *  - Web Crypto API: no third-party dependencies, browser-native
 */

export interface EncryptedPayload {
  /** AES-GCM ciphertext + auth tag, base64-encoded */
  encrypted_data: string;
  /** AES-256 key wrapped with server's RSA public key, base64-encoded */
  encrypted_key: string;
  /** AES-GCM initialisation vector, base64-encoded (required for decryption) */
  iv: string;
  /** Key algorithm identifier for future key rotation support */
  key_version: string;
}

export interface SecureBridgeOptions {
  /** PEM-encoded RSA public key from the server */
  publicKeyPem: string;
  /** Key version tag for server-side key rotation handling (default: "v1") */
  keyVersion?: string;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function base64Encode(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// ─── Main Class ─────────────────────────────────────────────────────────────

export class UpPassSecureBridge {
  private rsaPublicKey: CryptoKey | null = null;
  private keyVersion: string;

  constructor(private readonly options: SecureBridgeOptions) {
    this.keyVersion = options.keyVersion ?? "v1";
  }

  /**
   * Import and cache the RSA public key.
   * Must be called once before encrypt().
   */
  async init(): Promise<void> {
    const keyBuffer = pemToArrayBuffer(this.options.publicKeyPem);

    this.rsaPublicKey = await crypto.subtle.importKey(
      "spki",
      keyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      false,      // non-extractable: private memory only
      ["wrapKey"] // only allowed usage
    );
  }

  /**
   * Encrypt a sensitive payload using hybrid encryption.
   *
   * Flow:
   *   1. Generate random AES-256-GCM transient key
   *   2. Encrypt plaintext with AES-256-GCM  → encrypted_data
   *   3. Wrap AES key with RSA-OAEP           → encrypted_key
   *   4. Return packaged payload
   */
  async encrypt(plaintext: string): Promise<EncryptedPayload> {
    if (!this.rsaPublicKey) {
      throw new Error("SecureBridge not initialised. Call init() first.");
    }

    // Step 1: Generate a transient AES-256-GCM key (ephemeral, never stored)
    const aesKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,         // extractable=true so we can wrap it with RSA
      ["encrypt"]
    );

    // Step 2: Encrypt the payload
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV (GCM standard)
    const encoded = new TextEncoder().encode(plaintext);

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      encoded
    );

    // Step 3: Wrap (encrypt) the AES key using the server's RSA public key
    const wrappedKey = await crypto.subtle.wrapKey(
      "raw",
      aesKey,
      this.rsaPublicKey,
      { name: "RSA-OAEP" }
    );

    return {
      encrypted_data: base64Encode(ciphertext),
      encrypted_key: base64Encode(wrappedKey),
      iv: base64Encode(iv.buffer),
      key_version: this.keyVersion,
    };
  }
}
