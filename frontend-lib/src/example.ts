/**
 * UpPass Secure Bridge — Usage Example
 *
 * Demonstrates how a frontend application integrates the library.
 * In production, PUBLIC_KEY_PEM is injected at build time or fetched
 * from a /public-key endpoint (never hardcoded in source).
 */

import { UpPassSecureBridge } from "./uppass-secure-bridge";

// ── In production: load from environment variable or config endpoint ─────────
const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLF29amygykE
... (your RSA-2048 or RSA-4096 public key here) ...
-----END PUBLIC KEY-----`;

async function submitNationalId(nationalId: string): Promise<void> {
  // 1. Initialise — import key once per session
  const bridge = new UpPassSecureBridge({ publicKeyPem: PUBLIC_KEY_PEM, keyVersion: "v1" });
  await bridge.init();

  // 2. Encrypt — new transient AES key generated each call
  const payload = await bridge.encrypt(nationalId);

  console.log("Encrypted payload:", {
    encrypted_data: payload.encrypted_data.slice(0, 40) + "...",
    encrypted_key: payload.encrypted_key.slice(0, 40) + "...",
    iv: payload.iv,
    key_version: payload.key_version,
  });

  // 3. Send to backend — plaintext never touches the wire
  const response = await fetch("https://api.uppass.io/v1/submit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Submission failed: ${response.status}`);
  }

  console.log("Submitted successfully. Reference:", (await response.json()).ref);
}

// ── Entry point ──────────────────────────────────────────────────────────────
submitNationalId("1234567890123").catch(console.error);
