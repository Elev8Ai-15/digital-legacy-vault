/**
 * vault-crypto.js — Client-Side Encryption Layer
 * 
 * Digital Legacy Vault - AES-256-GCM Encryption
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * This module handles the encryption pipeline BEFORE Shamir splitting:
 *   1. User enters credentials
 *   2. Credentials are encrypted with AES-256-GCM (this module)
 *   3. Encrypted blob is split into shares via Shamir SSS
 *   4. Shares are distributed to guardians
 * 
 * All operations run in the browser using Web Crypto API.
 * Nothing unencrypted ever leaves the client device.
 */

// ============================================================
// KEY DERIVATION
// ============================================================

/**
 * Derive an AES-256 key from a user's master password using PBKDF2
 * 
 * @param {string} password - User's master password
 * @param {Uint8Array} salt - Random salt (stored alongside encrypted data)
 * @param {number} iterations - PBKDF2 iterations (default 600,000 — OWASP 2023 recommendation)
 * @returns {Promise<CryptoKey>} AES-256-GCM encryption key
 */
async function deriveKey(password, salt, iterations = 600000) {
  const encoder = new TextEncoder();
  
  // Import password as raw key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  // Derive AES-256 key via PBKDF2-HMAC-SHA256
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, // not extractable
    ["encrypt", "decrypt"]
  );
}

/**
 * Generate a cryptographically secure random salt
 * @param {number} length - Salt length in bytes (default 32)
 * @returns {Uint8Array}
 */
function generateSalt(length = 32) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generate a random initialization vector for AES-GCM
 * @returns {Uint8Array} 12-byte IV (recommended for AES-GCM)
 */
function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

// ============================================================
// ENCRYPTION / DECRYPTION
// ============================================================

/**
 * Encrypt credential data with AES-256-GCM
 * 
 * @param {Object} credentials - The credentials to encrypt
 * @param {string} credentials.platform - Platform name (e.g., "Instagram")
 * @param {string} credentials.username - Username or email
 * @param {string} credentials.password - Account password
 * @param {string} masterPassword - User's vault master password
 * @returns {Promise<{encrypted: string, salt: string, iv: string}>} Base64-encoded encrypted package
 */
async function encryptCredentials(credentials, masterPassword) {
  if (!masterPassword || masterPassword.length < 8) {
    throw new Error("Master password must be at least 8 characters");
  }

  const encoder = new TextEncoder();
  
  // Serialize credentials to JSON
  const plaintext = JSON.stringify({
    p: credentials.platform,
    u: credentials.username,
    pw: credentials.password,
    ts: Date.now(), // timestamp for freshness verification
    v: 1, // schema version
  });

  // Generate random salt and IV
  const salt = generateSalt(32);
  const iv = generateIV();

  // Derive encryption key
  const key = await deriveKey(masterPassword, salt);

  // Encrypt with AES-256-GCM
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128, // 128-bit auth tag (maximum security)
    },
    key,
    encoder.encode(plaintext)
  );

  // Package as base64 strings for storage/transport
  return {
    encrypted: arrayBufferToBase64(ciphertext),
    salt: arrayBufferToBase64(salt),
    iv: arrayBufferToBase64(iv),
    version: 1,
  };
}

/**
 * Decrypt credential data with AES-256-GCM
 * 
 * @param {Object} encryptedPackage - The encrypted package from encryptCredentials
 * @param {string} masterPassword - User's vault master password
 * @returns {Promise<{platform: string, username: string, password: string}>} Decrypted credentials
 */
async function decryptCredentials(encryptedPackage, masterPassword) {
  const salt = base64ToUint8Array(encryptedPackage.salt);
  const iv = base64ToUint8Array(encryptedPackage.iv);
  const ciphertext = base64ToArrayBuffer(encryptedPackage.encrypted);

  // Derive the same key
  const key = await deriveKey(masterPassword, salt);

  // Decrypt
  let plaintext;
  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: 128,
      },
      key,
      ciphertext
    );
    plaintext = new TextDecoder().decode(decrypted);
  } catch (e) {
    throw new Error("Decryption failed — wrong password or corrupted data");
  }

  // Parse and validate
  const parsed = JSON.parse(plaintext);
  if (parsed.v !== 1) {
    throw new Error(`Unsupported credential schema version: ${parsed.v}`);
  }

  return {
    platform: parsed.p,
    username: parsed.u,
    password: parsed.pw,
    encryptedAt: new Date(parsed.ts),
  };
}

// ============================================================
// FULL PIPELINE: ENCRYPT → SPLIT → DISTRIBUTE
// ============================================================

/**
 * Full encryption pipeline: encrypt credentials then split into Shamir shares
 * 
 * @param {Object} credentials - Platform credentials
 * @param {string} masterPassword - User's master password
 * @param {number} totalShares - Number of shares to create (default 5)
 * @param {number} threshold - Minimum shares needed to reconstruct (default 3)
 * @param {Function} shamirSplit - Reference to ShamirSSS.split
 * @returns {Promise<{shares: Array, metadata: Object}>} Shares + metadata needed for reconstruction
 */
async function encryptAndSplit(credentials, masterPassword, totalShares = 5, threshold = 3, shamirSplit) {
  // Step 1: Encrypt credentials
  const encrypted = await encryptCredentials(credentials, masterPassword);
  
  // Step 2: Serialize the encrypted package to a string
  const serialized = JSON.stringify(encrypted);
  
  // Step 3: Split the serialized encrypted data using Shamir's SSS
  const shares = shamirSplit(serialized, totalShares, threshold);
  
  // Metadata needed for reconstruction (NOT secret — can be stored on-chain or platform)
  const metadata = {
    platform: credentials.platform,
    username: credentials.username.replace(/(.{2}).*(@.*)/, "$1***$2"), // masked
    totalShares,
    threshold,
    createdAt: new Date().toISOString(),
    encryptionVersion: 1,
    algorithm: "AES-256-GCM",
    kdf: "PBKDF2-SHA256-600000",
  };
  
  return { shares, metadata };
}

/**
 * Full reconstruction pipeline: collect shares → reconstruct → decrypt
 * 
 * @param {Array} shares - At least `threshold` Shamir shares
 * @param {string} masterPassword - User's (or beneficiary's) master password
 * @param {Function} shamirReconstruct - Reference to ShamirSSS.reconstruct
 * @returns {Promise<Object>} Decrypted credentials
 */
async function reconstructAndDecrypt(shares, masterPassword, shamirReconstruct) {
  // Step 1: Reconstruct the encrypted package from shares
  const serialized = shamirReconstruct(shares);
  
  // Step 2: Parse the encrypted package
  const encrypted = JSON.parse(serialized);
  
  // Step 3: Decrypt with master password
  const credentials = await decryptCredentials(encrypted, masterPassword);
  
  return credentials;
}

// ============================================================
// UTILITIES
// ============================================================

function arrayBufferToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64ToArrayBuffer(base64) {
  return base64ToUint8Array(base64).buffer;
}

/**
 * Estimate password strength (basic — use zxcvbn in production)
 * @param {string} password
 * @returns {{score: number, feedback: string}} Score 0-4
 */
function estimatePasswordStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  
  score = Math.min(score, 4);
  
  const feedback = [
    "Very weak — easily crackable",
    "Weak — add more character types",
    "Fair — consider making it longer",
    "Strong — good complexity",
    "Very strong — excellent",
  ][score];
  
  return { score, feedback };
}

// ============================================================
// EXPORTS
// ============================================================

export {
  encryptCredentials,
  decryptCredentials,
  encryptAndSplit,
  reconstructAndDecrypt,
  deriveKey,
  generateSalt,
  generateIV,
  estimatePasswordStrength,
};
