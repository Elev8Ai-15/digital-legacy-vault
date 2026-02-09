/**
 * did-manager.js — Decentralized Identity Module
 * 
 * Digital Legacy Vault - W3C DID & Verifiable Credentials
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * Implements DID:key method (simplest, no external resolution needed)
 * and Verifiable Credential issuance for beneficiary identity proof.
 * 
 * W3C Standards:
 *   - DID Core: https://www.w3.org/TR/did-core/
 *   - VC Data Model: https://www.w3.org/TR/vc-data-model-2.0/
 * 
 * Usage:
 *   const manager = new DIDManager();
 *   const { did, keyPair } = await manager.createDID();
 *   const vc = await manager.issueVerifiableCredential(did, claims);
 */

// ============================================================
// KEY PAIR GENERATION
// ============================================================

/**
 * Generate an ECDSA P-256 key pair using Web Crypto API
 * P-256 chosen for compatibility with BBS# ZKP signatures
 * 
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey, publicKeyJwk: Object}>}
 */
async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true, // extractable (needed for DID document)
    ["sign", "verify"]
  );

  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyJwk,
    privateKeyJwk,
  };
}

/**
 * Convert JWK public key to multibase-encoded multicodec key
 * Required for did:key method
 */
function jwkToMultibase(publicKeyJwk) {
  // P-256 multicodec prefix: 0x1200
  const xBytes = base64UrlToBytes(publicKeyJwk.x);
  const yBytes = base64UrlToBytes(publicKeyJwk.y);

  // Uncompressed point format: 0x04 || x || y
  const uncompressed = new Uint8Array(1 + 32 + 32);
  uncompressed[0] = 0x04;
  uncompressed.set(xBytes, 1);
  uncompressed.set(yBytes, 33);

  // Multicodec varint prefix for P-256 public key (0x1200)
  const multicodec = new Uint8Array(2 + uncompressed.length);
  multicodec[0] = 0x80;
  multicodec[1] = 0x24;
  multicodec.set(uncompressed, 2);

  // Multibase base58btc prefix: 'z'
  return "z" + base58Encode(multicodec);
}

// ============================================================
// DID MANAGER
// ============================================================

class DIDManager {
  constructor() {
    this.dids = new Map(); // Store created DIDs
  }

  /**
   * Create a new DID using the did:key method
   * 
   * @returns {Promise<{did: string, document: Object, keyPair: Object}>}
   */
  async createDID() {
    const keyPair = await generateKeyPair();
    const multibaseKey = jwkToMultibase(keyPair.publicKeyJwk);
    const did = `did:key:${multibaseKey}`;

    // Build DID Document (W3C DID Core compliant)
    const document = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
      ],
      id: did,
      verificationMethod: [
        {
          id: `${did}#key-1`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: {
            kty: keyPair.publicKeyJwk.kty,
            crv: keyPair.publicKeyJwk.crv,
            x: keyPair.publicKeyJwk.x,
            y: keyPair.publicKeyJwk.y,
          },
        },
      ],
      authentication: [`${did}#key-1`],
      assertionMethod: [`${did}#key-1`],
      capabilityDelegation: [`${did}#key-1`],
      created: new Date().toISOString(),
    };

    const result = {
      did,
      document,
      keyPair: {
        publicKeyJwk: keyPair.publicKeyJwk,
        privateKeyJwk: keyPair.privateKeyJwk,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
      },
    };

    this.dids.set(did, result);
    return result;
  }

  /**
   * Issue a Verifiable Credential (VC)
   * Used for beneficiary identity verification
   * 
   * @param {string} issuerDID - DID of the issuer (vault owner)
   * @param {string} subjectDID - DID of the subject (beneficiary)
   * @param {Object} claims - Claims about the subject
   * @returns {Promise<Object>} Signed Verifiable Credential
   */
  async issueVerifiableCredential(issuerDID, subjectDID, claims) {
    const issuer = this.dids.get(issuerDID);
    if (!issuer) throw new Error("Issuer DID not found");

    const credential = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
      ],
      type: ["VerifiableCredential", "DigitalLegacyBeneficiaryCredential"],
      issuer: issuerDID,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: subjectDID,
        ...claims,
      },
    };

    // Sign the credential
    const signature = await this._signCredential(credential, issuer.keyPair.privateKey);

    return {
      ...credential,
      proof: {
        type: "JsonWebSignature2020",
        created: new Date().toISOString(),
        verificationMethod: `${issuerDID}#key-1`,
        proofPurpose: "assertionMethod",
        jws: signature,
      },
    };
  }

  /**
   * Verify a Verifiable Credential's signature
   * 
   * @param {Object} credential - The VC to verify
   * @returns {Promise<{valid: boolean, errors: string[]}>}
   */
  async verifyCredential(credential) {
    const errors = [];

    // Check required fields
    if (!credential["@context"]) errors.push("Missing @context");
    if (!credential.type) errors.push("Missing type");
    if (!credential.issuer) errors.push("Missing issuer");
    if (!credential.credentialSubject) errors.push("Missing credentialSubject");
    if (!credential.proof) errors.push("Missing proof");

    if (errors.length > 0) return { valid: false, errors };

    // Check expiration
    if (credential.expirationDate && new Date(credential.expirationDate) < new Date()) {
      errors.push("Credential expired");
      return { valid: false, errors };
    }

    // Verify signature
    const issuer = this.dids.get(credential.issuer);
    if (!issuer) {
      errors.push("Cannot resolve issuer DID");
      return { valid: false, errors };
    }

    try {
      const { proof, ...credentialWithoutProof } = credential;
      const valid = await this._verifySignature(
        credentialWithoutProof,
        proof.jws,
        issuer.keyPair.publicKey
      );

      if (!valid) errors.push("Invalid signature");
      return { valid: errors.length === 0, errors };
    } catch (e) {
      errors.push(`Verification error: ${e.message}`);
      return { valid: false, errors };
    }
  }

  /**
   * Create a Verifiable Presentation (VP)
   * Used by beneficiary to present their credentials during claim
   * 
   * @param {string} holderDID - DID of the holder (beneficiary)
   * @param {Object[]} credentials - Array of VCs to include
   * @returns {Promise<Object>} Signed Verifiable Presentation
   */
  async createPresentation(holderDID, credentials) {
    const holder = this.dids.get(holderDID);
    if (!holder) throw new Error("Holder DID not found");

    const presentation = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiablePresentation"],
      holder: holderDID,
      verifiableCredential: credentials,
    };

    const signature = await this._signCredential(presentation, holder.keyPair.privateKey);

    return {
      ...presentation,
      proof: {
        type: "JsonWebSignature2020",
        created: new Date().toISOString(),
        verificationMethod: `${holderDID}#key-1`,
        proofPurpose: "authentication",
        jws: signature,
      },
    };
  }

  /**
   * Generate a hash of a DID for on-chain storage
   * Smart contract stores the hash, not the full DID
   */
  async didToOnChainHash(did) {
    const encoder = new TextEncoder();
    const data = encoder.encode(did);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return "0x" + Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // ─── PRIVATE HELPERS ───

  async _signCredential(data, privateKey) {
    const encoder = new TextEncoder();
    const payload = encoder.encode(JSON.stringify(data));

    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      payload
    );

    return arrayBufferToBase64Url(signature);
  }

  async _verifySignature(data, signatureB64, publicKey) {
    const encoder = new TextEncoder();
    const payload = encoder.encode(JSON.stringify(data));
    const signature = base64UrlToArrayBuffer(signatureB64);

    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      signature,
      payload
    );
  }
}

// ============================================================
// BASE58 ENCODING (for did:key multibase)
// ============================================================

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes) {
  const digits = [0];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let result = "";
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    result += BASE58_ALPHABET[0];
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToArrayBuffer(b64url) {
  return base64UrlToBytes(b64url).buffer;
}

// ============================================================
// EXPORTS
// ============================================================

export { DIDManager, generateKeyPair };
