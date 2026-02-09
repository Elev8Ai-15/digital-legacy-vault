/**
 * shamir.js - Shamir's Secret Sharing Implementation
 * 
 * Digital Legacy Vault - Client-Side Credential Splitting
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * This runs ENTIRELY on the client device. No secrets ever leave the device
 * in unencrypted form. The platform server never sees the original credentials.
 * 
 * Based on Adi Shamir's 1979 algorithm using polynomial interpolation
 * over a finite field (GF(2^8) for byte-level operations).
 * 
 * Usage:
 *   const shares = ShamirSSS.split("my_password_123", 5, 3);
 *   // shares = [ {x:1, y:[...]}, {x:2, y:[...]}, ... ] (5 shares)
 *   
 *   const reconstructed = ShamirSSS.reconstruct([shares[0], shares[2], shares[4]]);
 *   // reconstructed = "my_password_123" (any 3 of 5 reconstructs)
 */

// ============================================================
// GF(2^8) Finite Field Arithmetic
// ============================================================
// Using the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
// Same field used by AES - well-tested and secure

const GF256 = {
  // Precomputed lookup tables for speed
  EXP: new Uint8Array(512),
  LOG: new Uint8Array(256),

  init() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      this.EXP[i] = x;
      this.LOG[x] = i;
      x = x ^ (x << 1); // multiply by generator (3)
      if (x >= 256) {
        x ^= 0x11b; // reduce by irreducible polynomial
      }
    }
    // Fill extended table for modular arithmetic convenience
    for (let i = 255; i < 512; i++) {
      this.EXP[i] = this.EXP[i - 255];
    }
    this.LOG[0] = 0; // Convention: log(0) = 0 (never used in division)
  },

  add(a, b) {
    return a ^ b; // XOR in GF(2^8)
  },

  sub(a, b) {
    return a ^ b; // Same as add in GF(2^8)
  },

  mul(a, b) {
    if (a === 0 || b === 0) return 0;
    return this.EXP[this.LOG[a] + this.LOG[b]];
  },

  div(a, b) {
    if (b === 0) throw new Error("Division by zero in GF(2^8)");
    if (a === 0) return 0;
    return this.EXP[(this.LOG[a] + 255 - this.LOG[b]) % 255];
  },

  inv(a) {
    if (a === 0) throw new Error("Inverse of zero in GF(2^8)");
    return this.EXP[255 - this.LOG[a]];
  },
};

// Initialize lookup tables
GF256.init();

// ============================================================
// CRYPTOGRAPHIC RANDOM
// ============================================================

function secureRandomBytes(count) {
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const bytes = new Uint8Array(count);
    crypto.getRandomValues(bytes);
    return bytes;
  }
  throw new Error("No secure random source available");
}

function secureRandomByte() {
  return secureRandomBytes(1)[0];
}

// Ensure non-zero random byte (required for polynomial coefficients)
function secureRandomNonZeroByte() {
  let b;
  do {
    b = secureRandomByte();
  } while (b === 0);
  return b;
}

// ============================================================
// POLYNOMIAL OPERATIONS
// ============================================================

/**
 * Evaluate polynomial at point x in GF(2^8)
 * polynomial = [a0, a1, a2, ...] where f(x) = a0 + a1*x + a2*x^2 + ...
 * a0 is the secret
 */
function evaluatePolynomial(coefficients, x) {
  if (x === 0) throw new Error("Cannot evaluate at x=0 (that's the secret)");

  let result = 0;
  // Horner's method for efficient evaluation
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = GF256.add(GF256.mul(result, x), coefficients[i]);
  }
  return result;
}

/**
 * Lagrange interpolation to find f(0) = secret
 * Given k points (x_i, y_i), reconstructs the polynomial and evaluates at x=0
 */
function lagrangeInterpolateAt0(points) {
  const k = points.length;
  let secret = 0;

  for (let i = 0; i < k; i++) {
    let numerator = 1;
    let denominator = 1;

    for (let j = 0; j < k; j++) {
      if (i === j) continue;

      // We're evaluating at x=0, so numerator term is (0 - x_j) = x_j in GF(2^8)
      numerator = GF256.mul(numerator, points[j].x);
      // Denominator term is (x_i - x_j)
      denominator = GF256.mul(denominator, GF256.sub(points[i].x, points[j].x));
    }

    // Lagrange basis polynomial value at x=0: L_i(0) = numerator/denominator
    const basis = GF256.div(numerator, denominator);
    // Add y_i * L_i(0) to result
    secret = GF256.add(secret, GF256.mul(points[i].y, basis));
  }

  return secret;
}

// ============================================================
// SHAMIR'S SECRET SHARING
// ============================================================

const ShamirSSS = {
  /**
   * Split a secret string into n shares, requiring k to reconstruct
   *
   * @param {string} secret - The secret to split (credential, password, etc.)
   * @param {number} n - Total number of shares to generate (2-255)
   * @param {number} k - Minimum shares needed to reconstruct (2-n)
   * @returns {Array<{x: number, y: Uint8Array}>} - Array of n shares
   */
  split(secret, n, k) {
    // Validation
    if (!secret || typeof secret !== "string") {
      throw new Error("Secret must be a non-empty string");
    }
    if (n < 2 || n > 255) {
      throw new Error("Total shares (n) must be between 2 and 255");
    }
    if (k < 2 || k > n) {
      throw new Error("Threshold (k) must be between 2 and n");
    }

    // Convert secret to bytes
    const encoder = new TextEncoder();
    const secretBytes = encoder.encode(secret);

    // Generate shares for each byte of the secret
    const shares = [];
    for (let i = 0; i < n; i++) {
      shares.push({
        x: i + 1, // x values are 1 through n (never 0, that's the secret)
        y: new Uint8Array(secretBytes.length),
      });
    }

    // For each byte of the secret, create a random polynomial and evaluate
    for (let byteIdx = 0; byteIdx < secretBytes.length; byteIdx++) {
      // Create polynomial: f(x) = secret_byte + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
      const coefficients = new Uint8Array(k);
      coefficients[0] = secretBytes[byteIdx]; // constant term = secret byte

      // Random coefficients for degree 1 through k-1
      for (let i = 1; i < k; i++) {
        coefficients[i] = secureRandomNonZeroByte();
      }

      // Evaluate polynomial at each share's x value
      for (let shareIdx = 0; shareIdx < n; shareIdx++) {
        shares[shareIdx].y[byteIdx] = evaluatePolynomial(
          coefficients,
          shares[shareIdx].x
        );
      }
    }

    // Zero out the coefficient array (security hygiene)
    // In production, use a secure memory wipe
    for (let i = 0; i < secretBytes.length; i++) {
      secretBytes[i] = 0;
    }

    return shares;
  },

  /**
   * Reconstruct a secret from k or more shares
   *
   * @param {Array<{x: number, y: Uint8Array}>} shares - At least k shares
   * @returns {string} - The reconstructed secret
   */
  reconstruct(shares) {
    if (!shares || shares.length < 2) {
      throw new Error("Need at least 2 shares to reconstruct");
    }

    // Validate all shares have same length
    const secretLength = shares[0].y.length;
    for (const share of shares) {
      if (share.y.length !== secretLength) {
        throw new Error("Share length mismatch - shares may be from different secrets");
      }
    }

    // Check for duplicate x values
    const xValues = new Set(shares.map((s) => s.x));
    if (xValues.size !== shares.length) {
      throw new Error("Duplicate share detected");
    }

    // Reconstruct each byte using Lagrange interpolation
    const secretBytes = new Uint8Array(secretLength);
    for (let byteIdx = 0; byteIdx < secretLength; byteIdx++) {
      const points = shares.map((share) => ({
        x: share.x,
        y: share.y[byteIdx],
      }));
      secretBytes[byteIdx] = lagrangeInterpolateAt0(points);
    }

    // Decode back to string
    const decoder = new TextDecoder();
    return decoder.decode(secretBytes);
  },

  /**
   * Serialize a share to a base64 string for storage/transport
   */
  serializeShare(share) {
    const header = new Uint8Array([share.x, ...share.y]);
    return btoa(String.fromCharCode(...header));
  },

  /**
   * Deserialize a share from base64
   */
  deserializeShare(encoded) {
    const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    return {
      x: bytes[0],
      y: bytes.slice(1),
    };
  },

  /**
   * Verify that a set of shares can reconstruct (without revealing the secret)
   * Useful for testing share distribution before going live
   */
  verifyShares(shares, k) {
    if (shares.length < k) return false;

    try {
      // Take first k shares and reconstruct
      const subset1 = shares.slice(0, k);
      const result1 = this.reconstruct(subset1);

      // Take a different subset and verify same result
      if (shares.length > k) {
        const subset2 = [...shares.slice(0, k - 1), shares[shares.length - 1]];
        const result2 = this.reconstruct(subset2);
        return result1 === result2;
      }

      return result1.length > 0;
    } catch {
      return false;
    }
  },
};

export { ShamirSSS, GF256 };
