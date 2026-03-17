/**
 * Random Number Generator implementations for ACT.
 *
 * Provides both:
 * - WebCryptoPRNG: Production CSPRNG using Web Crypto API
 * - SeededPRNGForTestingOnly: Deterministic PRNG for testing (SHAKE128-based)
 */

import { shake128 } from '@noble/hashes/sha3.js';

/**
 * PRNG interface for deterministic randomness.
 *
 * Production implementations MUST use a CSPRNG (FIPS 186).
 * Test implementations may use SeededPRNGForTestingOnly for reproducibility.
 */
export interface PRNG {
  /** Generate n random bytes */
  randomBytes(n: number): Uint8Array;
}

/**
 * Production PRNG using Web Crypto API.
 *
 * Uses crypto.getRandomValues() which is available in:
 * - Browsers
 * - Node.js (via globalThis.crypto)
 * - Cloudflare Workers
 */
export class WebCryptoPRNG implements PRNG {
  randomBytes(n: number): Uint8Array {
    const bytes = new Uint8Array(n);
    crypto.getRandomValues(bytes);
    return bytes;
  }
}

/**
 * Domain separator for test DRNG (matches sigma-proofs TestDRNGForTestingOnly).
 */
const TEST_DRNG_IV = (() => {
  const label = new TextEncoder().encode('sigma-proofs/TestDRNG/SHAKE128');
  const result = new Uint8Array(64);
  result.set(label);
  return result;
})();

/**
 * Deterministic PRNG for testing, using continuous SHAKE128 XOF squeeze.
 *
 * Aligned with sigma-proofs TestDRNGForTestingOnly for interop:
 * - Uses same domain separator: "sigma-proofs/TestDRNG/SHAKE128" (padded to 64 bytes)
 * - Uses continuous squeeze with offset tracking (not counter mode)
 *
 * WARNING: Only use for testing! Not cryptographically secure for production.
 */
export class SeededPRNGForTestingOnly implements PRNG {
  private readonly hasher: ReturnType<typeof shake128.create>;
  private squeezeOffset = 0;

  constructor(seed: Uint8Array) {
    if (seed.length !== 32) {
      throw new Error('SeededPRNGForTestingOnly seed must be exactly 32 bytes');
    }
    // Initialize with domain separator padded to SHAKE128 rate (168 bytes)
    const initialBlock = new Uint8Array(168);
    initialBlock.set(TEST_DRNG_IV);
    this.hasher = shake128.create({});
    this.hasher.update(initialBlock);
    // Absorb seed
    this.hasher.update(seed);
  }

  randomBytes(n: number): Uint8Array {
    // Continuous squeeze: get bytes from squeezeOffset to squeezeOffset + n
    const end = this.squeezeOffset + n;
    const full = this.hasher.clone().xof(end);
    const result = full.subarray(this.squeezeOffset, end);
    this.squeezeOffset = end;
    return result;
  }
}

/**
 * Default PRNG for production use.
 */
export const defaultPRNG = new WebCryptoPRNG();

/**
 * Convert Uint8Array to hex string.
 * Workers-compatible (no Buffer dependency).
 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
