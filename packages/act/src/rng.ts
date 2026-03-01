/**
 * Random Number Generator implementations for ACT.
 *
 * Provides both:
 * - WebCryptoPRNG: Production CSPRNG using Web Crypto API
 * - SeededPRNG: Deterministic PRNG for testing (SHAKE128-based)
 */

import { shake128 } from '@noble/hashes/sha3';
import type { PRNG } from './types-vnext.js';

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
 * Deterministic PRNG for testing, using SHAKE128.
 *
 * Matches the spec's SeededPRNG (Appendix B):
 *   state = SHAKE128("")
 *   state.absorb(seed)
 *   randomBytes(n) = state.squeeze(n)
 *
 * WARNING: Only use for testing! Not cryptographically secure for production.
 */
export class SeededPRNG implements PRNG {
  private counter: number = 0;
  private readonly seed: Uint8Array;

  constructor(seed: Uint8Array) {
    this.seed = seed;
  }

  randomBytes(n: number): Uint8Array {
    // SHAKE128 is an XOF, so we can squeeze arbitrary amounts
    // We use counter to ensure each call produces unique output
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, this.counter++, true);

    const input = new Uint8Array(this.seed.length + 4);
    input.set(this.seed);
    input.set(counterBytes, this.seed.length);

    return shake128(input, { dkLen: n });
  }
}

/**
 * Default PRNG for production use.
 */
export const defaultPRNG = new WebCryptoPRNG();
