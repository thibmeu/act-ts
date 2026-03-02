/**
 * Deterministic RNG for test vector generation.
 *
 * Matches the TestDRNG from the sigma-protocols POC:
 * https://github.com/mmaker/draft-irtf-cfrg-sigma-protocols/blob/main/poc/test_drng.sage
 *
 * WARNING: This is FOR TESTING ONLY. Never use in production.
 */

import { Shake128Sponge } from './fiat-shamir/sponge.js';
import type { Group, Scalar } from './group.js';

const DOMAIN_SEPARATOR = (() => {
  const label = new TextEncoder().encode('sigma-proofs/TestDRNG/SHAKE128');
  const result = new Uint8Array(64);
  result.set(label);
  return result;
})();

/**
 * Deterministic RNG matching POC's TestDRNG.
 *
 * Uses SHAKE128 sponge with incremental squeezing.
 */
export class TestDRNGForTestingOnly {
  private readonly sponge: Shake128Sponge;
  private squeezeOffset = 0;
  private readonly group: Group;

  constructor(seed: Uint8Array, group: Group) {
    if (seed.length !== 32) {
      throw new Error('TestDRNG seed must be exactly 32 bytes');
    }
    this.sponge = new Shake128Sponge(DOMAIN_SEPARATOR);
    this.sponge.absorb(seed);
    this.group = group;
  }

  /**
   * Get random bytes (incremental squeezing).
   */
  getRandomBytes(length: number): Uint8Array {
    const end = this.squeezeOffset + length;
    const full = this.sponge.squeeze(end);
    const result = full.subarray(this.squeezeOffset, end);
    this.squeezeOffset = end;
    return result;
  }

  /**
   * Generate a random scalar matching POC's random_scalar().
   *
   * Uses wide reduction: generates (scalarSize + 16) bytes and reduces mod order.
   */
  randomScalar(): Scalar {
    const scalarSize = this.group.scalarSize;
    const wideBytes = this.getRandomBytes(scalarSize + 16);
    // Convert to bigint (big-endian as in POC's OS2IP)
    let n = 0n;
    for (const b of wideBytes) {
      n = (n << 8n) | BigInt(b);
    }
    // Reduce mod order
    const order = this.group.order;
    const reduced = n % order;
    return this.group.scalarFromBigint(reduced);
  }
}
