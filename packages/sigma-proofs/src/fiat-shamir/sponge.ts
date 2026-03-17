/**
 * Duplex sponge interfaces for Fiat-Shamir transformation.
 *
 * Implements Section 7 of draft-irtf-cfrg-fiat-shamir-01.
 */

import { shake128 } from '@noble/hashes/sha3.js';

/**
 * DuplexSponge interface (Section 2 of draft-irtf-cfrg-fiat-shamir-01).
 *
 * Provides absorb/squeeze operations for the Fiat-Shamir transformation.
 */
export interface DuplexSponge {
  /** Absorb bytes into the sponge state */
  absorb(data: Uint8Array): void;
  /** Squeeze bytes from the sponge state */
  squeeze(length: number): Uint8Array;
  /** Clone the sponge state */
  clone(): DuplexSponge;
}

/**
 * SHAKE128 duplex sponge (Section 7.1 of draft-irtf-cfrg-fiat-shamir-01).
 *
 * Uses SHAKE128 XOF with 128-bit security. The initialization vector
 * is padded to the SHAKE128 rate (168 bytes) with zeros.
 */
export class Shake128Sponge implements DuplexSponge {
  // SHAKE128 rate = 168 bytes (1344 bits)
  private static readonly RATE = 168;

  private state: ReturnType<typeof shake128.create>;

  /**
   * Create a new SHAKE128 sponge.
   *
   * @param iv - Initialization vector (typically 64 bytes per Section 7.1.1)
   */
  constructor(iv: Uint8Array) {
    // Section 7.1.1: Pad IV to rate bytes with zeros
    const initialBlock = new Uint8Array(Shake128Sponge.RATE);
    initialBlock.set(iv.subarray(0, Math.min(iv.length, Shake128Sponge.RATE)));
    // Remaining bytes are already 0

    this.state = shake128.create({});
    this.state.update(initialBlock);
  }

  /**
   * Clone constructor for internal use.
   */
  private static fromState(state: ReturnType<typeof shake128.create>): Shake128Sponge {
    const sponge = Object.create(Shake128Sponge.prototype) as Shake128Sponge;
    sponge.state = state;
    return sponge;
  }

  /**
   * Absorb data into the sponge (Section 7.1.2).
   */
  absorb(data: Uint8Array): void {
    this.state.update(data);
  }

  /**
   * Squeeze bytes from the sponge (Section 7.1.3).
   *
   * Note: Per the spec, we clone before squeezing to allow continued use.
   */
  squeeze(length: number): Uint8Array {
    // Clone before digest to preserve state for further operations
    return this.state.clone().xof(length);
  }

  /**
   * Clone the sponge state.
   */
  clone(): Shake128Sponge {
    return Shake128Sponge.fromState(this.state.clone());
  }
}
