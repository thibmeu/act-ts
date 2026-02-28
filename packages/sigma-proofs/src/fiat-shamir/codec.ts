/**
 * Codec interface for Fiat-Shamir transformation.
 *
 * Implements Section 3, 6, and 8 of draft-irtf-cfrg-fiat-shamir-01.
 */

import type { DuplexSponge } from './sponge.js';
import type { Group, GroupElement, Scalar } from '../group.js';

/**
 * Codec interface (Section 3 of draft-irtf-cfrg-fiat-shamir-01).
 *
 * Maps prover messages to the hash domain and hash outputs to verifier challenges.
 */
export interface Codec {
  /** Absorb commitment elements into the hash state */
  absorbElements(elements: readonly GroupElement[]): void;
  /** Absorb scalars into the hash state */
  absorbScalars(scalars: readonly Scalar[]): void;
  /** Squeeze a challenge scalar from the hash state */
  squeezeChallenge(): Scalar;
  /** Clone the codec state */
  clone(): Codec;
}

/**
 * Byte-oriented codec for Schnorr proofs (Section 6 of draft-irtf-cfrg-fiat-shamir-01).
 *
 * Works with any prime-order elliptic curve group.
 */
export class ByteCodec implements Codec {
  constructor(
    private readonly group: Group,
    private readonly sponge: DuplexSponge
  ) {}

  /**
   * Absorb group elements into the hash state (Section 8.1.3).
   */
  absorbElements(elements: readonly GroupElement[]): void {
    for (const element of elements) {
      this.sponge.absorb(element.toBytes());
    }
  }

  /**
   * Absorb scalars into the hash state (Section 8.1.2).
   */
  absorbScalars(scalars: readonly Scalar[]): void {
    for (const scalar of scalars) {
      this.sponge.absorb(scalar.toBytes());
    }
  }

  /**
   * Squeeze a challenge scalar from the hash state (Section 8.1.4).
   *
   * Per Section 6 and Appendix C of https://eprint.iacr.org/2025/536.pdf:
   * We squeeze (scalar_byte_length + 16) bytes, interpret as big-endian
   * integer, and reduce mod group order for uniform distribution.
   */
  squeezeChallenge(): Scalar {
    // Need extra 128 bits (16 bytes) for uniform distribution after mod reduction
    const uniformBytes = this.sponge.squeeze(this.group.scalarSize + 16);

    // Convert to big-endian integer (OS2IP per RFC 8017)
    let value = 0n;
    for (const byte of uniformBytes) {
      value = (value << 8n) | BigInt(byte);
    }

    // Reduce mod order for uniform scalar
    const reduced = value % this.group.order;
    return this.group.scalarFromBigint(reduced);
  }

  /**
   * Clone the codec state.
   */
  clone(): ByteCodec {
    return new ByteCodec(this.group, this.sponge.clone());
  }
}
