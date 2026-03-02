/**
 * BLS12-381 G1 ciphersuite for sigma protocols.
 *
 * Uses @noble/curves implementation per draft-irtf-cfrg-sigma-protocols.
 * BLS12-381 G1 points are 48 bytes compressed, scalars are 32 bytes big-endian.
 */

import { bls12_381 } from '@noble/curves/bls12-381.js';
import { bytesToNumberBE, numberToBytesBE, bytesToHex } from '@noble/curves/utils.js';
import type { Group, GroupElement, Scalar } from '../group.js';
import { asciiToBytes } from '../utils.js';

const G1 = bls12_381.G1;
const G1Point = G1.Point;
const Fr = bls12_381.fields.Fr;
const ORDER = Fr.ORDER;

/** Default domain separation tag for hash-to-curve */
const DEFAULT_DST = asciiToBytes('sigma-proofs-bls12381-g1-v1');

type G1PointType = InstanceType<typeof G1Point>;

/**
 * Scalar wrapper for BLS12-381 Fr field.
 * Scalars are 32 bytes big-endian per spec.
 */
class BLS12381Scalar implements Scalar {
  constructor(readonly value: bigint) {}

  add(other: Scalar): Scalar {
    if (!(other instanceof BLS12381Scalar)) {
      throw new TypeError('Cannot mix scalars from different groups');
    }
    return new BLS12381Scalar(Fr.add(this.value, other.value));
  }

  sub(other: Scalar): Scalar {
    if (!(other instanceof BLS12381Scalar)) {
      throw new TypeError('Cannot mix scalars from different groups');
    }
    return new BLS12381Scalar(Fr.sub(this.value, other.value));
  }

  mul(other: Scalar): Scalar {
    if (!(other instanceof BLS12381Scalar)) {
      throw new TypeError('Cannot mix scalars from different groups');
    }
    return new BLS12381Scalar(Fr.mul(this.value, other.value));
  }

  neg(): Scalar {
    return new BLS12381Scalar(Fr.neg(this.value));
  }

  inv(): Scalar {
    if (this.value === 0n) {
      throw new Error('Cannot invert zero scalar');
    }
    return new BLS12381Scalar(Fr.inv(this.value));
  }

  equals(other: Scalar): boolean {
    if (!(other instanceof BLS12381Scalar)) {
      return false;
    }
    return Fr.eql(this.value, other.value);
  }

  isZero(): boolean {
    return this.value === 0n;
  }

  toBytes(): Uint8Array {
    // BLS12-381 scalars are 32 bytes big-endian
    return numberToBytesBE(this.value, 32);
  }
}

/**
 * Group element wrapper for BLS12-381 G1.
 * G1 points are 48 bytes compressed.
 */
class BLS12381Element implements GroupElement {
  constructor(readonly point: G1PointType) {}

  add(other: GroupElement): GroupElement {
    if (!(other instanceof BLS12381Element)) {
      throw new TypeError('Cannot mix elements from different groups');
    }
    return new BLS12381Element(this.point.add(other.point));
  }

  negate(): GroupElement {
    return new BLS12381Element(this.point.negate());
  }

  multiply(scalar: Scalar): GroupElement {
    if (!(scalar instanceof BLS12381Scalar)) {
      throw new TypeError('Cannot mix scalar/element from different groups');
    }
    return new BLS12381Element(this.point.multiply(scalar.value));
  }

  equals(other: GroupElement): boolean {
    if (!(other instanceof BLS12381Element)) {
      return false;
    }
    return this.point.equals(other.point);
  }

  toBytes(): Uint8Array {
    // BLS12-381 G1 points are 48 bytes compressed
    return this.point.toBytes(true);
  }
}

/**
 * BLS12-381 G1 group implementation.
 *
 * Per draft-irtf-cfrg-sigma-protocols:
 * - Scalars: 32 bytes big-endian
 * - Elements: 48 bytes compressed G1 points
 */
export class BLS12381Group implements Group {
  readonly name = 'BLS12-381-G1';
  readonly scalarSize = 32;
  readonly elementSize = 48;
  readonly order = ORDER;

  identity(): GroupElement {
    return new BLS12381Element(G1Point.ZERO);
  }

  generator(): GroupElement {
    return new BLS12381Element(G1Point.BASE);
  }

  randomScalar(): Scalar {
    // Generate random bytes and reduce mod order
    const bytes = new Uint8Array(48); // Extra bytes for uniform distribution
    crypto.getRandomValues(bytes);
    const value = Fr.create(bytesToNumberBE(bytes));
    return new BLS12381Scalar(value);
  }

  scalarFromBigint(n: bigint): Scalar {
    return new BLS12381Scalar(Fr.create(n));
  }

  scalarFromBytes(bytes: Uint8Array): Scalar {
    if (bytes.length !== 32) {
      throw new Error(`Expected 32 bytes, got ${bytes.length}`);
    }
    const value = bytesToNumberBE(bytes);
    if (value >= ORDER) {
      throw new Error('Scalar out of range');
    }
    return new BLS12381Scalar(value);
  }

  elementFromBytes(bytes: Uint8Array): GroupElement {
    if (bytes.length !== 48) {
      throw new Error(`Expected 48 bytes, got ${bytes.length}`);
    }
    // fromHex expects hex string
    return new BLS12381Element(G1Point.fromHex(bytesToHex(bytes)));
  }

  msm(scalars: Scalar[], elements: GroupElement[]): GroupElement {
    if (scalars.length !== elements.length) {
      throw new Error('Scalars and elements must have same length');
    }
    if (scalars.length === 0) {
      return this.identity();
    }

    // Validate all inputs belong to this group and compute MSM manually
    // BLS12-381 in noble-curves v2 doesn't expose msm directly on Point
    let result = G1Point.ZERO;
    for (let i = 0; i < scalars.length; i++) {
      const s = scalars[i];
      const e = elements[i];
      if (!(s instanceof BLS12381Scalar)) {
        throw new TypeError(`Scalar at index ${i} is not a BLS12381Scalar`);
      }
      if (!(e instanceof BLS12381Element)) {
        throw new TypeError(`Element at index ${i} is not a BLS12381Element`);
      }
      result = result.add(e.point.multiply(s.value));
    }
    return new BLS12381Element(result);
  }

  hashToElement(data: Uint8Array, dst?: Uint8Array): GroupElement {
    const actualDst = dst ?? DEFAULT_DST;
    const point = G1.hashToCurve(data, { DST: actualDst });
    return new BLS12381Element(point);
  }

  hashToScalar(data: Uint8Array, dst?: Uint8Array): Scalar {
    const actualDst = dst ?? DEFAULT_DST;
    // Use G1.hashToScalar which returns a bigint
    const scalar = G1.hashToScalar(data, { DST: actualDst });
    return new BLS12381Scalar(Fr.create(scalar));
  }
}

/** Default BLS12-381 G1 group instance */
export const bls12_381_g1 = new BLS12381Group();
