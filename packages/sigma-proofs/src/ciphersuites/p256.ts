/**
 * P-256 (secp256r1) ciphersuite for sigma protocols.
 *
 * Implements Section 2.3.1 of draft-irtf-cfrg-sigma-protocols-01.
 */

import { p256, p256_hasher } from '@noble/curves/nist.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { pippenger } from '@noble/curves/abstract/curve.js';
import type { Group, GroupElement, Scalar } from '../group.js';

const Point = p256.Point;
const Fn = Point.Fn;

/** Group order as bigint */
const ORDER = Fn.ORDER;

/** Default domain separation tag for hash-to-curve */
import { asciiToBytes } from '../utils.js';

const DEFAULT_DST = asciiToBytes('sigma-proofs-P256-v1');

type P256Point = InstanceType<typeof Point>;

/**
 * Scalar wrapper for P-256.
 */
class P256Scalar implements Scalar {
  constructor(readonly value: bigint) {}

  add(other: Scalar): Scalar {
    if (!(other instanceof P256Scalar)) {
      throw new TypeError('Cannot mix scalars from different groups');
    }
    return new P256Scalar(Fn.add(this.value, other.value));
  }

  sub(other: Scalar): Scalar {
    if (!(other instanceof P256Scalar)) {
      throw new TypeError('Cannot mix scalars from different groups');
    }
    return new P256Scalar(Fn.sub(this.value, other.value));
  }

  mul(other: Scalar): Scalar {
    if (!(other instanceof P256Scalar)) {
      throw new TypeError('Cannot mix scalars from different groups');
    }
    return new P256Scalar(Fn.mul(this.value, other.value));
  }

  neg(): Scalar {
    return new P256Scalar(Fn.neg(this.value));
  }

  inv(): Scalar {
    if (this.value === 0n) {
      throw new Error('Cannot invert zero scalar');
    }
    return new P256Scalar(Fn.inv(this.value));
  }

  equals(other: Scalar): boolean {
    if (!(other instanceof P256Scalar)) {
      return false;
    }
    return Fn.eql(this.value, other.value);
  }

  isZero(): boolean {
    return this.value === 0n;
  }

  toBytes(): Uint8Array {
    // Field-Element-to-Octet-String per SEC1
    return numberToBytesBE(this.value, 32);
  }
}

/**
 * Group element wrapper for P-256.
 */
class P256Element implements GroupElement {
  constructor(readonly point: P256Point) {}

  add(other: GroupElement): GroupElement {
    if (!(other instanceof P256Element)) {
      throw new TypeError('Cannot mix elements from different groups');
    }
    return new P256Element(this.point.add(other.point));
  }

  negate(): GroupElement {
    return new P256Element(this.point.negate());
  }

  multiply(scalar: Scalar): GroupElement {
    if (!(scalar instanceof P256Scalar)) {
      throw new TypeError('Cannot mix scalar/element from different groups');
    }
    return new P256Element(this.point.multiply(scalar.value));
  }

  equals(other: GroupElement): boolean {
    if (!(other instanceof P256Element)) {
      return false;
    }
    return this.point.equals(other.point);
  }

  toBytes(): Uint8Array {
    // Compressed Elliptic-Curve-Point-to-Octet-String per SEC1 (33 bytes)
    return this.point.toBytes(true);
  }
}

/**
 * P-256 group implementation.
 */
export class P256Group implements Group {
  readonly name = 'P-256';
  readonly scalarSize = 32;
  readonly elementSize = 33; // Compressed
  readonly order = ORDER;

  identity(): GroupElement {
    return new P256Element(Point.ZERO);
  }

  generator(): GroupElement {
    return new P256Element(Point.BASE);
  }

  randomScalar(): Scalar {
    const bytes = p256.utils.randomSecretKey();
    const value = bytesToNumberBE(bytes);
    return new P256Scalar(Fn.create(value));
  }

  scalarFromBigint(n: bigint): Scalar {
    return new P256Scalar(Fn.create(n));
  }

  scalarFromBytes(bytes: Uint8Array): Scalar {
    if (bytes.length !== 32) {
      throw new Error(`Expected 32 bytes, got ${bytes.length}`);
    }
    const value = bytesToNumberBE(bytes);
    if (value >= ORDER) {
      throw new Error('Scalar out of range');
    }
    return new P256Scalar(value);
  }

  elementFromBytes(bytes: Uint8Array): GroupElement {
    if (bytes.length !== 33) {
      throw new Error(`Expected 33 bytes (compressed), got ${bytes.length}`);
    }
    return new P256Element(Point.fromBytes(bytes));
  }

  msm(scalars: Scalar[], elements: GroupElement[]): GroupElement {
    if (scalars.length !== elements.length) {
      throw new Error('Scalars and elements must have same length');
    }
    if (scalars.length === 0) {
      return this.identity();
    }

    // Validate all inputs belong to this group and extract internal representation
    const points: P256Point[] = [];
    const bigints: bigint[] = [];
    for (let i = 0; i < scalars.length; i++) {
      const s = scalars[i];
      const e = elements[i];
      if (!(s instanceof P256Scalar)) {
        throw new TypeError(`Scalar at index ${i} is not a P256Scalar`);
      }
      if (!(e instanceof P256Element)) {
        throw new TypeError(`Element at index ${i} is not a P256Element`);
      }
      points.push(e.point);
      bigints.push(s.value);
    }

    // Use Pippenger's algorithm for efficient MSM
    const result = pippenger(Point, points, bigints);
    return new P256Element(result);
  }

  hashToElement(data: Uint8Array, dst?: Uint8Array): GroupElement {
    const actualDst = dst ?? DEFAULT_DST;
    const point = p256_hasher.hashToCurve(data, { DST: actualDst });
    return new P256Element(point);
  }

  hashToScalar(data: Uint8Array, dst?: Uint8Array): Scalar {
    const actualDst = dst ?? DEFAULT_DST;
    const scalar = p256_hasher.hashToScalar(data, { DST: actualDst });
    return new P256Scalar(scalar);
  }
}

/** Default P-256 group instance */
export const p256Group = new P256Group();
export { p256Group as p256 };
