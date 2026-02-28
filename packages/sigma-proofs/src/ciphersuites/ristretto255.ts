/**
 * Ristretto255 ciphersuite for sigma protocols.
 *
 * Uses @noble/curves implementation of RFC 9496.
 */

import {
  ristretto255 as noble_ristretto255,
  ristretto255_hasher,
  ed25519,
} from '@noble/curves/ed25519.js';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils.js';
import type { Group, GroupElement, Scalar } from '../group.js';

const Fn = noble_ristretto255.Point.Fn;
const Point = noble_ristretto255.Point;
const ORDER = Fn.ORDER;

/** Default domain separation tag for hash-to-curve */
import { asciiToBytes } from '../utils.js';

const DEFAULT_DST = asciiToBytes('sigma-proofs-ristretto255-v1');

/**
 * Scalar wrapper for ristretto255.
 */
class Ristretto255Scalar implements Scalar {
  constructor(readonly value: bigint) {}

  add(other: Scalar): Scalar {
    if (!(other instanceof Ristretto255Scalar)) {
      throw new TypeError('Cannot mix scalars from different groups');
    }
    return new Ristretto255Scalar(Fn.add(this.value, other.value));
  }

  sub(other: Scalar): Scalar {
    if (!(other instanceof Ristretto255Scalar)) {
      throw new TypeError('Cannot mix scalars from different groups');
    }
    return new Ristretto255Scalar(Fn.sub(this.value, other.value));
  }

  mul(other: Scalar): Scalar {
    if (!(other instanceof Ristretto255Scalar)) {
      throw new TypeError('Cannot mix scalars from different groups');
    }
    return new Ristretto255Scalar(Fn.mul(this.value, other.value));
  }

  neg(): Scalar {
    return new Ristretto255Scalar(Fn.neg(this.value));
  }

  inv(): Scalar {
    if (this.value === 0n) {
      throw new Error('Cannot invert zero scalar');
    }
    return new Ristretto255Scalar(Fn.inv(this.value));
  }

  equals(other: Scalar): boolean {
    if (!(other instanceof Ristretto255Scalar)) {
      return false;
    }
    return Fn.eql(this.value, other.value);
  }

  isZero(): boolean {
    return this.value === 0n;
  }

  toBytes(): Uint8Array {
    return numberToBytesLE(this.value, 32);
  }
}

type RistrettoPoint = InstanceType<typeof Point>;

/**
 * Group element wrapper for ristretto255.
 */
class Ristretto255Element implements GroupElement {
  constructor(readonly point: RistrettoPoint) {}

  add(other: GroupElement): GroupElement {
    if (!(other instanceof Ristretto255Element)) {
      throw new TypeError('Cannot mix elements from different groups');
    }
    return new Ristretto255Element(this.point.add(other.point));
  }

  multiply(scalar: Scalar): GroupElement {
    if (!(scalar instanceof Ristretto255Scalar)) {
      throw new TypeError('Cannot mix scalar/element from different groups');
    }
    return new Ristretto255Element(this.point.multiply(scalar.value));
  }

  equals(other: GroupElement): boolean {
    if (!(other instanceof Ristretto255Element)) {
      return false;
    }
    return this.point.equals(other.point);
  }

  toBytes(): Uint8Array {
    return this.point.toBytes();
  }
}

/**
 * Ristretto255 group implementation.
 */
export class Ristretto255Group implements Group {
  readonly name = 'ristretto255';
  readonly scalarSize = 32;
  readonly elementSize = 32;
  readonly order = ORDER;

  identity(): GroupElement {
    return new Ristretto255Element(Point.ZERO);
  }

  generator(): GroupElement {
    return new Ristretto255Element(Point.BASE);
  }

  randomScalar(): Scalar {
    // Use ed25519's randomSecretKey which gives uniform scalar
    const bytes = ed25519.utils.randomSecretKey();
    const value = Fn.create(bytesToNumberLE(bytes));
    return new Ristretto255Scalar(value);
  }

  scalarFromBigint(n: bigint): Scalar {
    return new Ristretto255Scalar(Fn.create(n));
  }

  scalarFromBytes(bytes: Uint8Array): Scalar {
    if (bytes.length !== 32) {
      throw new Error(`Expected 32 bytes, got ${bytes.length}`);
    }
    const value = bytesToNumberLE(bytes);
    if (value >= ORDER) {
      throw new Error('Scalar out of range');
    }
    return new Ristretto255Scalar(value);
  }

  elementFromBytes(bytes: Uint8Array): GroupElement {
    if (bytes.length !== 32) {
      throw new Error(`Expected 32 bytes, got ${bytes.length}`);
    }
    return new Ristretto255Element(Point.fromBytes(bytes));
  }

  msm(scalars: Scalar[], elements: GroupElement[]): GroupElement {
    if (scalars.length !== elements.length) {
      throw new Error('Scalars and elements must have same length');
    }
    if (scalars.length === 0) {
      return this.identity();
    }

    // Validate all inputs belong to this group before processing
    for (let i = 0; i < scalars.length; i++) {
      if (!(scalars[i] instanceof Ristretto255Scalar)) {
        throw new TypeError(`Scalar at index ${i} is not a Ristretto255Scalar`);
      }
      if (!(elements[i] instanceof Ristretto255Element)) {
        throw new TypeError(`Element at index ${i} is not a Ristretto255Element`);
      }
    }

    // Now safe to access internal representation
    let acc = Point.ZERO;
    for (let i = 0; i < scalars.length; i++) {
      const s = scalars[i] as Ristretto255Scalar;
      const e = elements[i] as Ristretto255Element;
      acc = acc.add(e.point.multiply(s.value));
    }
    return new Ristretto255Element(acc);
  }

  hashToElement(data: Uint8Array, dst?: Uint8Array): GroupElement {
    const actualDst = dst ?? DEFAULT_DST;
    const point = ristretto255_hasher.hashToCurve(data, { DST: actualDst });
    return new Ristretto255Element(point);
  }

  hashToScalar(data: Uint8Array, dst?: Uint8Array): Scalar {
    const actualDst = dst ?? DEFAULT_DST;
    const scalar = ristretto255_hasher.hashToScalar(data, { DST: actualDst });
    return new Ristretto255Scalar(scalar);
  }
}

/** Default ristretto255 group instance */
export const ristretto255 = new Ristretto255Group();
