/**
 * Ristretto255 Group Implementation for ACT
 *
 * Uses @noble/curves ristretto255 (RFC 9496)
 * Provides Scalar and GroupElement abstractions per Section 2.2
 */

import {
  ristretto255 as noble_ristretto255,
  ristretto255_hasher,
  ed25519,
} from '@noble/curves/ed25519.js';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils.js';
import type { Scalar, GroupElement } from './types.js';

const Fn = noble_ristretto255.Point.Fn;
const Point = noble_ristretto255.Point;

// Group order (same as ed25519 scalar field order)
// q = 2^252 + 27742317777372353535851937790883648493
const ORDER = BigInt('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');

type RistrettoPoint = InstanceType<typeof Point>;

/**
 * Ristretto255 Scalar implementation
 */
export class Ristretto255Scalar implements Scalar {
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

/**
 * Ristretto255 Group Element implementation
 */
export class Ristretto255Element implements GroupElement {
  constructor(readonly point: RistrettoPoint) {}

  add(other: GroupElement): GroupElement {
    if (!(other instanceof Ristretto255Element)) {
      throw new TypeError('Cannot mix elements from different groups');
    }
    return new Ristretto255Element(this.point.add(other.point));
  }

  sub(other: GroupElement): GroupElement {
    if (!(other instanceof Ristretto255Element)) {
      throw new TypeError('Cannot mix elements from different groups');
    }
    return new Ristretto255Element(this.point.subtract(other.point));
  }

  multiply(scalar: Scalar): GroupElement {
    if (!(scalar instanceof Ristretto255Scalar)) {
      throw new TypeError('Cannot mix scalar/element from different groups');
    }
    // Handle zero scalar (noble-curves rejects 0 in multiply)
    if (scalar.value === 0n) {
      return new Ristretto255Element(Point.ZERO);
    }
    return new Ristretto255Element(this.point.multiply(scalar.value));
  }

  equals(other: GroupElement): boolean {
    if (!(other instanceof Ristretto255Element)) {
      return false;
    }
    return this.point.equals(other.point);
  }

  isIdentity(): boolean {
    return this.point.equals(Point.ZERO);
  }

  toBytes(): Uint8Array {
    return this.point.toBytes();
  }
}

/**
 * Group operations for ACT
 */
export const group = {
  /** Group order */
  ORDER,

  /** Scalar byte size */
  SCALAR_SIZE: 32,

  /** Element byte size */
  ELEMENT_SIZE: 32,

  /** Identity element */
  identity(): GroupElement {
    return new Ristretto255Element(Point.ZERO);
  },

  /** Generator G */
  generator(): GroupElement {
    return new Ristretto255Element(Point.BASE);
  },

  /** Random scalar from secure source */
  randomScalar(): Scalar {
    const bytes = ed25519.utils.randomSecretKey();
    const value = Fn.create(bytesToNumberLE(bytes));
    return new Ristretto255Scalar(value);
  },

  /** Scalar from bigint (reduced mod order) */
  scalarFromBigint(n: bigint): Scalar {
    return new Ristretto255Scalar(Fn.create(n));
  },

  /** Scalar from bytes (little-endian, must be < ORDER) */
  scalarFromBytes(bytes: Uint8Array): Scalar {
    if (bytes.length !== 32) {
      throw new Error(`Expected 32 bytes, got ${bytes.length}`);
    }
    const value = bytesToNumberLE(bytes);
    if (value >= ORDER) {
      throw new Error('Scalar out of range');
    }
    return new Ristretto255Scalar(value);
  },

  /** Element from compressed bytes */
  elementFromBytes(bytes: Uint8Array): GroupElement {
    if (bytes.length !== 32) {
      throw new Error(`Expected 32 bytes, got ${bytes.length}`);
    }
    return new Ristretto255Element(Point.fromBytes(bytes));
  },

  /** Zero scalar */
  zero(): Scalar {
    return new Ristretto255Scalar(0n);
  },

  /** One scalar */
  one(): Scalar {
    return new Ristretto255Scalar(1n);
  },

  /**
   * Multi-scalar multiplication: sum(scalars[i] * elements[i])
   *
   * Handles zero scalars gracefully (noble-curves rejects 0 in multiply)
   */
  msm(scalars: readonly Scalar[], elements: readonly GroupElement[]): GroupElement {
    if (scalars.length !== elements.length) {
      throw new Error('Scalars and elements must have same length');
    }
    if (scalars.length === 0) {
      return group.identity();
    }

    let result = group.identity() as Ristretto255Element;
    for (let i = 0; i < scalars.length; i++) {
      const s = scalars[i] as Ristretto255Scalar;
      const e = elements[i] as Ristretto255Element;
      // Skip zero scalars (0 * P = identity)
      if (s.value !== 0n) {
        result = new Ristretto255Element(result.point.add(e.point.multiply(s.value)));
      }
    }
    return result;
  },

  /**
   * Hash to group element using ristretto255_hash
   * Used for OneWayMap in parameter generation
   */
  hashToElement(uniformBytes: Uint8Array): GroupElement {
    // ristretto255 OneWayMap requires 64 uniform bytes (RFC 9496 Section 4.3.4)
    if (uniformBytes.length !== 64) {
      throw new Error(`OneWayMap requires 64 bytes, got ${uniformBytes.length}`);
    }
    const point = ristretto255_hasher.hashToCurve(uniformBytes, {
      DST: new Uint8Array(0), // No additional DST, bytes are already uniform
    });
    return new Ristretto255Element(point);
  },

  /**
   * Hash to scalar
   */
  hashToScalar(data: Uint8Array, dst: Uint8Array): Scalar {
    const scalar = ristretto255_hasher.hashToScalar(data, { DST: dst });
    return new Ristretto255Scalar(scalar);
  },
};
