/**
 * Ciphersuites of draft-irtf-cfrg-sigma-protocols-03, Section 8.
 */

import type { WeierstrassPoint, WeierstrassPointCons } from '@noble/curves/abstract/weierstrass.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { p256 } from '@noble/curves/nist.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import type { Job } from './mul.ts';
import { mulManyWebCrypto } from './webcrypto.ts';

export type Point = WeierstrassPoint<bigint>;

export class SigmaError extends Error {
  override name = 'SigmaError';
}

/** A prime-order group with its codecs (Section 8). */
export interface Ciphersuite {
  /** Ciphersuite identifier, carried verbatim in every tag (Section 5.1). */
  readonly id: string;
  readonly Point: WeierstrassPointCons<bigint>;
  /** Group order p. */
  readonly order: bigint;
  /** Element encoding length. */
  readonly Ne: number;
  /** Scalar encoding length. */
  readonly Ns: number;
  /** Native batch multiplication; resolves to undefined where unavailable. */
  readonly mulMany?: (jobs: readonly Job[]) => Promise<Point[] | undefined>;
}

function suite(
  id: string,
  Point: WeierstrassPointCons<bigint>,
  Ne: number,
  mulMany?: Ciphersuite['mulMany']
): Ciphersuite {
  return { id, Point, order: Point.Fn.ORDER, Ne, Ns: 32, ...(mulMany && { mulMany }) };
}

/**
 * Marks a long-lived point, such as a generator of an application, for
 * noble's fixed-base table (window 8), built on its first noble
 * multiplication; returns it. The synchronous API then multiplies it several
 * times faster. The asynchronous API never needs the table.
 */
export function registerFixedBase(point: Point): Point {
  return point.precompute(8);
}

/** sigma-proofs_Shake128_P256 (Section 8.1). */
export const P256: Ciphersuite = suite(
  'sigma-proofs_Shake128_P256',
  p256.Point,
  33,
  mulManyWebCrypto
);

/** sigma-proofs_Shake128_BLS12381 (Section 8.2). */
export const BLS12381: Ciphersuite = suite(
  'sigma-proofs_Shake128_BLS12381',
  bls12_381.G1.Point,
  48
);

/** Scalar.serialize: I2OSP(s, Ns). */
export function serializeScalar(suite: Ciphersuite, s: bigint): Uint8Array {
  return numberToBytesBE(s, suite.Ns);
}

/** Scalar.deserialize: OS2IP, rejecting values outside [0, p). */
export function deserializeScalar(suite: Ciphersuite, bytes: Uint8Array): bigint {
  if (bytes.length !== suite.Ns) throw new SigmaError('invalid scalar length');
  const s = bytesToNumberBE(bytes);
  if (s >= suite.order) throw new SigmaError('non-canonical scalar');
  return s;
}

/** Group.serialize of one element; the identity has no encoding. */
export function serializeElement(_suite: Ciphersuite, point: Point): Uint8Array {
  if (point.is0()) throw new SigmaError('cannot serialize the identity');
  return point.toBytes(true);
}

/**
 * Group.deserialize of one element: compressed form only, validated
 * (on curve, in subgroup), identity rejected.
 */
export function deserializeElement(suite: Ciphersuite, bytes: Uint8Array): Point {
  if (bytes.length !== suite.Ne) throw new SigmaError('invalid element length');
  // SEC1 compressed prefixes for P-256; for BLS12-381 noble checks the flag bits.
  if (suite.Ne === 33 && bytes[0] !== 2 && bytes[0] !== 3) {
    throw new SigmaError('invalid element encoding');
  }
  let point: Point;
  try {
    point = suite.Point.fromBytes(bytes);
  } catch {
    throw new SigmaError('invalid element encoding');
  }
  if (point.is0()) throw new SigmaError('identity element');
  return point;
}
