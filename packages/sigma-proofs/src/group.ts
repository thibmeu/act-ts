/**
 * Group abstraction for sigma protocols.
 *
 * Defines the interface for prime-order elliptic curve groups
 * as specified in Section 2.1 of draft-irtf-cfrg-sigma-protocols-01.
 */

/**
 * A scalar in the field Zq where q is the group order.
 */
export interface Scalar {
  /** Add another scalar (mod q) */
  add(other: Scalar): Scalar;
  /** Subtract another scalar (mod q) */
  sub(other: Scalar): Scalar;
  /** Multiply by another scalar (mod q) */
  mul(other: Scalar): Scalar;
  /** Negate this scalar (mod q) */
  neg(): Scalar;
  /** Multiplicative inverse (mod q). Throws if scalar is zero. */
  inv(): Scalar;
  /** Check equality */
  equals(other: Scalar): boolean;
  /** Check if this scalar is zero */
  isZero(): boolean;
  /** Serialize to canonical bytes (little-endian for ristretto255, big-endian for P-256) */
  toBytes(): Uint8Array;
}

/**
 * An element of the prime-order group.
 */
export interface GroupElement {
  /** Add another group element */
  add(other: GroupElement): GroupElement;
  /** Negate this element (additive inverse) */
  negate(): GroupElement;
  /** Scalar multiplication */
  multiply(scalar: Scalar): GroupElement;
  /** Check equality */
  equals(other: GroupElement): boolean;
  /** Serialize to canonical bytes (compressed, Ne bytes) */
  toBytes(): Uint8Array;
}

/**
 * A prime-order elliptic curve group suitable for sigma protocols.
 */
export interface Group {
  /** Name identifier for the group */
  readonly name: string;

  /** Size of serialized scalars in bytes (Ns) */
  readonly scalarSize: number;

  /** Size of serialized elements in bytes (Ne) */
  readonly elementSize: number;

  /** The group order q */
  readonly order: bigint;

  /** Return the identity element */
  identity(): GroupElement;

  /** Return the standard generator G */
  generator(): GroupElement;

  /** Sample a random scalar uniformly from Zq */
  randomScalar(): Scalar;

  /** Create a scalar from a bigint */
  scalarFromBigint(n: bigint): Scalar;

  /** Deserialize a scalar from bytes */
  scalarFromBytes(bytes: Uint8Array): Scalar;

  /** Deserialize a group element from bytes */
  elementFromBytes(bytes: Uint8Array): GroupElement;

  /** Multi-scalar multiplication: sum(scalars[i] * elements[i]) */
  msm(scalars: Scalar[], elements: GroupElement[]): GroupElement;

  /**
   * Hash arbitrary data to a group element.
   * Uses the group's hash-to-curve algorithm (RFC 9380).
   *
   * @param data - Data to hash
   * @param dst - Domain separation tag (optional, uses default if not provided)
   */
  hashToElement(data: Uint8Array, dst?: Uint8Array): GroupElement;

  /**
   * Hash arbitrary data to a scalar.
   * Uses hash_to_field with expand_message_xmd/xof.
   *
   * @param data - Data to hash
   * @param dst - Domain separation tag (optional, uses default if not provided)
   */
  hashToScalar(data: Uint8Array, dst?: Uint8Array): Scalar;
}
