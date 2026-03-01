/**
 * ACT Core Types - VNEXT (sigma-draft-compliance)
 *
 * Type definitions for Anonymous Credit Tokens per the new draft:
 * - draft-schlesinger-cfrg-act (sigma-draft-compliance branch)
 * - draft-irtf-cfrg-sigma-protocols-01
 * - draft-irtf-cfrg-fiat-shamir-01
 */

import type { Scalar as SigmaScalar, GroupElement as SigmaGroupElement, Group } from 'sigma-proofs';

// Re-export sigma-proofs types for convenience
export type Scalar = SigmaScalar;
export type GroupElement = SigmaGroupElement;

/**
 * PRNG interface for deterministic randomness.
 *
 * Production implementations MUST use a CSPRNG (FIPS 186).
 * Test implementations may use SeededPRNG for reproducibility.
 */
export interface PRNG {
  /** Generate n random bytes */
  randomBytes(n: number): Uint8Array;
}

/**
 * System parameters (Section 3.1 of new draft)
 *
 * - G: Generator of the Ristretto group (implicit, from group)
 * - H1, H2, H3, H4: Additional generators for commitments
 * - L: Bit length for credit values (1 <= L <= 128)
 * - domainSeparator: Unique deployment identifier
 */
export interface SystemParams {
  readonly group: Group;
  readonly H1: GroupElement;
  readonly H2: GroupElement;
  readonly H3: GroupElement;
  readonly H4: GroupElement;
  readonly L: number;
  readonly domainSeparator: Uint8Array;
}

/**
 * Issuer's private key
 */
export interface PrivateKey {
  readonly x: Scalar;
}

/**
 * Issuer's public key (W = G * x)
 */
export interface PublicKey {
  readonly W: GroupElement;
}

/**
 * Key pair for issuer
 */
export interface KeyPair {
  readonly privateKey: PrivateKey;
  readonly publicKey: PublicKey;
}

/**
 * Credit token held by client.
 *
 * Contains BBS signature components and credit value:
 * - A: Signature point
 * - e: Signature scalar
 * - k: Nullifier (client-chosen)
 * - r: Blinding factor
 * - c: Credit amount
 * - ctx: Request context
 */
export interface CreditToken {
  readonly A: GroupElement;
  readonly e: Scalar;
  readonly k: Scalar;
  readonly r: Scalar;
  readonly c: bigint;
  readonly ctx: Scalar;
}

/**
 * Client state during issuance
 */
export interface IssuanceState {
  readonly k: Scalar;
  readonly r: Scalar;
  readonly ctx: Scalar;
}

/**
 * Issuance request (new format: K + pok)
 */
export interface IssuanceRequest {
  readonly K: GroupElement;
  readonly pok: Uint8Array; // NISigmaProtocol proof bytes
}

/**
 * Issuance response (new format: A, e, c + pok)
 */
export interface IssuanceResponse {
  readonly A: GroupElement;
  readonly e: Scalar;
  readonly c: bigint;
  readonly pok: Uint8Array;
}

/**
 * Client state during spend
 */
export interface SpendState {
  readonly kStar: Scalar;
  readonly rStar: Scalar;
  readonly m: bigint;
  readonly ctx: Scalar;
}

/**
 * Spend proof (new format: k, s, ctx, A', B_bar, Com[] + pok)
 */
export interface SpendProof {
  readonly k: Scalar;
  readonly s: bigint;
  readonly ctx: Scalar;
  readonly APrime: GroupElement;
  readonly BBar: GroupElement;
  readonly Com: readonly GroupElement[];
  readonly pok: Uint8Array;
}

/**
 * Refund response (new format: A*, e*, t + pok)
 */
export interface Refund {
  readonly AStar: GroupElement;
  readonly eStar: Scalar;
  readonly t: bigint;
  readonly pok: Uint8Array;
}

/**
 * Error types for ACT protocol
 */
export class ACTError extends Error {
  constructor(
    message: string,
    readonly code: ACTErrorCode
  ) {
    super(message);
    this.name = 'ACTError';
  }
}

export enum ACTErrorCode {
  InvalidIssuanceRequestProof = 1,
  InvalidIssuanceResponseProof = 2,
  InvalidSpendProof = 3,
  InvalidRefundProof = 4,
  DoubleSpend = 5,
  InvalidAmount = 6,
  AmountTooBig = 7,
  ScalarOutOfRange = 8,
  IdentityPoint = 9,
  InvalidParameter = 10,
  InvalidRefundAmount = 11,
}
