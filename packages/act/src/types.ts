/**
 * ACT Core Types
 *
 * Type definitions for Anonymous Credit Tokens (draft-schlesinger-cfrg-act-01)
 *
 * Section 2.2: Data Types
 * Section 3.1: System Parameters
 */

/**
 * Scalar: An integer modulo the group order q (Section 2.2)
 *
 * For ristretto255: q = 2^252 + 27742317777372353535851937790883648493
 */
export interface Scalar {
  readonly value: bigint;
  add(other: Scalar): Scalar;
  sub(other: Scalar): Scalar;
  mul(other: Scalar): Scalar;
  neg(): Scalar;
  inv(): Scalar;
  equals(other: Scalar): boolean;
  isZero(): boolean;
  toBytes(): Uint8Array;
}

/**
 * Element: A Ristretto255 group element (Section 2.2)
 */
export interface GroupElement {
  add(other: GroupElement): GroupElement;
  sub(other: GroupElement): GroupElement;
  multiply(scalar: Scalar): GroupElement;
  equals(other: GroupElement): boolean;
  isIdentity(): boolean;
  toBytes(): Uint8Array;
}

/**
 * System parameters (Section 3.1)
 *
 * - G: Generator of the Ristretto group (implicit, from group)
 * - H1, H2, H3, H4: Additional generators for commitments
 * - L: Bit length for credit values (1 <= L <= 128)
 */
export interface SystemParams {
  readonly H1: GroupElement;
  readonly H2: GroupElement;
  readonly H3: GroupElement;
  readonly H4: GroupElement;
  readonly L: number;
  readonly domainSeparator: string;
}

/**
 * Issuer's private key (Section 3.2)
 */
export interface PrivateKey {
  readonly x: Scalar;
}

/**
 * Issuer's public key (Section 3.2)
 *
 * W = G * x
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
 * Credit token held by client (Section 3.3.3, step 20)
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
  readonly c: bigint; // Credit amount as integer (0 <= c < 2^L)
  readonly ctx: Scalar;
}

/**
 * Client state during issuance (Section 3.3.1, step 15-16)
 */
export interface IssuanceState {
  readonly k: Scalar; // Nullifier
  readonly r: Scalar; // Blinding factor
}

/**
 * Issuance request from client (Section 3.3.1, step 14)
 */
export interface IssuanceRequest {
  readonly K: GroupElement; // K = H2 * k + H3 * r
  readonly gamma: Scalar; // Challenge
  readonly kBar: Scalar; // Response for k
  readonly rBar: Scalar; // Response for r
}

/**
 * Issuance response from issuer (Section 3.3.2, step 29)
 */
export interface IssuanceResponse {
  readonly A: GroupElement; // Signature point
  readonly e: Scalar; // Signature exponent
  readonly gammaResp: Scalar; // Challenge
  readonly z: Scalar; // Response
  readonly c: bigint; // Credit amount
  readonly ctx: Scalar; // Context
}

/**
 * Client state during spend (Section 3.4.1, step 128)
 */
export interface SpendState {
  readonly kStar: Scalar; // New nullifier (k*)
  readonly rStar: Scalar; // New blinding factor (r*)
  readonly m: bigint; // Remaining balance (c - s)
  readonly ctx: Scalar; // Context
}

/**
 * Spend proof from client (Section 3.4.1, step 124-127)
 */
export interface SpendProof {
  readonly k: Scalar; // Revealed nullifier
  readonly s: bigint; // Spend amount
  readonly ctx: Scalar; // Context
  readonly APrime: GroupElement; // Randomized signature A'
  readonly BBar: GroupElement; // Randomized B_bar
  readonly Com: readonly GroupElement[]; // Bit commitments (length L)
  readonly gamma: Scalar; // Challenge
  readonly eBar: Scalar;
  readonly r2Bar: Scalar;
  readonly r3Bar: Scalar;
  readonly cBar: Scalar;
  readonly rBar: Scalar;
  readonly w00: Scalar;
  readonly w01: Scalar;
  readonly gamma0: readonly Scalar[]; // Length L
  readonly z: readonly (readonly [Scalar, Scalar])[]; // Length L, pairs
  readonly kBarFinal: Scalar;
  readonly sBarFinal: Scalar;
}

/**
 * Refund response from issuer (Section 3.4.3, step 28)
 */
export interface Refund {
  readonly AStar: GroupElement; // New signature point
  readonly eStar: Scalar; // New signature exponent
  readonly gamma: Scalar; // Challenge
  readonly z: Scalar; // Response
  readonly t: bigint; // Partial return amount
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
}
