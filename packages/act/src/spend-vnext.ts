/**
 * ACT Token Spending Protocol - VNEXT (sigma-draft-compliance)
 *
 * Section 3.4: Token Spending
 *
 * Uses algebraic binary constraints for range proofs instead of CDS OR-proofs.
 * Uses NISigmaProtocol from draft-irtf-cfrg-fiat-shamir for Fiat-Shamir transform.
 */

import {
  LinearRelation,
  NISigmaProtocol,
  appendDleq,
  type Group,
} from 'sigma-proofs';
import type {
  SystemParams,
  PrivateKey,
  PublicKey,
  CreditToken,
  SpendProof,
  SpendState,
  Refund,
  Scalar,
  GroupElement,
  PRNG,
} from './types-vnext.js';
import { ACTError, ACTErrorCode } from './types-vnext.js';
import { serializeProof, deserializeProof } from './issuance-vnext.js';

/**
 * Cached common scalars per group to avoid redundant scalarFromBigint() calls.
 * Uses WeakMap to allow GC of unused groups.
 */
const cachedOne = new WeakMap<Group, Scalar>();
const cachedZero = new WeakMap<Group, Scalar>();

/** Get cached scalar 1 for group */
function getOne(group: Group): Scalar {
  let one = cachedOne.get(group);
  if (one === undefined) {
    one = group.scalarFromBigint(1n);
    cachedOne.set(group, one);
  }
  return one;
}

/** Get cached scalar 0 for group */
function getZero(group: Group): Scalar {
  let zero = cachedZero.get(group);
  if (zero === undefined) {
    zero = group.scalarFromBigint(0n);
    cachedZero.set(group, zero);
  }
  return zero;
}

/**
 * Concatenate Uint8Arrays
 */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Encode scalar to bytes
 */
function encodeScalar(s: Scalar): Uint8Array {
  return s.toBytes();
}

/**
 * Build session ID for spend proof.
 *
 * session_id = domain_separator + "spend" + Encode(k) + Encode(ctx)
 */
function spendSessionId(params: SystemParams, k: Scalar, ctx: Scalar): Uint8Array {
  const label = new Uint8Array([115, 112, 101, 110, 100]); // "spend"
  return concat(params.domainSeparator, label, encodeScalar(k), encodeScalar(ctx));
}

/**
 * Build session ID for refund proof.
 *
 * session_id = domain_separator + "refund" + Encode(e) + Encode(t) + Encode(ctx)
 */
function refundSessionId(
  params: SystemParams,
  e: Scalar,
  t: bigint,
  ctx: Scalar
): Uint8Array {
  const label = new Uint8Array([114, 101, 102, 117, 110, 100]); // "refund"
  const tScalar = params.group.scalarFromBigint(t);
  return concat(params.domainSeparator, label, encodeScalar(e), encodeScalar(tScalar), encodeScalar(ctx));
}

/**
 * Decompose value into L bits (LSB-first).
 */
function bitDecompose(value: bigint, L: number): bigint[] {
  const bits: bigint[] = [];
  for (let i = 0; i < L; i++) {
    bits.push((value >> BigInt(i)) & 1n);
  }
  return bits;
}

/**
 * Generate a non-zero random scalar.
 */
function randomNonZeroScalar(group: Group, rng: PRNG): Scalar {
  for (let attempt = 0; attempt < 100; attempt++) {
    const bytes = rng.randomBytes(group.scalarSize + 16);
    const scalar = group.hashToScalar(bytes);
    if (!scalar.isZero()) {
      return scalar;
    }
  }
  throw new Error('Failed to generate non-zero scalar after 100 attempts');
}

/**
 * Compute sum(2^j * P[j]) for j=0..n-1 using Horner's method.
 *
 * Horner's method: P[0] + 2*(P[1] + 2*(P[2] + ... + 2*P[n-1]))
 * This converts n-point MSM to (n-1) doublings + (n-1) additions.
 *
 * Performance: For L=64, naive approach does 64 scalar muls + 64 adds.
 * Horner does 63 doublings + 63 adds. Since doubling ≈ 0.5x cost of
 * scalar mul, this is ~2x faster.
 *
 * @param points - Array of group elements [P[0], P[1], ..., P[n-1]]
 * @returns sum(2^j * P[j]) for j=0..n-1
 */
function pow2WeightedSum(points: readonly GroupElement[]): GroupElement {
  if (points.length === 0) {
    throw new Error('pow2WeightedSum requires at least one point');
  }
  if (points.length === 1) {
    const p0 = points[0];
    if (!p0) throw new Error('Missing point at index 0');
    return p0;
  }

  // Start from the last element
  const lastIdx = points.length - 1;
  const lastPoint = points[lastIdx];
  if (!lastPoint) throw new Error(`Missing point at index ${lastIdx}`);
  let result = lastPoint;

  // Work backwards: result = P[j] + 2*result
  for (let j = points.length - 2; j >= 0; j--) {
    const pj = points[j];
    if (!pj) throw new Error(`Missing point at index ${j}`);
    result = pj.add(result.add(result)); // P[j] + 2*result
  }

  return result;
}

/**
 * Compute sum(2^j * s[j]) for j=0..n-1 using Horner's method.
 *
 * Horner's method: s[0] + 2*(s[1] + 2*(s[2] + ... + 2*s[n-1]))
 *
 * @param scalars - Array of scalars [s[0], s[1], ..., s[n-1]]
 * @returns sum(2^j * s[j]) for j=0..n-1
 */
function pow2WeightedScalarSum(scalars: readonly Scalar[]): Scalar {
  if (scalars.length === 0) {
    throw new Error('pow2WeightedScalarSum requires at least one scalar');
  }
  if (scalars.length === 1) {
    const s0 = scalars[0];
    if (!s0) throw new Error('Missing scalar at index 0');
    return s0;
  }

  // Start from the last element
  const lastIdx = scalars.length - 1;
  const lastScalar = scalars[lastIdx];
  if (!lastScalar) throw new Error(`Missing scalar at index ${lastIdx}`);
  let result = lastScalar;

  // Work backwards: result = s[j] + 2*result
  for (let j = scalars.length - 2; j >= 0; j--) {
    const sj = scalars[j];
    if (!sj) throw new Error(`Missing scalar at index ${j}`);
    result = sj.add(result.add(result)); // s[j] + 2*result
  }

  return result;
}

/**
 * Build the common spend proof relation structure.
 *
 * This builds the relation for both prover and verifier to ensure they match.
 * The key elements (APrime, BBar, Com, ABar) are passed as parameters.
 */
function buildSpendRelation(
  params: SystemParams,
  APrime: GroupElement,
  BBar: GroupElement,
  ABar: GroupElement,
  Com: readonly GroupElement[],
  k: Scalar,
  ctx: Scalar,
  s: bigint
): {
  relation: LinearRelation;
  scalarVarCount: number;
  eVar: number;
  r2Var: number;
  r3Var: number;
  cVar: number;
  rVar: number;
  bVars: number[];
  sComVars: number[];
  s2Vars: number[];
  kStarVar: number;
  kStar2Var: number;
} {
  const { group, H1, H2, H3, H4, L } = params;
  const G = group.generator();
  const one = getOne(group);

  // H1' = G + k*H2 + ctx*H4 (public, derived from k and ctx in proof)
  // Actually H1' uses the ctx from token, but k is revealed in the proof
  // We compute it here for both prover and verifier
  const sScalar = group.scalarFromBigint(s);

  // K' = sum(2^j * Com[j]) using Horner's method
  const KPrime = pow2WeightedSum(Com);

  // ComTotal = s*H1 + K'
  // Handle s=0 case (multiply by zero scalar not allowed)
  const ComTotal = s === 0n ? KPrime : H1.multiply(sScalar).add(KPrime);

  const relation = new LinearRelation(group);

  // Scalar variables:
  // [e, r2, r3, c, r, b[0..L-1], sCom[0..L-1], s2[0..L-1], kStar, kStar2]
  // where kStar2 = (1 - b[0]) * kStar (needed for binary constraint on Com[0])
  // Total: 5 + 3*L + 2 = 7 + 3*L
  const numScalars = 7 + 3 * L;
  const scalarVars = relation.allocateScalars(numScalars);

  const eVar = scalarVars[0]!;
  const r2Var = scalarVars[1]!;
  const r3Var = scalarVars[2]!;
  const cVar = scalarVars[3]!;
  const rVar = scalarVars[4]!;
  const bVars: number[] = [];
  const sComVars: number[] = [];
  const s2Vars: number[] = [];

  for (let j = 0; j < L; j++) {
    bVars.push(scalarVars[5 + j]!);
    sComVars.push(scalarVars[5 + L + j]!);
    s2Vars.push(scalarVars[5 + 2 * L + j]!);
  }
  const kStarVar = scalarVars[5 + 3 * L]!;
  const kStar2Var = scalarVars[6 + 3 * L]!;

  // Element allocation:
  // Fixed elements: G, H1, H2, H3, negAPrime, BBar, ABar, negH1, negH3, H1Prime, ComTotal
  // Variable elements: Com[0..L-1]
  // Total: 11 + L
  const elemVars = relation.allocateElements(11 + L);

  const gIdx = elemVars[0]!;
  const h1Idx = elemVars[1]!;
  const h2Idx = elemVars[2]!;
  const h3Idx = elemVars[3]!;
  const negAPrimeIdx = elemVars[4]!;
  const bBarIdx = elemVars[5]!;
  const aBarIdx = elemVars[6]!;
  const negH1Idx = elemVars[7]!;
  const negH3Idx = elemVars[8]!;
  const h1PrimeIdx = elemVars[9]!;
  const comTotalIdx = elemVars[10]!;

  const comIndices: number[] = [];
  for (let j = 0; j < L; j++) {
    comIndices.push(elemVars[11 + j]!);
  }

  // Set element values
  const elementPairs: Array<[number, GroupElement]> = [
    [gIdx, G],
    [h1Idx, H1],
    [h2Idx, H2],
    [h3Idx, H3],
    [negAPrimeIdx, APrime.negate()],
    [bBarIdx, BBar],
    [aBarIdx, ABar],
    [negH1Idx, H1.negate()],
    [negH3Idx, H3.negate()],
    [h1PrimeIdx, group.msm([one, k, ctx], [G, H2, H4])], // H1' = G + k*H2 + ctx*H4
    [comTotalIdx, ComTotal],
  ];

  for (let j = 0; j < L; j++) {
    elementPairs.push([comIndices[j]!, Com[j]!]);
  }

  relation.setElements(elementPairs);

  // Equation 1: BBS signature verification
  // ABar = e * (-A') + r2 * BBar
  relation.appendEquation(aBarIdx, [
    [eVar, negAPrimeIdx],
    [r2Var, bBarIdx],
  ]);

  // Equation 2: Credential structure (simplified)
  // H1' = r3 * BBar + c * (-H1) + r * (-H3)
  // This proves knowledge of c and r
  relation.appendEquation(h1PrimeIdx, [
    [r3Var, bBarIdx],
    [cVar, negH1Idx],
    [rVar, negH3Idx],
  ]);

  // Equations for range proof: 2*L equations
  // For each bit j:
  //   Opening: Com[j] = b[j]*H1 + kStar*H2 + sCom[j]*H3 (j=0)
  //            Com[j] = b[j]*H1 + sCom[j]*H3 (j>0)
  //   Binary:  Com[j] = b[j]*Com[j] + s2[j]*H3

  for (let j = 0; j < L; j++) {
    const comIdx = comIndices[j]!;
    const bVar = bVars[j]!;
    const sComVar = sComVars[j]!;
    const s2Var = s2Vars[j]!;

    // Opening equation
    if (j === 0) {
      relation.appendEquation(comIdx, [
        [bVar, h1Idx],
        [kStarVar, h2Idx],
        [sComVar, h3Idx],
      ]);
    } else {
      relation.appendEquation(comIdx, [
        [bVar, h1Idx],
        [sComVar, h3Idx],
      ]);
    }

    // Binary constraint
    // For j=0: Com[0] = b[0]*Com[0] + kStar2*H2 + s2[0]*H3
    //   where kStar2 = (1-b[0])*kStar handles the extra H2 term
    // For j>0: Com[j] = b[j]*Com[j] + s2[j]*H3
    if (j === 0) {
      relation.appendEquation(comIdx, [
        [bVar, comIdx],
        [kStar2Var, h2Idx],
        [s2Var, h3Idx],
      ]);
    } else {
      relation.appendEquation(comIdx, [
        [bVar, comIdx],
        [s2Var, h3Idx],
      ]);
    }
  }

  // Equation for commitment total consistency (final equation: 2L+3)
  // ComTotal = c*H1 + kStar*H2 + Σ sCom[j]*(H3*2^j)
  //
  // This equation ties together:
  // - c (the token's credit balance, proven in eq 2)
  // - kStar (the new nullifier randomness, bound in Com[0])
  // - sCom[j] (the randomizers, bound in each Com[j])
  //
  // Since ComTotal = s*H1 + KPrime where KPrime = sum(2^j*Com[j]),
  // and each Com[j] = b[j]*H1 + ... (opening) with b[j] being bits of (c-s),
  // this verifies the consistency between s and c via the range proof.

  // Allocate additional elements for consistency equation
  // We need separate H1, H2 vars and H3*2^j coefficients
  const consistencyH1Idx = relation.allocateElements(1)[0]!;
  const consistencyH2Idx = relation.allocateElements(1)[0]!;

  relation.setElements([
    [consistencyH1Idx, H1],
    [consistencyH2Idx, H2],
  ]);

  // Build the consistency equation: ComTotal = c*H1 + kStar*H2 + Σ sCom[j]*(H3*2^j)
  const coefficients: Array<[number, number]> = [
    [cVar, consistencyH1Idx],
    [kStarVar, consistencyH2Idx],
  ];

  // Add the sCom[j]*(H3*2^j) terms
  // Use doubling chain instead of scalar multiplication: H3*2^j = 2*(H3*2^(j-1))
  const h3Powers: GroupElement[] = [H3]; // h3Powers[0] = H3 = H3*2^0
  for (let j = 1; j < L; j++) {
    const prev = h3Powers[j - 1];
    if (!prev) throw new Error(`Missing h3Powers at index ${j - 1}`);
    h3Powers.push(prev.add(prev)); // H3*2^j = 2 * H3*2^(j-1)
  }

  for (let j = 0; j < L; j++) {
    const h3Times2j = h3Powers[j];
    if (!h3Times2j) throw new Error(`Missing h3Powers at index ${j}`);
    const h3CoeffIdx = relation.allocateElements(1)[0]!;
    relation.setElements([[h3CoeffIdx, h3Times2j]]);
    coefficients.push([sComVars[j]!, h3CoeffIdx]);
  }

  relation.appendEquation(comTotalIdx, coefficients);

  return {
    relation,
    scalarVarCount: numScalars,
    eVar,
    r2Var,
    r3Var,
    cVar,
    rVar,
    bVars,
    sComVars,
    s2Vars,
    kStarVar,
    kStar2Var,
  };
}

/**
 * ProveSpend (Section 3.4.1)
 *
 * Creates a spend proof showing the client has a valid token with at least s credits.
 *
 * @param params - System parameters
 * @param token - Credit token to spend from
 * @param s - Amount to spend (0 <= s <= c)
 * @param rng - Random number generator
 * @returns Tuple of (proof, state)
 */
export function proveSpend(
  params: SystemParams,
  token: CreditToken,
  s: bigint,
  rng: PRNG
): [SpendProof, SpendState] {
  const { group, H1, H2, H3, H4, L } = params;
  const { A, e, k, r, c, ctx } = token;
  const maxValue = 1n << BigInt(L);

  // Validate inputs
  if (s < 0n) {
    throw new ACTError(`Spend amount must be non-negative`, ACTErrorCode.InvalidAmount);
  }
  if (s >= maxValue) {
    throw new ACTError(`Spend amount ${s} >= 2^L`, ACTErrorCode.InvalidAmount);
  }
  if (c >= maxValue) {
    throw new ACTError(`Token balance ${c} >= 2^L`, ACTErrorCode.InvalidAmount);
  }
  if (s > c) {
    throw new ACTError(`Spend amount ${s} > balance ${c}`, ACTErrorCode.InvalidAmount);
  }

  const G = group.generator();
  const one = getOne(group);
  const cScalar = group.scalarFromBigint(c);

  // Randomize the signature with non-zero scalars
  const r1 = randomNonZeroScalar(group, rng);
  const r2 = randomNonZeroScalar(group, rng);

  // B = G + c*H1 + k*H2 + r*H3 + ctx*H4
  const B = group.msm([one, cScalar, k, r, ctx], [G, H1, H2, H3, H4]);

  // A' = A * (r1 * r2)
  const APrime = A.multiply(r1.mul(r2));

  // B_bar = B * r1
  const BBar = B.multiply(r1);

  // r3 = 1/r1
  const r3 = r1.inv();

  // A_bar = A' * e (what we're proving knowledge of)
  // Actually for the proof: A_bar = e*(-A') + r2*BBar from verifier's perspective
  // The prover knows e and r2 such that this holds
  // Verifier computes: A_bar = A' * sk
  // So prover needs: A'*sk = e*(-A') + r2*BBar
  // => A'*(sk+e) = r2*BBar
  // This requires knowing sk, which prover doesn't have!
  //
  // The actual relation is different. Let me re-read the spec...
  //
  // From spec: A_bar = A' * (e + sk) = A' * e + A' * sk
  // Verifier computes A' * sk, so:
  // A_bar - A'*sk = A' * e
  // => We need: prover knows e such that A'*e = A_bar - A'*sk
  //
  // Wait, the verifier computes ABar = APrime * sk and checks the proof.
  // The proof shows: ABar = e*(-APrime) + r2*BBar
  // Which means: APrime*sk = -e*APrime + r2*BBar
  // => APrime*(sk+e) = r2*BBar
  // => APrime*(sk+e) = r2*B*r1
  // => A*r1*r2*(sk+e) = r2*B*r1
  // => A*(sk+e) = B
  // This is the BBS signature verification equation! The token has A = B / (sk+e).

  // BBS signature: A * (sk + e) = B
  // Randomized: A' = A * r1 * r2, B_bar = B * r1
  // Equation to prove: A'*sk = -e*A' + r2*BBar
  //
  // Prover computes ABar = -e*A' + r2*BBar
  // Let's verify this equals A'*sk:
  //   -e*A' + r2*BBar = -e*A*r1*r2 + r2*B*r1
  //                   = r1*r2*(-e*A) + r1*r2*B/r2 ... no
  //   Actually: -e*A*r1*r2 + r2*B*r1 = r1*r2*(-e*A + B/r2)... wrong
  //   
  //   Let's be more careful:
  //   -e*A' + r2*BBar = -e*(A*r1*r2) + r2*(B*r1)
  //                   = -e*A*r1*r2 + B*r1*r2
  //                   = r1*r2*(-e*A + B)
  //                   = r1*r2*(B - e*A)
  //   From BBS: A*(sk+e) = B => B - e*A = A*sk
  //   So: r1*r2*(B - e*A) = r1*r2*A*sk = A'*sk ✓
  //
  // So prover's ABar should equal verifier's ABar = A'*sk
  const ABar = APrime.multiply(e).negate().add(BBar.multiply(r2));

  // Decompose remaining balance m = c - s into bits
  const m = c - s;
  const bits = bitDecompose(m, L);

  // Generate new nullifier k* and blinding factors for each bit commitment
  const kStar = randomNonZeroScalar(group, rng);

  // Pre-size arrays to avoid reallocations
  const sCom: Scalar[] = new Array<Scalar>(L);
  const s2: Scalar[] = new Array<Scalar>(L);
  const Com: GroupElement[] = new Array<GroupElement>(L);

  // Cache scalar 0 and 1 for bit conversion (bits are always 0n or 1n)
  const zero = getZero(group);
  const scalarBits: Scalar[] = new Array<Scalar>(L);
  for (let j = 0; j < L; j++) {
    scalarBits[j] = bits[j] === 1n ? one : zero;
  }

  for (let j = 0; j < L; j++) {
    const sj = randomNonZeroScalar(group, rng);
    sCom[j] = sj;

    const bj = scalarBits[j]!;

    // Com[j] = b[j]*H1 + s[j]*H3 (+ kstar*H2 for j=0)
    if (j === 0) {
      Com[j] = group.msm([bj, kStar, sj], [H1, H2, H3]);
    } else {
      Com[j] = group.msm([bj, sj], [H1, H3]);
    }

    // s2[j] = (1 - b[j]) * s[j]
    const oneMinusBj = one.sub(bj);
    s2[j] = oneMinusBj.mul(sj);
  }

  // Compute r* = sum(2^j * s[j]) using Horner's method
  const rStar = pow2WeightedScalarSum(sCom);

  // Compute kStar2 = (1 - b[0]) * kStar
  // This is needed for the binary constraint on Com[0]
  const b0Scalar = scalarBits[0]!;
  const oneMinusB0 = one.sub(b0Scalar);
  const kStar2 = oneMinusB0.mul(kStar);

  // Build relation
  const { relation, scalarVarCount } =
    buildSpendRelation(params, APrime, BBar, ABar, Com, k, ctx, s);

  // Build witness
  // Order must match variable allocation: e, r2, r3, c, r, b[0..L-1], sCom[0..L-1], s2[0..L-1], kStar, kStar2
  const witness: Scalar[] = [
    e,
    r2,
    r3,
    cScalar,
    r,
    ...bits.map((b) => group.scalarFromBigint(b)),
    ...sCom,
    ...s2,
    kStar,
    kStar2,
  ];

  // Generate NI proof (NISigmaProtocol uses internal randomness)
  const sessionId = spendSessionId(params, k, ctx);
  const prover = new NISigmaProtocol(relation, { sessionId });
  const proof = prover.prove(witness);
  const pok = serializeProof(proof, group.scalarSize);

  const spendProof: SpendProof = {
    k,
    s,
    ctx,
    APrime,
    BBar,
    Com,
    pok,
  };

  const state: SpendState = {
    kStar,
    rStar,
    m,
    ctx,
  };

  return [spendProof, state];
}

/**
 * VerifySpendProof (Section 3.4.2)
 *
 * Verifies a spend proof.
 *
 * @param params - System parameters
 * @param sk - Issuer's private key
 * @param proof - Spend proof from client
 * @throws ACTError if proof is invalid
 */
export function verifySpendProof(
  params: SystemParams,
  sk: PrivateKey,
  proof: SpendProof
): void {
  const { group, L } = params;
  const { k, s, ctx, APrime, BBar, Com, pok } = proof;

  // Check A' is not identity
  if (APrime.equals(group.identity())) {
    throw new ACTError("A' is identity", ACTErrorCode.IdentityPoint);
  }

  // Validate proof structure
  if (Com.length !== L) {
    throw new ACTError(
      `Invalid commitment count: expected ${L}, got ${Com.length}`,
      ACTErrorCode.InvalidSpendProof
    );
  }

  // Compute A_bar = A' * sk.x (issuer's view)
  const ABar = APrime.multiply(sk.x);

  // Build relation (same as prover)
  const { relation, scalarVarCount } = buildSpendRelation(params, APrime, BBar, ABar, Com, k, ctx, s);

  // Verify proof
  const sessionId = spendSessionId(params, k, ctx);
  const verifier = new NISigmaProtocol(relation, { sessionId });

  const parsedProof = deserializeProof(group, pok, scalarVarCount);

  if (!verifier.verify(parsedProof)) {
    throw new ACTError('Invalid spend proof', ACTErrorCode.InvalidSpendProof);
  }
}

/**
 * IssueRefund (Section 3.4.3)
 *
 * Issues a refund token for remaining balance after spending.
 *
 * @param params - System parameters
 * @param sk - Issuer's private key
 * @param proof - Verified spend proof
 * @param t - Credits to return (0 <= t <= s)
 * @param rng - Random number generator
 * @returns Refund message
 */
export function issueRefund(
  params: SystemParams,
  sk: PrivateKey,
  proof: SpendProof,
  t: bigint,
  rng: PRNG
): Refund {
  const { group, H1, H4, L } = params;
  const { s, ctx, Com } = proof;
  const maxValue = 1n << BigInt(L);

  // Validate partial return amount
  if (t < 0n) {
    throw new ACTError('Return amount must be non-negative', ACTErrorCode.InvalidAmount);
  }
  if (t >= maxValue) {
    throw new ACTError(`Return amount ${t} >= 2^L`, ACTErrorCode.InvalidAmount);
  }
  if (t > s) {
    throw new ACTError(
      `Return amount ${t} > spend amount ${s}`,
      ACTErrorCode.InvalidRefundAmount
    );
  }

  // Reconstruct K' = sum(2^j * Com[j]) using Horner's method
  const KPrime = pow2WeightedSum(Com);

  const G = group.generator();
  const one = getOne(group);

  // Create new BBS signature
  const eStar = randomNonZeroScalar(group, rng);
  const tScalar = group.scalarFromBigint(t);

  // X_A* = G + K' + t*H1 + ctx*H4
  const XAStar = group.msm([one, one, tScalar, ctx], [G, KPrime, H1, H4]);

  // A* = X_A* * (1/(e* + sk.x))
  const skPlusEStar = sk.x.add(eStar);
  const AStar = XAStar.multiply(skPlusEStar.inv());

  // X_G = (e* + sk.x) * G
  const X_G = G.multiply(skPlusEStar);

  // Build DLEQ proof
  const relation = new LinearRelation(group);
  const refundScalars = relation.allocateScalars(1);
  const dVar = refundScalars[0]!;
  const refundElems = relation.allocateElements(4);
  const gIdx = refundElems[0]!;
  const aStarIdx = refundElems[1]!;
  const xaStarIdx = refundElems[2]!;
  const xgIdx = refundElems[3]!;
  relation.setElements([
    [gIdx, G],
    [aStarIdx, AStar],
    [xaStarIdx, XAStar],
    [xgIdx, X_G],
  ]);
  appendDleq(relation, aStarIdx, gIdx, xaStarIdx, xgIdx, dVar);

  const sessionId = refundSessionId(params, eStar, t, ctx);
  const prover = new NISigmaProtocol(relation, { sessionId });
  const refundProof = prover.prove([skPlusEStar]);
  const pok = serializeProof(refundProof, group.scalarSize);

  return { AStar, eStar, t, pok };
}

/**
 * ConstructRefundToken (Section 3.4.4)
 *
 * Verifies refund and constructs new token.
 *
 * @param params - System parameters
 * @param pk - Issuer's public key
 * @param proof - The spend proof that was sent
 * @param refund - Issuer's refund response
 * @param state - Client's spend state
 * @returns New credit token
 */
export function constructRefundToken(
  params: SystemParams,
  pk: PublicKey,
  proof: SpendProof,
  refund: Refund,
  state: SpendState
): CreditToken {
  const { group, H1, H4, L } = params;
  const { AStar, eStar, t, pok } = refund;
  const { kStar, rStar, m, ctx } = state;
  const { Com } = proof;

  // Reconstruct K' = sum(2^j * Com[j]) using Horner's method
  const KPrime = pow2WeightedSum(Com);

  const G = group.generator();
  const one = getOne(group);
  const tScalar = group.scalarFromBigint(t);

  // X_A* = G + K' + t*H1 + ctx*H4
  const XAStar = group.msm([one, one, tScalar, ctx], [G, KPrime, H1, H4]);

  // X_G = e* * G + pk.W
  const X_G = G.multiply(eStar).add(pk.W);

  // Verify DLEQ proof
  const relation = new LinearRelation(group);
  const verifyScalars = relation.allocateScalars(1);
  const dVar = verifyScalars[0]!;
  const verifyElems = relation.allocateElements(4);
  const gIdx = verifyElems[0]!;
  const aStarIdx = verifyElems[1]!;
  const xaStarIdx = verifyElems[2]!;
  const xgIdx = verifyElems[3]!;
  relation.setElements([
    [gIdx, G],
    [aStarIdx, AStar],
    [xaStarIdx, XAStar],
    [xgIdx, X_G],
  ]);
  appendDleq(relation, aStarIdx, gIdx, xaStarIdx, xgIdx, dVar);

  const sessionId = refundSessionId(params, eStar, t, ctx);
  const verifier = new NISigmaProtocol(relation, { sessionId });
  const parsedProof = deserializeProof(group, pok, 1);

  if (!verifier.verify(parsedProof)) {
    throw new ACTError('Invalid refund proof', ACTErrorCode.InvalidRefundProof);
  }

  // Construct new token with balance m + t
  const newBalance = m + t;

  return {
    A: AStar,
    e: eStar,
    k: kStar,
    r: rStar,
    c: newBalance,
    ctx,
  };
}

/**
 * Verify spend and issue refund (issuer-side convenience).
 *
 * @param params - System parameters
 * @param sk - Issuer's private key
 * @param proof - Client's spend proof
 * @param usedNullifiers - Set of already-used nullifiers (modified in place)
 * @param t - Credits to return (default 0)
 * @param rng - Random number generator
 * @returns Refund message
 */
export function verifyAndRefund(
  params: SystemParams,
  sk: PrivateKey,
  proof: SpendProof,
  usedNullifiers: Set<string>,
  t: bigint,
  rng: PRNG
): Refund {
  // Check nullifier hasn't been used
  const nullifierKey = Buffer.from(proof.k.toBytes()).toString('hex');
  if (usedNullifiers.has(nullifierKey)) {
    throw new ACTError('Double spend detected', ACTErrorCode.DoubleSpend);
  }

  // Verify the proof
  verifySpendProof(params, sk, proof);

  // Record nullifier
  usedNullifiers.add(nullifierKey);

  // Issue refund
  return issueRefund(params, sk, proof, t, rng);
}
