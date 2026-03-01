/**
 * ACT Token Spending Protocol
 *
 * Section 3.4: Token Spending
 *
 * Allows client to spend s credits from a token with c credits (0 <= s <= c).
 * Uses range proofs with bit decomposition to prove c - s >= 0 without
 * revealing c.
 */

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
} from './types.js';
import { ACTError, ACTErrorCode } from './types.js';
import { group } from './group.js';
import { Transcript } from './transcript.js';

/**
 * BitDecompose (Section 3.5.4)
 *
 * Decomposes a value into L bits (LSB-first order).
 */
function bitDecompose(value: bigint, L: number): bigint[] {
  const bits: bigint[] = [];
  for (let i = 0; i < L; i++) {
    bits.push((value >> BigInt(i)) & 1n);
  }
  return bits;
}

/**
 * ProveSpend (Section 3.4.1)
 *
 * Creates a spend proof showing the client has a valid token with
 * at least s credits.
 *
 * @param params - System parameters
 * @param token - Credit token to spend from
 * @param s - Amount to spend (0 <= s <= c)
 * @returns Tuple of (proof, state) where state is used to receive change
 */
export function proveSpend(
  params: SystemParams,
  token: CreditToken,
  s: bigint
): [SpendProof, SpendState] {
  const { A, e, k, r, c, ctx } = token;
  const L = params.L;
  const maxValue = 1n << BigInt(L);

  // Steps 1-7: Validate inputs
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

  // Steps 8-13: Randomize the signature
  const r1 = group.randomScalar();
  const r2 = group.randomScalar();

  // B = G + H1 * c + H2 * k + H3 * r + H4 * ctx
  const cScalar = group.scalarFromBigint(c);
  const B = group.msm(
    [group.one(), cScalar, k, r, ctx],
    [G, params.H1, params.H2, params.H3, params.H4]
  );

  // A' = A * (r1 * r2)
  const APrime = A.multiply(r1.mul(r2));

  // B_bar = B * r1
  const BBar = B.multiply(r1);

  // r3 = 1/r1
  const r3 = r1.inv();

  // Steps 14-22: Generate initial proof components for sigma protocol
  const cPrime = group.randomScalar();
  const rPrime = group.randomScalar();
  const ePrime = group.randomScalar();
  const r2Prime = group.randomScalar();
  const r3Prime = group.randomScalar();

  // A1 = A' * e' + B_bar * r2'
  const A1 = APrime.multiply(ePrime).add(BBar.multiply(r2Prime));

  // A2 = B_bar * r3' + H1 * c' + H3 * r'
  const A2 = group.msm([r3Prime, cPrime, rPrime], [BBar, params.H1, params.H3]);

  // Steps 23-25: Decompose c - s into bits (remaining balance m)
  const m = c - s;
  const bits = bitDecompose(m, L);

  // Steps 26-32: Create commitments for each bit
  const kStar = group.randomScalar(); // New nullifier k*
  const sBlinding: Scalar[] = []; // s[j] blinding factors for each bit
  const Com: GroupElement[] = [];

  // Com[0] = H1 * i[0] + H2 * k* + H3 * s[0]
  const s0 = group.randomScalar();
  sBlinding.push(s0);
  const i0Scalar = group.scalarFromBigint(bits[0]);
  Com.push(group.msm([i0Scalar, kStar, s0], [params.H1, params.H2, params.H3]));

  // For j = 1 to L-1: Com[j] = H1 * i[j] + H3 * s[j]
  for (let j = 1; j < L; j++) {
    const sj = group.randomScalar();
    sBlinding.push(sj);
    const ijScalar = group.scalarFromBigint(bits[j]);
    Com.push(group.msm([ijScalar, sj], [params.H1, params.H3]));
  }

  // Steps 33-66: Range proof using OR-proof for each bit
  // For each bit position, we prove the commitment opens to either 0 or 1.
  // We use the standard OR-proof technique: simulate one branch, prove the other.

  // Arrays to store proof components
  const gamma0Simulated: Scalar[] = []; // Simulated challenges
  const CPrimeProver: [GroupElement, GroupElement][] = []; // First-round messages

  // For bit 0: need H2*k* component in real branch
  const k0Prime = group.randomScalar(); // Nonce for k* in bit 0
  const sPrimeArr: Scalar[] = []; // Nonces for blinding factors
  const w0 = group.randomScalar(); // For simulated branch of bit 0
  const zSimArr: [Scalar, Scalar][] = []; // Simulated responses

  for (let j = 0; j < L; j++) {
    const sPrimeJ = group.randomScalar();
    sPrimeArr.push(sPrimeJ);

    // Compute C[j][0] = Com[j] and C[j][1] = Com[j] - H1
    const Cj0 = Com[j];
    const Cj1 = Com[j].sub(params.H1);

    // Random challenge and responses for simulated branch
    const gamma0J = group.randomScalar();
    gamma0Simulated.push(gamma0J);

    const z0Sim = group.randomScalar();
    const z1Sim = group.randomScalar();
    zSimArr.push([z0Sim, z1Sim]);

    if (j === 0) {
      // Bit 0 has k* component
      if (bits[0] === 0n) {
        // Real branch is b=0: C'[0][0] = H2 * k0' + H3 * s'[0]
        // Simulated branch is b=1: C'[0][1] = H2 * w0 + H3 * z_sim[0][1] - C[0][1] * gamma0[0]
        const CPrime00 = group.msm([k0Prime, sPrimeJ], [params.H2, params.H3]);
        const CPrime01 = group.msm([w0, z1Sim], [params.H2, params.H3]).sub(Cj1.multiply(gamma0J));
        CPrimeProver.push([CPrime00, CPrime01]);
      } else {
        // Real branch is b=1: C'[0][1] = H2 * k0' + H3 * s'[0]
        // Simulated branch is b=0: C'[0][0] = H2 * w0 + H3 * z_sim[0][0] - C[0][0] * gamma0[0]
        const CPrime00 = group.msm([w0, z0Sim], [params.H2, params.H3]).sub(Cj0.multiply(gamma0J));
        const CPrime01 = group.msm([k0Prime, sPrimeJ], [params.H2, params.H3]);
        CPrimeProver.push([CPrime00, CPrime01]);
      }
    } else {
      // Bits 1 to L-1: no k* component
      if (bits[j] === 0n) {
        // Real branch is b=0: C'[j][0] = H3 * s'[j]
        // Simulated branch is b=1: C'[j][1] = H3 * z_sim[j][1] - C[j][1] * gamma0[j]
        const CPrimeJ0 = params.H3.multiply(sPrimeJ);
        const CPrimeJ1 = params.H3.multiply(z1Sim).sub(Cj1.multiply(gamma0J));
        CPrimeProver.push([CPrimeJ0, CPrimeJ1]);
      } else {
        // Real branch is b=1: C'[j][1] = H3 * s'[j]
        // Simulated branch is b=0: C'[j][0] = H3 * z_sim[j][0] - C[j][0] * gamma0[j]
        const CPrimeJ0 = params.H3.multiply(z0Sim).sub(Cj0.multiply(gamma0J));
        const CPrimeJ1 = params.H3.multiply(sPrimeJ);
        CPrimeProver.push([CPrimeJ0, CPrimeJ1]);
      }
    }
  }

  // Steps 67-72: Compute K' and final commitment
  // K' = Sum(Com[j] * 2^j for j in [L])
  // r* = Sum(s[j] * 2^j for j in [L])
  let KPrime = group.identity();
  let rStar = group.zero();
  for (let j = 0; j < L; j++) {
    const pow2j = group.scalarFromBigint(1n << BigInt(j));
    KPrime = KPrime.add(Com[j].multiply(pow2j));
    rStar = rStar.add(sBlinding[j].mul(pow2j));
  }

  const kPrime2 = group.randomScalar(); // Nonce for k_bar response
  const sPrime2 = group.randomScalar(); // Nonce for s_bar response

  // C_final = H1 * (-c') + H2 * k' + H3 * s'
  const CFinal = group.msm([cPrime.neg(), kPrime2, sPrime2], [params.H1, params.H2, params.H3]);

  // Steps 73-86: Generate challenge using transcript
  const transcript = new Transcript('spend', params);
  transcript.addScalar(k);
  transcript.addScalar(ctx);
  transcript.addElement(APrime);
  transcript.addElement(BBar);
  transcript.addElement(A1);
  transcript.addElement(A2);
  for (let j = 0; j < L; j++) {
    transcript.addElement(Com[j]);
  }
  for (let j = 0; j < L; j++) {
    transcript.addElement(CPrimeProver[j][0]);
    transcript.addElement(CPrimeProver[j][1]);
  }
  transcript.addElement(CFinal);
  const gamma = transcript.getChallenge();

  // Steps 88-93: Compute sigma protocol responses
  const eBar = ePrime.sub(gamma.mul(e));
  const r2Bar = gamma.mul(r2).add(r2Prime);
  const r3Bar = gamma.mul(r3).add(r3Prime);
  const cBar = cPrime.sub(gamma.mul(cScalar));
  const rBar = rPrime.sub(gamma.mul(r));

  // Steps 94-120: Complete range proof responses
  // For each bit, compute final responses based on which branch was real
  const zFinal: [Scalar, Scalar][] = [];
  const gamma0Final: Scalar[] = [];
  let w00Final: Scalar;
  let w01Final: Scalar;

  for (let j = 0; j < L; j++) {
    if (j === 0) {
      // Bit 0 with k* component
      if (bits[0] === 0n) {
        // Real branch was b=0
        // gamma0_final[0] = gamma - gamma0_simulated[0]
        const gamma0F = gamma.sub(gamma0Simulated[0]);
        gamma0Final.push(gamma0F);
        // w00 = gamma0F * k* + k0'
        w00Final = gamma0F.mul(kStar).add(k0Prime);
        // w01 = w0 (from simulation)
        w01Final = w0;
        // z[0][0] = gamma0F * s[0] + s'[0]
        const z00 = gamma0F.mul(sBlinding[0]).add(sPrimeArr[0]);
        // z[0][1] = z_sim[0][1] (from simulation)
        const z01 = zSimArr[0][1];
        zFinal.push([z00, z01]);
      } else {
        // Real branch was b=1
        // gamma0_final[0] = gamma0_simulated[0]
        gamma0Final.push(gamma0Simulated[0]);
        const gamma1F = gamma.sub(gamma0Simulated[0]);
        // w00 = w0 (from simulation)
        w00Final = w0;
        // w01 = gamma1F * k* + k0'
        w01Final = gamma1F.mul(kStar).add(k0Prime);
        // z[0][0] = z_sim[0][0] (from simulation)
        const z00 = zSimArr[0][0];
        // z[0][1] = gamma1F * s[0] + s'[0]
        const z01 = gamma1F.mul(sBlinding[0]).add(sPrimeArr[0]);
        zFinal.push([z00, z01]);
      }
    } else {
      // Bits 1 to L-1
      if (bits[j] === 0n) {
        // Real branch was b=0
        const gamma0F = gamma.sub(gamma0Simulated[j]);
        gamma0Final.push(gamma0F);
        // z[j][0] = gamma0F * s[j] + s'[j]
        const zj0 = gamma0F.mul(sBlinding[j]).add(sPrimeArr[j]);
        // z[j][1] = z_sim[j][1]
        const zj1 = zSimArr[j][1];
        zFinal.push([zj0, zj1]);
      } else {
        // Real branch was b=1
        gamma0Final.push(gamma0Simulated[j]);
        const gamma1F = gamma.sub(gamma0Simulated[j]);
        // z[j][0] = z_sim[j][0]
        const zj0 = zSimArr[j][0];
        // z[j][1] = gamma1F * s[j] + s'[j]
        const zj1 = gamma1F.mul(sBlinding[j]).add(sPrimeArr[j]);
        zFinal.push([zj0, zj1]);
      }
    }
  }

  // Steps 121-122: Final responses for K' opening
  // k_bar = gamma * k* + k' (proves knowledge of k* in K')
  const kBarFinal = gamma.mul(kStar).add(kPrime2);
  // s_bar = gamma * r* + s' (proves knowledge of r* in K')
  const sBarFinal = gamma.mul(rStar).add(sPrime2);

  // Construct proof
  const proof: SpendProof = {
    k,
    s,
    ctx,
    APrime,
    BBar,
    Com,
    gamma,
    eBar,
    r2Bar,
    r3Bar,
    cBar,
    rBar,
    w00: w00Final!,
    w01: w01Final!,
    gamma0: gamma0Final,
    z: zFinal,
    kBarFinal,
    sBarFinal,
  };

  const state: SpendState = {
    kStar,
    rStar,
    m,
    ctx,
  };

  return [proof, state];
}

/**
 * VerifySpendProof (Section 3.4.5)
 *
 * Verifies a spend proof.
 *
 * @param params - System parameters
 * @param sk - Issuer's private key
 * @param proof - Spend proof from client
 * @returns true if valid
 */
export function verifySpendProof(params: SystemParams, sk: PrivateKey, proof: SpendProof): boolean {
  const {
    k,
    s,
    ctx,
    APrime,
    BBar,
    Com,
    gamma,
    eBar,
    r2Bar,
    r3Bar,
    cBar,
    rBar,
    w00,
    w01,
    gamma0,
    z,
    kBarFinal,
    sBarFinal,
  } = proof;

  const L = params.L;
  const G = group.generator();

  // Step 3-4: Check A' is not identity
  if (APrime.isIdentity()) {
    throw new ACTError("A' is identity", ACTErrorCode.IdentityPoint);
  }

  // Steps 5-7: Compute issuer's view
  // A_bar = A' * sk.x
  const ABar = APrime.multiply(sk.x);

  // H1_prime = G + H2 * k + H4 * ctx
  const H1Prime = group.msm([group.one(), k, ctx], [G, params.H2, params.H4]);

  // Steps 8-10: Verify sigma protocol
  // A1 = A' * e_bar + B_bar * r2_bar - A_bar * gamma
  const A1 = APrime.multiply(eBar).add(BBar.multiply(r2Bar)).sub(ABar.multiply(gamma));

  // A2 = B_bar * r3_bar + H1 * c_bar + H3 * r_bar - H1_prime * gamma
  const A2 = group
    .msm([r3Bar, cBar, rBar], [BBar, params.H1, params.H3])
    .sub(H1Prime.multiply(gamma));

  // Steps 11-27: Range proof verification
  const CPrime: [GroupElement, GroupElement][] = [];

  for (let j = 0; j < L; j++) {
    const gamma1J = gamma.sub(gamma0[j]);
    const Cj0 = Com[j];
    const Cj1 = Com[j].sub(params.H1);

    if (j === 0) {
      // Steps 19-20: Bit 0 with k* component
      // C'[0][0] = H2 * w00 + H3 * z[0][0] - C[0][0] * gamma0[0]
      const CPrime00 = group
        .msm([w00, z[0][0]], [params.H2, params.H3])
        .sub(Cj0.multiply(gamma0[0]));
      // C'[0][1] = H2 * w01 + H3 * z[0][1] - C[0][1] * gamma1[0]
      const CPrime01 = group.msm([w01, z[0][1]], [params.H2, params.H3]).sub(Cj1.multiply(gamma1J));
      CPrime.push([CPrime00, CPrime01]);
    } else {
      // Steps 22-27: Remaining bits
      // C'[j][0] = H3 * z[j][0] - C[j][0] * gamma0[j]
      const CPrimeJ0 = params.H3.multiply(z[j][0]).sub(Cj0.multiply(gamma0[j]));
      // C'[j][1] = H3 * z[j][1] - C[j][1] * gamma1[j]
      const CPrimeJ1 = params.H3.multiply(z[j][1]).sub(Cj1.multiply(gamma1J));
      CPrime.push([CPrimeJ0, CPrimeJ1]);
    }
  }

  // Steps 28-31: Verify final commitment
  // K' = Sum(Com[j] * 2^j for j in [L])
  let KPrime = group.identity();
  for (let j = 0; j < L; j++) {
    const pow2j = group.scalarFromBigint(1n << BigInt(j));
    KPrime = KPrime.add(Com[j].multiply(pow2j));
  }

  // Com_total = H1 * s + K'
  const sScalar = group.scalarFromBigint(s);
  const ComTotal = params.H1.multiply(sScalar).add(KPrime);

  // C_final = H1 * (-c_bar) + H2 * k_bar + H3 * s_bar - Com_total * gamma
  const CFinal = group
    .msm([cBar.neg(), kBarFinal, sBarFinal], [params.H1, params.H2, params.H3])
    .sub(ComTotal.multiply(gamma));

  // Steps 32-46: Recompute challenge
  const transcript = new Transcript('spend', params);
  transcript.addScalar(k);
  transcript.addScalar(ctx);
  transcript.addElement(APrime);
  transcript.addElement(BBar);
  transcript.addElement(A1);
  transcript.addElement(A2);
  for (let j = 0; j < L; j++) {
    transcript.addElement(Com[j]);
  }
  for (let j = 0; j < L; j++) {
    transcript.addElement(CPrime[j][0]);
    transcript.addElement(CPrime[j][1]);
  }
  transcript.addElement(CFinal);
  const gammaCheck = transcript.getChallenge();

  // Steps 47-49: Verify challenge
  if (!gamma.equals(gammaCheck)) {
    throw new ACTError('Invalid spend proof', ACTErrorCode.InvalidSpendProof);
  }

  return true;
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
 * @returns Refund message
 */
export function issueRefund(
  params: SystemParams,
  sk: PrivateKey,
  proof: SpendProof,
  t: bigint
): Refund {
  const { s, ctx, Com } = proof;
  const L = params.L;
  const maxValue = 1n << BigInt(L);

  // Validate partial return amount
  if (t >= maxValue) {
    throw new ACTError(`Return amount ${t} >= 2^L`, ACTErrorCode.InvalidAmount);
  }
  if (t > s) {
    throw new ACTError(`Return amount ${t} > spend amount ${s}`, ACTErrorCode.InvalidAmount);
  }

  // Reconstruct K' = Sum(Com[j] * 2^j for j in [L])
  let KPrime = group.identity();
  for (let j = 0; j < L; j++) {
    const pow2j = group.scalarFromBigint(1n << BigInt(j));
    KPrime = KPrime.add(Com[j].multiply(pow2j));
  }

  const G = group.generator();
  const pk_W = G.multiply(sk.x);

  // Steps 6-9: Create new BBS signature
  const eStar = group.randomScalar();
  const tScalar = group.scalarFromBigint(t);

  // X_A* = G + K' + H1 * t + H4 * ctx
  const XAStar = group.msm(
    [group.one(), group.one(), tScalar, ctx],
    [G, KPrime, params.H1, params.H4]
  );

  // A* = X_A* * (1/(e* + sk.x))
  const AStar = XAStar.multiply(eStar.add(sk.x).inv());

  // Steps 10-14: Generate proof
  const alpha = group.randomScalar();
  const Y_A = AStar.multiply(alpha);
  const Y_G = G.multiply(alpha);
  const X_G = G.multiply(eStar).add(pk_W);

  // Steps 15-25: Fiat-Shamir
  const transcript = new Transcript('refund', params);
  transcript.addScalar(eStar);
  transcript.addCredit(t);
  transcript.addScalar(ctx);
  transcript.addElement(AStar);
  transcript.addElement(XAStar);
  transcript.addElement(X_G);
  transcript.addElement(Y_A);
  transcript.addElement(Y_G);
  const gammaRefund = transcript.getChallenge();

  // Step 27: z = gamma * (sk + e*) + alpha
  const zRefund = gammaRefund.mul(sk.x.add(eStar)).add(alpha);

  return {
    AStar,
    eStar,
    gamma: gammaRefund,
    z: zRefund,
    t,
  };
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
  const { AStar, eStar, gamma, z, t } = refund;
  const { kStar, rStar, m, ctx } = state;
  const { Com } = proof;
  const L = params.L;

  // Reconstruct K' = Sum(Com[j] * 2^j for j in [L])
  let KPrime = group.identity();
  for (let j = 0; j < L; j++) {
    const pow2j = group.scalarFromBigint(1n << BigInt(j));
    KPrime = KPrime.add(Com[j].multiply(pow2j));
  }

  const G = group.generator();
  const tScalar = group.scalarFromBigint(t);

  // Steps 5-6: Reconstruct X_A* and X_G
  // X_A* = G + K' + H1 * t + H4 * ctx
  const XAStar = group.msm(
    [group.one(), group.one(), tScalar, ctx],
    [G, KPrime, params.H1, params.H4]
  );

  // X_G = G * e* + pk.W
  const X_G = G.multiply(eStar).add(pk.W);

  // Steps 7-9: Verify proof
  // Y_A = A* * z + X_A* * (-gamma)
  const Y_A = AStar.multiply(z).sub(XAStar.multiply(gamma));

  // Y_G = G * z + X_G * (-gamma)
  const Y_G = G.multiply(z).sub(X_G.multiply(gamma));

  // Steps 10-20: Recompute challenge
  const transcript = new Transcript('refund', params);
  transcript.addScalar(eStar);
  transcript.addCredit(t);
  transcript.addScalar(ctx);
  transcript.addElement(AStar);
  transcript.addElement(XAStar);
  transcript.addElement(X_G);
  transcript.addElement(Y_A);
  transcript.addElement(Y_G);
  const gammaCheck = transcript.getChallenge();

  if (!gamma.equals(gammaCheck)) {
    throw new ACTError('Invalid refund proof', ACTErrorCode.InvalidRefundProof);
  }

  // Step 22-23: Construct new token with balance m + t
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
 * Verify spend and issue refund (issuer-side convenience)
 *
 * @param params - System parameters
 * @param sk - Issuer's private key
 * @param proof - Client's spend proof
 * @param usedNullifiers - Set of already-used nullifiers (modified in place)
 * @param t - Credits to return (default 0)
 * @returns Refund message
 */
export function verifyAndRefund(
  params: SystemParams,
  sk: PrivateKey,
  proof: SpendProof,
  usedNullifiers: Set<string>,
  t: bigint = 0n
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
  return issueRefund(params, sk, proof, t);
}
