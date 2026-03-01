/**
 * ACT Token Issuance Protocol
 *
 * Section 3.3: Token Issuance
 *
 * Interactive protocol between client and issuer:
 * 1. Client: IssueRequest - creates commitment K and proof of knowledge
 * 2. Issuer: IssueResponse - creates BBS signature and proof of correctness
 * 3. Client: VerifyIssuance - verifies response and constructs token
 */

import type {
  SystemParams,
  PrivateKey,
  PublicKey,
  IssuanceRequest,
  IssuanceResponse,
  IssuanceState,
  CreditToken,
  Scalar,
} from './types.js';
import { ACTError, ACTErrorCode } from './types.js';
import { group } from './group.js';
import { SimpleTranscript, Transcript } from './transcript.js';

/**
 * Client: IssueRequest (Section 3.3.1)
 *
 * Creates an issuance request with commitment K and proof of knowledge of k, r.
 *
 * @param params - System parameters (H1-H4)
 * @returns Tuple of (request, state) where state must be kept secret
 */
export function issueRequest(params: SystemParams): [IssuanceRequest, IssuanceState] {
  // Step 1-2: Sample nullifier k and blinding factor r
  const k = group.randomScalar();
  const r = group.randomScalar();

  // Step 3: Compute commitment K = H2 * k + H3 * r
  const K = group.msm([k, r], [params.H2, params.H3]);

  // Steps 4-7: Generate proof of knowledge
  const kPrime = group.randomScalar();
  const rPrime = group.randomScalar();
  const K1 = group.msm([kPrime, rPrime], [params.H2, params.H3]);

  // Steps 8-11: Fiat-Shamir challenge
  const transcript = new SimpleTranscript('request');
  transcript.addElement(K);
  transcript.addElement(K1);
  const gamma = transcript.getChallenge();

  // Steps 12-13: Compute responses
  const kBar = kPrime.add(gamma.mul(k));
  const rBar = rPrime.add(gamma.mul(r));

  // Steps 14-16: Return request and state
  const request: IssuanceRequest = {
    K,
    gamma,
    kBar,
    rBar,
  };

  const state: IssuanceState = {
    k,
    r,
  };

  return [request, state];
}

/**
 * Issuer: IssueResponse (Section 3.3.2)
 *
 * Verifies the client's proof, creates a BBS signature, and returns a proof
 * of correct computation.
 *
 * @param params - System parameters
 * @param sk - Issuer's private key
 * @param request - Client's issuance request
 * @param c - Credit amount to issue (must be > 0 and < 2^L)
 * @param ctx - Request context (application-specific)
 * @returns Issuance response
 */
export function issueResponse(
  params: SystemParams,
  sk: PrivateKey,
  request: IssuanceRequest,
  c: bigint,
  ctx: Scalar
): IssuanceResponse {
  // Validate credit amount
  if (c <= 0n) {
    throw new ACTError('Credit amount must be positive', ACTErrorCode.InvalidAmount);
  }
  if (c >= 1n << BigInt(params.L)) {
    throw new ACTError(
      `Credit amount ${c} exceeds maximum ${(1n << BigInt(params.L)) - 1n}`,
      ACTErrorCode.AmountTooBig
    );
  }

  // Steps 1-8: Verify proof of knowledge
  const { K, gamma, kBar, rBar } = request;

  // Step 3: Recompute K1 = H2 * k_bar + H3 * r_bar - K * gamma
  const K1 = group.msm([kBar, rBar], [params.H2, params.H3]).sub(K.multiply(gamma));

  // Steps 4-6: Recompute challenge
  const transcript = new SimpleTranscript('request');
  transcript.addElement(K);
  transcript.addElement(K1);
  const gammaCheck = transcript.getChallenge();

  // Step 7-8: Verify challenge
  if (!gamma.equals(gammaCheck)) {
    throw new ACTError('Invalid issuance request proof', ACTErrorCode.InvalidIssuanceRequestProof);
  }

  // Steps 9-11: Create BBS signature
  // e <- Zq
  const e = group.randomScalar();

  // A = (G + H1 * c + H4 * ctx + K) * (1/(e + sk.x))
  const G = group.generator();
  const cScalar = group.scalarFromBigint(c);
  const X_A = group.msm([group.one(), cScalar, ctx, group.one()], [G, params.H1, params.H4, K]);
  const invDenom = e.add(sk.x).inv();
  const A = X_A.multiply(invDenom);

  // Steps 12-15: Generate proof of correct computation
  const alpha = group.randomScalar();
  const Y_A = A.multiply(alpha);
  const Y_G = G.multiply(alpha);

  // Step 16-17: X_A already computed; X_G = G * e + pk.W
  const pk_W = G.multiply(sk.x); // pk.W
  const X_G = G.multiply(e).add(pk_W);

  // Steps 18-28: Fiat-Shamir for response proof
  const transcriptResp = new Transcript('respond', params);
  transcriptResp.addCredit(c);
  transcriptResp.addScalar(ctx);
  transcriptResp.addScalar(e);
  transcriptResp.addElement(A);
  transcriptResp.addElement(X_A);
  transcriptResp.addElement(X_G);
  transcriptResp.addElement(Y_A);
  transcriptResp.addElement(Y_G);
  const gammaResp = transcriptResp.getChallenge();

  // Step 28: z = gamma_resp * (sk + e) + alpha
  const z = gammaResp.mul(sk.x.add(e)).add(alpha);

  // Step 29-30: Return response
  return {
    A,
    e,
    gammaResp,
    z,
    c,
    ctx,
  };
}

/**
 * Client: VerifyIssuance (Section 3.3.3)
 *
 * Verifies the issuer's response and constructs the credit token.
 *
 * @param params - System parameters
 * @param pk - Issuer's public key
 * @param request - The issuance request that was sent
 * @param response - Issuer's response
 * @param state - Client state from request generation
 * @returns Credit token
 */
export function verifyIssuance(
  params: SystemParams,
  pk: PublicKey,
  request: IssuanceRequest,
  response: IssuanceResponse,
  state: IssuanceState
): CreditToken {
  const { K } = request;
  const { A, e, gammaResp, z, c, ctx } = response;
  const { k, r } = state;

  // Validate credit amount
  if (c >= 1n << BigInt(params.L)) {
    throw new ACTError(`Credit amount ${c} exceeds maximum`, ACTErrorCode.AmountTooBig);
  }

  // Steps 5-6: Recompute X_A and X_G
  const G = group.generator();
  const cScalar = group.scalarFromBigint(c);

  // X_A = G + H1 * c + H4 * ctx + K
  const X_A = group.msm([group.one(), cScalar, ctx, group.one()], [G, params.H1, params.H4, K]);

  // X_G = G * e + pk.W
  const X_G = G.multiply(e).add(pk.W);

  // Steps 7-8: Verify proof
  // Y_A = A * z - X_A * gamma_resp
  const Y_A = A.multiply(z).sub(X_A.multiply(gammaResp));

  // Y_G = G * z - X_G * gamma_resp
  const Y_G = G.multiply(z).sub(X_G.multiply(gammaResp));

  // Steps 9-18: Recompute challenge
  const transcriptResp = new Transcript('respond', params);
  transcriptResp.addCredit(c);
  transcriptResp.addScalar(ctx);
  transcriptResp.addScalar(e);
  transcriptResp.addElement(A);
  transcriptResp.addElement(X_A);
  transcriptResp.addElement(X_G);
  transcriptResp.addElement(Y_A);
  transcriptResp.addElement(Y_G);
  const gammaCheck = transcriptResp.getChallenge();

  // Steps 18-19: Verify challenge
  if (!gammaResp.equals(gammaCheck)) {
    throw new ACTError(
      'Invalid issuance response proof',
      ACTErrorCode.InvalidIssuanceResponseProof
    );
  }

  // Steps 20-21: Construct token
  return {
    A,
    e,
    k,
    r,
    c,
    ctx,
  };
}

/**
 * Full issuance flow for client
 *
 * Convenience function that combines request and verification.
 * The caller must handle the network round-trip to get the response.
 */
export interface IssuanceFlow {
  /** Create the initial request */
  createRequest(): [IssuanceRequest, IssuanceState];
  /** Verify response and get token */
  verifyResponse(response: IssuanceResponse, state: IssuanceState): CreditToken;
}

export function createIssuanceFlow(params: SystemParams, pk: PublicKey): IssuanceFlow {
  return {
    createRequest(): [IssuanceRequest, IssuanceState] {
      return issueRequest(params);
    },
    verifyResponse(response: IssuanceResponse, state: IssuanceState): CreditToken {
      // Need to reconstruct request from state for verification
      const k = state.k;
      const r = state.r;
      const K = group.msm([k, r], [params.H2, params.H3]);

      // We don't have the original gamma/kBar/rBar but verifyIssuance
      // only needs K from the request
      const mockRequest: IssuanceRequest = {
        K,
        gamma: group.zero(), // Not used in verifyIssuance
        kBar: group.zero(),
        rBar: group.zero(),
      };

      return verifyIssuance(params, pk, mockRequest, response, state);
    },
  };
}
