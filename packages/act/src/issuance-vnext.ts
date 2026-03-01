/**
 * ACT Token Issuance Protocol - VNEXT (sigma-draft-compliance)
 *
 * Section 3.3: Token Issuance
 *
 * Uses NISigmaProtocol from draft-irtf-cfrg-fiat-shamir for Fiat-Shamir transform.
 * Uses LinearRelation from draft-irtf-cfrg-sigma-protocols for proof structure.
 */

import {
  LinearRelation,
  NISigmaProtocol,
  appendPedersen,
  appendDleq,
} from 'sigma-proofs';
import type {
  SystemParams,
  PrivateKey,
  PublicKey,
  IssuanceRequest,
  IssuanceResponse,
  IssuanceState,
  CreditToken,
  Scalar,
  PRNG,
} from './types-vnext.js';
import { ACTError, ACTErrorCode } from './types-vnext.js';

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
 * Encode scalar to bytes for session ID
 */
function encodeScalar(s: Scalar): Uint8Array {
  return s.toBytes();
}

/**
 * Encode bigint credit amount to scalar bytes
 */
function encodeBigint(group: { scalarFromBigint(n: bigint): Scalar }, c: bigint): Uint8Array {
  return group.scalarFromBigint(c).toBytes();
}

/**
 * Build session ID for issuance request.
 *
 * session_id = domain_separator + "request"
 */
function requestSessionId(params: SystemParams): Uint8Array {
  const label = new Uint8Array([114, 101, 113, 117, 101, 115, 116]); // "request"
  return concat(params.domainSeparator, label);
}

/**
 * Build session ID for issuance response.
 *
 * session_id = domain_separator + "respond" + Encode(c) + Encode(ctx)
 */
function respondSessionId(params: SystemParams, c: bigint, ctx: Scalar): Uint8Array {
  const label = new Uint8Array([114, 101, 115, 112, 111, 110, 100]); // "respond"
  return concat(params.domainSeparator, label, encodeBigint(params.group, c), encodeScalar(ctx));
}

/**
 * Client: IssueRequest (Section 3.3.1)
 *
 * Creates an issuance request with commitment K and proof of knowledge of (k, r).
 *
 * Proof statement: PoK{(k, r): K = k*H2 + r*H3}
 *
 * @param params - System parameters
 * @param ctx - Request context (determined by issuer/client agreement)
 * @param rng - Random number generator
 * @returns Tuple of (request, state)
 */
export function issueRequest(
  params: SystemParams,
  ctx: Scalar,
  rng: PRNG
): [IssuanceRequest, IssuanceState] {
  const { group, H2, H3 } = params;

  // Sample nullifier k and blinding factor r
  const kBytes = rng.randomBytes(group.scalarSize + 16);
  const rBytes = rng.randomBytes(group.scalarSize + 16);
  const k = group.hashToScalar(kBytes);
  const r = group.hashToScalar(rBytes);

  // Compute commitment K = k*H2 + r*H3
  const K = group.msm([k, r], [H2, H3]);

  // Build proof statement: K = k*H2 + r*H3
  const relation = new LinearRelation(group);
  const [kVar, rVar] = relation.allocateScalars(2);
  const [h2Idx, h3Idx, kIdx] = relation.allocateElements(3);
  relation.setElements([
    [h2Idx, H2],
    [h3Idx, H3],
    [kIdx, K],
  ]);
  appendPedersen(relation, h2Idx, h3Idx, kIdx, kVar, rVar);

  // Generate NI proof
  const sessionId = requestSessionId(params);
  const prover = new NISigmaProtocol(relation, { sessionId });
  const proof = prover.prove([k, r], rng);

  // Serialize proof
  const pok = serializeProof(proof, group.scalarSize);

  const request: IssuanceRequest = { K, pok };
  const state: IssuanceState = { k, r, ctx };

  return [request, state];
}

/**
 * Issuer: IssueResponse (Section 3.3.2)
 *
 * Verifies client's proof, creates BBS signature, returns proof of correctness.
 *
 * Proof statement: DLEQ{(sk+e): A = (sk+e)^(-1)*X_A AND G = (sk+e)^(-1)*X_G}
 * Equivalently: PoK{(sk+e): X_A = (sk+e)*A AND X_G = (sk+e)*G}
 *
 * @param params - System parameters
 * @param sk - Issuer's private key
 * @param request - Client's issuance request
 * @param c - Credit amount (>= 0 and < 2^L)
 * @param ctx - Request context
 * @param rng - Random number generator
 * @returns Issuance response
 */
export function issueResponse(
  params: SystemParams,
  sk: PrivateKey,
  request: IssuanceRequest,
  c: bigint,
  ctx: Scalar,
  rng: PRNG
): IssuanceResponse {
  const { group, H1, H2, H3, H4, L } = params;
  const maxValue = 1n << BigInt(L);

  // Validate credit amount (new draft allows c >= 0)
  if (c < 0n) {
    throw new ACTError('Credit amount must be non-negative', ACTErrorCode.InvalidAmount);
  }
  if (c >= maxValue) {
    throw new ACTError(
      `Credit amount ${c} exceeds maximum ${maxValue - 1n}`,
      ACTErrorCode.AmountTooBig
    );
  }

  // Verify client's proof of knowledge
  const { K, pok } = request;

  const verifyRelation = new LinearRelation(group);
  const [kVarV, rVarV] = verifyRelation.allocateScalars(2);
  const [h2IdxV, h3IdxV, kIdxV] = verifyRelation.allocateElements(3);
  verifyRelation.setElements([
    [h2IdxV, H2],
    [h3IdxV, H3],
    [kIdxV, K],
  ]);
  appendPedersen(verifyRelation, h2IdxV, h3IdxV, kIdxV, kVarV, rVarV);

  const verifySessionId = requestSessionId(params);
  const verifier = new NISigmaProtocol(verifyRelation, { sessionId: verifySessionId });
  const clientProof = deserializeProof(group, pok, 2);

  if (!verifier.verify(clientProof)) {
    throw new ACTError('Invalid issuance request proof', ACTErrorCode.InvalidIssuanceRequestProof);
  }

  // Create BBS signature
  // e <- Zq (random)
  const eBytes = rng.randomBytes(group.scalarSize + 16);
  const e = group.hashToScalar(eBytes);

  // X_A = G + c*H1 + ctx*H4 + K
  const G = group.generator();
  const cScalar = group.scalarFromBigint(c);
  const one = group.scalarFromBigint(1n);
  const X_A = group.msm([one, cScalar, ctx, one], [G, H1, H4, K]);

  // A = X_A * (1/(e + sk.x))
  const skPlusE = sk.x.add(e);
  const invSkPlusE = skPlusE.inv();
  const A = X_A.multiply(invSkPlusE);

  // X_G = (e + sk.x) * G
  const X_G = G.multiply(skPlusE);

  // Build DLEQ proof: PoK{(d): X_A = d*A AND X_G = d*G} where d = sk+e
  const respRelation = new LinearRelation(group);
  const [dVar] = respRelation.allocateScalars(1);
  const [gIdx, aIdx, xaIdx, xgIdx] = respRelation.allocateElements(4);
  respRelation.setElements([
    [gIdx, G],
    [aIdx, A],
    [xaIdx, X_A],
    [xgIdx, X_G],
  ]);
  appendDleq(respRelation, aIdx, gIdx, xaIdx, xgIdx, dVar);

  const respSessionId = respondSessionId(params, c, ctx);
  const respProver = new NISigmaProtocol(respRelation, { sessionId: respSessionId });
  const respProof = respProver.prove([skPlusE], rng);
  const respPok = serializeProof(respProof, group.scalarSize);

  return { A, e, c, pok: respPok };
}

/**
 * Client: VerifyIssuance (Section 3.3.3)
 *
 * Verifies issuer's response and constructs credit token.
 *
 * @param params - System parameters
 * @param pk - Issuer's public key
 * @param response - Issuer's response
 * @param state - Client state from request generation
 * @returns Credit token
 */
export function verifyIssuance(
  params: SystemParams,
  pk: PublicKey,
  response: IssuanceResponse,
  state: IssuanceState
): CreditToken {
  const { group, H1, H2, H3, H4, L } = params;
  const { A, e, c, pok } = response;
  const { k, r, ctx } = state;
  const maxValue = 1n << BigInt(L);

  // Validate credit amount
  if (c >= maxValue) {
    throw new ACTError(`Credit amount ${c} exceeds maximum`, ACTErrorCode.AmountTooBig);
  }

  // Reconstruct K = k*H2 + r*H3
  const K = group.msm([k, r], [H2, H3]);

  // Reconstruct X_A = G + c*H1 + ctx*H4 + K
  const G = group.generator();
  const cScalar = group.scalarFromBigint(c);
  const one = group.scalarFromBigint(1n);
  const X_A = group.msm([one, cScalar, ctx, one], [G, H1, H4, K]);

  // Reconstruct X_G = e*G + pk.W
  const X_G = G.multiply(e).add(pk.W);

  // Verify DLEQ proof
  const verifyRelation = new LinearRelation(group);
  const [dVarV] = verifyRelation.allocateScalars(1);
  const [gIdxV, aIdxV, xaIdxV, xgIdxV] = verifyRelation.allocateElements(4);
  verifyRelation.setElements([
    [gIdxV, G],
    [aIdxV, A],
    [xaIdxV, X_A],
    [xgIdxV, X_G],
  ]);
  appendDleq(verifyRelation, aIdxV, gIdxV, xaIdxV, xgIdxV, dVarV);

  const verifySessionId = respondSessionId(params, c, ctx);
  const verifier = new NISigmaProtocol(verifyRelation, { sessionId: verifySessionId });
  const issuerProof = deserializeProof(group, pok, 1);

  if (!verifier.verify(issuerProof)) {
    throw new ACTError(
      'Invalid issuance response proof',
      ACTErrorCode.InvalidIssuanceResponseProof
    );
  }

  // Construct token
  return { A, e, k, r, c, ctx };
}

/**
 * Serialize NISigmaProtocol proof to bytes.
 *
 * Format: challenge (Ns bytes) || response[0] (Ns bytes) || ... || response[n-1] (Ns bytes)
 */
export function serializeProof(
  proof: { challenge: Scalar; response: readonly Scalar[] },
  scalarSize: number
): Uint8Array {
  const parts: Uint8Array[] = [proof.challenge.toBytes()];
  for (const r of proof.response) {
    parts.push(r.toBytes());
  }
  return concat(...parts);
}

/**
 * Deserialize NISigmaProtocol proof from bytes.
 */
export function deserializeProof(
  group: { scalarFromBytes(bytes: Uint8Array): Scalar; scalarSize: number },
  pok: Uint8Array,
  numResponses: number
): { challenge: Scalar; response: Scalar[] } {
  const scalarSize = group.scalarSize;
  const expectedLen = scalarSize * (1 + numResponses);
  if (pok.length !== expectedLen) {
    throw new ACTError(
      `Invalid proof length: expected ${expectedLen}, got ${pok.length}`,
      ACTErrorCode.InvalidIssuanceRequestProof
    );
  }

  const challenge = group.scalarFromBytes(pok.slice(0, scalarSize));
  const response: Scalar[] = [];
  for (let i = 0; i < numResponses; i++) {
    const start = scalarSize * (1 + i);
    const end = start + scalarSize;
    response.push(group.scalarFromBytes(pok.slice(start, end)));
  }

  return { challenge, response };
}
