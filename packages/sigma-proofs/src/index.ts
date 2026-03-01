/**
 * Interactive Sigma Proofs
 *
 * Implementation of draft-irtf-cfrg-sigma-protocols-01
 * https://www.ietf.org/archive/id/draft-irtf-cfrg-sigma-protocols-01.txt
 *
 * @module
 */

export { LinearMap, type LinearCombination } from './linear-map.js';
export { LinearRelation } from './linear-relation.js';
export { SchnorrProof, type ProverCommitment, type Commitment, type Response } from './schnorr.js';
export { type Group, type Scalar, type GroupElement } from './group.js';
export { appendPedersen, appendDleq, appendRangeProof, setupRangeProofElements } from './helpers.js';
export * from './ciphersuites/index.js';

// Fiat-Shamir transformation (draft-irtf-cfrg-fiat-shamir-01)
export {
  NISigmaProtocol,
  Shake128Sponge,
  ByteCodec,
  type DuplexSponge,
  type Codec,
  type NIOptions,
  type NIProof,
  type NIProofBatchable,
} from './fiat-shamir/index.js';
